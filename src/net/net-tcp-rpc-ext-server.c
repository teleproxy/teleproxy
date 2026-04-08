/*
    This file is part of Mtproto-proxy Library.

    Mtproto-proxy Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    Mtproto-proxy Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with Mtproto-proxy Library.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2010-2013 Vkontakte Ltd
              2010-2013 Nikolai Durov
              2010-2013 Andrey Lopatin
                   2013 Vitaliy Valtman
    
    Copyright 2014-2018 Telegram Messenger Inc                 
              2015-2016 Vitaly Valtman
                    2016-2018 Nikolai Durov
*/

#define        _FILE_OFFSET_BITS        64

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>

#include "common/kprintf.h"
#include "common/precise-time.h"
#include "common/resolver.h"
#include "common/rpc-const.h"
#include "common/sha256.h"
#include "net/net-connections.h"
#include "net/net-crypto-aes.h"
#include "net/net-events.h"
#include "net/net-tcp-connections.h"
#include "net/net-tcp-drs.h"
#include "net/net-tcp-rpc-ext-server.h"
#include "net/net-tcp-direct-dc.h"
#include "net/net-obfs2-parse.h"
#include "net/net-proxy-protocol.h"
#include "net/net-tls-parse.h"
#include "net/net-ip-acl.h"
#include "net/net-thread.h"
#include "mtproto/mtproto-dc-table.h"

#include "vv/vv-io.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/*
 *
 *                EXTERNAL RPC SERVER INTERFACE
 *
 */

int tcp_rpcs_compact_parse_execute (connection_job_t c);
int tcp_rpcs_ext_alarm (connection_job_t c);
int tcp_rpcs_ext_drs_alarm (connection_job_t c);
int tcp_rpcs_ext_init_accepted (connection_job_t c);

conn_type_t ct_tcp_rpc_ext_server = {
  .magic = CONN_FUNC_MAGIC,
  .flags = C_RAWMSG,
  .title = "rpc_ext_server",
  .init_accepted = tcp_rpcs_ext_init_accepted,
  .parse_execute = tcp_rpcs_compact_parse_execute,
  .close = tcp_rpcs_close_connection,
  .flush = tcp_rpc_flush,
  .write_packet = tcp_rpc_write_packet_compact,
  .connected = server_failed,
  .wakeup = tcp_rpcs_wakeup,
  .alarm = tcp_rpcs_ext_alarm,
  .crypto_init = aes_crypto_ctr128_init,
  .crypto_free = aes_crypto_free,
  .crypto_encrypt_output = cpu_tcp_aes_crypto_ctr128_encrypt_output,
  .crypto_decrypt_input = cpu_tcp_aes_crypto_ctr128_decrypt_input,
  .crypto_needed_output_bytes = cpu_tcp_aes_crypto_ctr128_needed_output_bytes,
};

/* DRS variant: uses dynamic record sizing for TLS connections */
conn_type_t ct_tcp_rpc_ext_server_drs = {
  .magic = CONN_FUNC_MAGIC,
  .flags = C_RAWMSG,
  .title = "rpc_ext_server_drs",
  .init_accepted = tcp_rpcs_ext_init_accepted,
  .parse_execute = tcp_rpcs_compact_parse_execute,
  .close = tcp_rpcs_close_connection,
  .flush = tcp_rpc_flush,
  .write_packet = tcp_rpc_write_packet_compact,
  .connected = server_failed,
  .wakeup = tcp_rpcs_wakeup,
  .alarm = tcp_rpcs_ext_drs_alarm,
  .crypto_init = aes_crypto_ctr128_init,
  .crypto_free = aes_crypto_free,
  .crypto_encrypt_output = cpu_tcp_aes_crypto_ctr128_encrypt_output_drs,
  .crypto_decrypt_input = cpu_tcp_aes_crypto_ctr128_decrypt_input,
  .crypto_needed_output_bytes = cpu_tcp_aes_crypto_ctr128_needed_output_bytes,
};

int tcp_proxy_pass_parse_execute (connection_job_t C);
int tcp_proxy_pass_close (connection_job_t C, int who);
int tcp_proxy_pass_write_packet (connection_job_t c, struct raw_message *raw);

conn_type_t ct_proxy_pass = {
  .magic = CONN_FUNC_MAGIC,
  .flags = C_RAWMSG,
  .title = "proxypass",
  .init_accepted = server_failed,
  .parse_execute = tcp_proxy_pass_parse_execute,
  .connected = server_noop,
  .close = tcp_proxy_pass_close,
  .write_packet = tcp_proxy_pass_write_packet,
};

int tcp_proxy_pass_parse_execute (connection_job_t C) {
  struct connection_info *c = CONN_INFO(C);
  if (!c->extra) {
    fail_connection (C, -1);
    return 0;
  }
  job_t E = job_incref (c->extra);
  struct connection_info *e = CONN_INFO(E);

  struct raw_message *r = malloc (sizeof (*r));
  rwm_move (r, &c->in);
  rwm_init (&c->in, 0);
  vkprintf (3, "proxying %d bytes to %s:%d\n", r->total_bytes, show_remote_ip (E), e->remote_port);
  mpq_push_w (e->out_queue, PTR_MOVE(r), 0);
  job_signal (JOB_REF_PASS (E), JS_RUN);
  return 0;
}

int tcp_proxy_pass_close (connection_job_t C, int who) {
  struct connection_info *c = CONN_INFO(C);
  vkprintf (1, "closing proxy pass connection #%d %s:%d -> %s:%d\n", c->fd, show_our_ip (C), c->our_port, show_remote_ip (C), c->remote_port);
  if (c->extra) {
    job_t E = PTR_MOVE (c->extra);
    fail_connection (E, -23);
    job_decref (JOB_REF_PASS (E));
  }
  return cpu_server_close_connection (C, who);
}

int tcp_proxy_pass_write_packet (connection_job_t C, struct raw_message *raw) {
  rwm_union (&CONN_INFO(C)->out, raw);
  return 0;
}

extern int direct_mode;
extern int workers;
extern long long direct_dc_connections_created, direct_dc_connections_active;
extern long long direct_dc_connections_failed, direct_dc_connections_dc_closed;
extern long long direct_dc_retries;
extern long long per_secret_connections[EXT_SECRET_MAX_SLOTS], per_secret_connections_created[EXT_SECRET_MAX_SLOTS];
extern long long per_secret_connections_rejected[EXT_SECRET_MAX_SLOTS];
extern long long per_secret_bytes_received[EXT_SECRET_MAX_SLOTS], per_secret_bytes_sent[EXT_SECRET_MAX_SLOTS];
extern long long per_secret_rejected_quota[EXT_SECRET_MAX_SLOTS];
extern long long per_secret_rejected_ips[EXT_SECRET_MAX_SLOTS];
extern long long per_secret_rejected_expired[EXT_SECRET_MAX_SLOTS];
extern long long per_secret_unique_ips[EXT_SECRET_MAX_SLOTS];
extern long long per_secret_rate_limited[EXT_SECRET_MAX_SLOTS];
extern long long per_secret_rejected_draining[EXT_SECRET_MAX_SLOTS];
extern long long per_secret_drain_forced[EXT_SECRET_MAX_SLOTS];
extern long long transport_errors_received;
extern long long quickack_packets_received;

int tcp_rpcs_default_execute (connection_job_t c, int op, struct raw_message *msg);

/* Secret state shared with net-tcp-rpc-ext-drain.c.  Engine thread owns
   all writes; the stats reader thread synchronizes via the existing
   __sync_synchronize barrier discipline around ext_secret_cnt. */
unsigned char ext_secret[EXT_SECRET_MAX_SLOTS][16];
int ext_secret_cnt = 0;
int ext_secret_pinned = 0;  /* CLI -S secrets that survive SIGHUP reload */
char ext_secret_label[EXT_SECRET_MAX_SLOTS][EXT_SECRET_LABEL_MAX + 1];
int ext_secret_limit[EXT_SECRET_MAX_SLOTS];  /* 0 = unlimited */
long long ext_secret_quota[EXT_SECRET_MAX_SLOTS];   /* byte quota, rx+tx (0 = unlimited) */
long long ext_secret_rate_limit[EXT_SECRET_MAX_SLOTS]; /* bytes/sec per IP (0 = unlimited) */
int ext_secret_max_ips[EXT_SECRET_MAX_SLOTS];       /* unique IP limit (0 = unlimited) */
int64_t ext_secret_expires[EXT_SECRET_MAX_SLOTS];   /* Unix timestamp (0 = never) */
int ext_secret_state[EXT_SECRET_MAX_SLOTS];          /* SLOT_FREE / SLOT_ACTIVE / SLOT_DRAINING */
double ext_secret_drain_started_at[EXT_SECRET_MAX_SLOTS]; /* precise_now snapshot */
static int ext_rand_pad_only = 0;

/* Per-secret IP tracking for unique-IP limits */
#define SECRET_MAX_TRACKED_IPS 256

struct tracked_ip {
  unsigned ip;              /* IPv4 (host byte order), 0 = empty */
  unsigned char ipv6[16];   /* IPv6 address */
  int connections;          /* active connections from this IP */
  long long tokens;         /* rate limit token bucket: available bytes */
  double last_refill_time;  /* precise_now at last token refill */
};

static struct tracked_ip per_secret_ips[EXT_SECRET_MAX_SLOTS][SECRET_MAX_TRACKED_IPS];
static int per_secret_unique_ip_count[EXT_SECRET_MAX_SLOTS];

/* Per-IP volume tracking for top-N metrics lives in net-tcp-rpc-ext-top-ips.c
   (issue #46).  Kept separate to preserve responsibility boundaries and to
   stay under the per-file LLM-context line budget. */

void tcp_rpcs_set_ext_secret (unsigned char secret[16], const char *label,
                              int limit, long long quota, long long rate_limit,
                              int max_ips, int64_t expires) {
  assert (ext_secret_cnt < EXT_SECRET_MAX_ACTIVE);
  int idx = ext_secret_cnt++;
  memcpy (ext_secret[idx], secret, 16);
  if (label && label[0]) {
    snprintf (ext_secret_label[idx], sizeof (ext_secret_label[idx]), "%s", label);
  } else {
    snprintf (ext_secret_label[idx], sizeof (ext_secret_label[idx]), "secret_%d", idx);
  }
  ext_secret_limit[idx] = limit;
  ext_secret_quota[idx] = quota;
  ext_secret_rate_limit[idx] = rate_limit;
  ext_secret_max_ips[idx] = max_ips;
  ext_secret_expires[idx] = expires;
  ext_secret_state[idx] = SLOT_ACTIVE;
  ext_secret_drain_started_at[idx] = 0;
  memset (per_secret_ips[idx], 0, sizeof (per_secret_ips[idx]));
  per_secret_unique_ip_count[idx] = 0;

  vkprintf (0, "Added secret #%d label=[%s] limit=%d quota=%lld rate_limit=%lld max_ips=%d expires=%lld\n",
            idx, ext_secret_label[idx], limit, quota, rate_limit, max_ips, (long long) expires);
}

const char *tcp_rpcs_get_ext_secret_label (int index) {
  assert (index >= 0 && index < ext_secret_cnt);
  return ext_secret_label[index];
}

int tcp_rpcs_get_ext_secret_limit (int index) {
  assert (index >= 0 && index < ext_secret_cnt);
  return ext_secret_limit[index];
}

long long tcp_rpcs_get_ext_secret_quota (int index) {
  assert (index >= 0 && index < ext_secret_cnt);
  return ext_secret_quota[index];
}

long long tcp_rpcs_get_ext_secret_rate_limit (int index) {
  assert (index >= 0 && index < ext_secret_cnt);
  return ext_secret_rate_limit[index];
}

int tcp_rpcs_get_ext_secret_max_ips (int index) {
  assert (index >= 0 && index < ext_secret_cnt);
  return ext_secret_max_ips[index];
}

int64_t tcp_rpcs_get_ext_secret_expires (int index) {
  assert (index >= 0 && index < ext_secret_cnt);
  return ext_secret_expires[index];
}

int tcp_rpcs_get_ext_secret_count (void) {
  return ext_secret_cnt;
}

static int secret_over_limit (int secret_id) {
  int limit = ext_secret_limit[secret_id];
  if (limit <= 0) { return 0; }
  int eff = workers > 1 ? limit / workers : limit;
  if (eff < 1) { eff = 1; }
  return per_secret_connections[secret_id] >= eff;
}

static int secret_expired (int secret_id) {
  int64_t exp = ext_secret_expires[secret_id];
  return exp > 0 && now >= exp;
}

int secret_over_quota (int secret_id) {
  long long quota = ext_secret_quota[secret_id];
  if (quota <= 0) { return 0; }
  long long eff = workers > 1 ? quota / workers : quota;
  if (eff < 1) { eff = 1; }
  long long used = per_secret_bytes_received[secret_id] + per_secret_bytes_sent[secret_id];
  return used >= eff;
}

/* Check if a new unique IP would exceed the limit.
   Returns 0 if the IP is already tracked or under the limit. */
static int ip_over_limit (int secret_id, unsigned ip, const unsigned char *ipv6) {
  int limit = ext_secret_max_ips[secret_id];
  if (limit <= 0) { return 0; }

  /* Check if this IP is already tracked (existing connection from same IP) */
  static const unsigned char zero_ipv6[16] = {};
  for (int i = 0; i < SECRET_MAX_TRACKED_IPS; i++) {
    struct tracked_ip *e = &per_secret_ips[secret_id][i];
    if (e->connections <= 0) { continue; }
    if (ip != 0) {
      if (e->ip == ip) { return 0; }  /* already tracked */
    } else {
      if (e->ip == 0 && memcmp (e->ipv6, zero_ipv6, 16) != 0 &&
          memcmp (e->ipv6, ipv6, 16) == 0) { return 0; }
    }
  }

  /* New IP — check against limit */
  int eff = workers > 1 ? limit / workers : limit;
  if (eff < 1) { eff = 1; }
  return per_secret_unique_ip_count[secret_id] >= eff;
}

/* Track a new connection from an IP.  Must be called AFTER all checks pass. */
static void ip_track_connect (int secret_id, unsigned ip, const unsigned char *ipv6) {
  if (ext_secret_max_ips[secret_id] <= 0 && ext_secret_rate_limit[secret_id] <= 0) { return; }

  static const unsigned char zero_ipv6[16] = {};

  /* Find existing entry for this IP */
  for (int i = 0; i < SECRET_MAX_TRACKED_IPS; i++) {
    struct tracked_ip *e = &per_secret_ips[secret_id][i];
    if (e->connections <= 0) { continue; }
    if (ip != 0) {
      if (e->ip == ip) { e->connections++; return; }
    } else {
      if (e->ip == 0 && memcmp (e->ipv6, zero_ipv6, 16) != 0 &&
          memcmp (e->ipv6, ipv6, 16) == 0) { e->connections++; return; }
    }
  }

  /* New IP — find an empty slot */
  for (int i = 0; i < SECRET_MAX_TRACKED_IPS; i++) {
    struct tracked_ip *e = &per_secret_ips[secret_id][i];
    if (e->connections <= 0) {
      e->ip = ip;
      if (ipv6) { memcpy (e->ipv6, ipv6, 16); } else { memset (e->ipv6, 0, 16); }
      e->connections = 1;
      /* Initialize rate limit token bucket */
      long long rl = ext_secret_rate_limit[secret_id];
      if (rl > 0) {
        long long eff = workers > 1 ? rl / workers : rl;
        if (eff < 1) { eff = 1; }
        e->tokens = eff;  /* start with 1s burst */
        e->last_refill_time = precise_now;
      }
      per_secret_unique_ip_count[secret_id]++;
      per_secret_unique_ips[secret_id]++;
      return;
    }
  }

  /* Table full — shouldn't happen if ip_over_limit was checked first */
  vkprintf (0, "WARNING: IP tracking table full for secret %d\n", secret_id);
}

void ip_track_disconnect_impl (int secret_id, unsigned ip, const unsigned char *ipv6) {
  if (ext_secret_max_ips[secret_id] <= 0 && ext_secret_rate_limit[secret_id] <= 0) { return; }

  static const unsigned char zero_ipv6[16] = {};

  for (int i = 0; i < SECRET_MAX_TRACKED_IPS; i++) {
    struct tracked_ip *e = &per_secret_ips[secret_id][i];
    if (e->connections <= 0) { continue; }
    int match = 0;
    if (ip != 0) {
      match = (e->ip == ip);
    } else {
      match = (e->ip == 0 && memcmp (e->ipv6, zero_ipv6, 16) != 0 &&
               memcmp (e->ipv6, ipv6, 16) == 0);
    }
    if (match) {
      e->connections--;
      if (e->connections <= 0) {
        e->ip = 0;
        memset (e->ipv6, 0, 16);
        e->connections = 0;
        per_secret_unique_ip_count[secret_id]--;
      }
      return;
    }
  }
}

void tcp_rpcs_ip_track_disconnect (int secret_id, unsigned ip, const unsigned char *ipv6) {
  ip_track_disconnect_impl (secret_id, ip, ipv6);
}

/* Wipe the IP-tracking table for a slot.  Used by the drain helpers in
   net-tcp-rpc-ext-drain.c, which can't see the private struct tracked_ip. */
void tcp_rpcs_ip_track_clear_slot (int secret_id) {
  if (secret_id < 0 || secret_id >= EXT_SECRET_MAX_SLOTS) { return; }
  memset (per_secret_ips[secret_id], 0, sizeof (per_secret_ips[secret_id]));
  per_secret_unique_ip_count[secret_id] = 0;
}

/*
 *  Per-IP rate limiting (token bucket)
 */

/* Find the tracked_ip entry for a given IP within a secret's table. */
static struct tracked_ip *find_tracked_ip (int secret_id, unsigned ip, const unsigned char *ipv6) {
  static const unsigned char zero_ipv6[16] = {};
  for (int i = 0; i < SECRET_MAX_TRACKED_IPS; i++) {
    struct tracked_ip *e = &per_secret_ips[secret_id][i];
    if (e->connections <= 0) { continue; }
    if (ip != 0) {
      if (e->ip == ip) { return e; }
    } else {
      if (e->ip == 0 && memcmp (e->ipv6, zero_ipv6, 16) != 0 &&
          memcmp (e->ipv6, ipv6, 16) == 0) { return e; }
    }
  }
  return NULL;
}

/* Refill tokens based on elapsed time.  Returns available tokens. */
static long long rate_bucket_refill (struct tracked_ip *tip, long long eff_rate) {
  double elapsed = precise_now - tip->last_refill_time;
  if (elapsed > 0) {
    long long refill = (long long)(elapsed * eff_rate);
    tip->tokens += refill;
    if (tip->tokens > eff_rate) {
      tip->tokens = eff_rate;  /* cap at 1-second burst */
    }
    tip->last_refill_time = precise_now;
  }
  return tip->tokens;
}

/* Consume tokens after a relay and throttle if bucket goes negative.
   Sets C_STOPREAD on the connection and schedules a timer to resume.
   Must be called AFTER tcp_direct_relay(). */
void rate_limit_after_relay (connection_job_t C, int secret_id,
                                    long long bytes, unsigned ip,
                                    const unsigned char *ipv6) {
  long long rl = ext_secret_rate_limit[secret_id];
  if (rl <= 0) { return; }

  struct tracked_ip *tip = find_tracked_ip (secret_id, ip, ipv6);
  if (!tip) { return; }

  long long eff = workers > 1 ? rl / workers : rl;
  if (eff < 1) { eff = 1; }

  rate_bucket_refill (tip, eff);
  tip->tokens -= bytes;

  if (tip->tokens < 0) {
    per_secret_rate_limited[secret_id]++;
    struct connection_info *c = CONN_INFO (C);
    __sync_fetch_and_or (&c->flags, C_STOPREAD);
    if (c->io_conn) {
      __sync_fetch_and_or (&SOCKET_CONN_INFO(c->io_conn)->flags, C_STOPREAD);
    }
    double delay = (double)(-tip->tokens) / (double)eff;
    if (delay < 0.001) { delay = 0.001; }
    if (delay > 5.0) { delay = 5.0; }
    job_timer_insert (C, precise_now + delay);
  }
}

/* Resume reading after rate limit pause (called from alarm handlers). */
int rate_limit_resume (connection_job_t C) {
  struct connection_info *c = CONN_INFO (C);
  if (!(c->flags & C_STOPREAD)) { return 0; }
  __sync_fetch_and_and (&c->flags, ~C_STOPREAD);
  if (c->io_conn) {
    __sync_fetch_and_and (&SOCKET_CONN_INFO(c->io_conn)->flags, ~C_STOPREAD);
    job_signal (JOB_REF_CREATE_PASS (c->io_conn), JS_RUN);
  }
  return 1;
}

void tcp_rpcs_set_ext_rand_pad_only(int set) {
  ext_rand_pad_only = set;
}

/* tcp_rpcs_pin_ext_secrets, tcp_rpcs_reload_ext_secrets and the
   tcp_rpcs_drain_* helpers live in net-tcp-rpc-ext-drain.c — they need
   shared write access to the ext_secret_* state defined above and were
   moved out to keep this file under the LLM-friendly file-size cap. */

static int allow_only_tls;

struct domain_info {
  const char *domain;
  int port;
  struct in_addr target;
  unsigned char target_ipv6[16];
  short server_hello_encrypted_size;
  char use_random_encrypted_size;
  char is_reversed_extension_order;
  struct domain_info *next;
};

static struct domain_info *default_domain_info;

#define DOMAIN_HASH_MOD 257
static struct domain_info *domains[DOMAIN_HASH_MOD];

static struct domain_info **get_domain_info_bucket (const char *domain, size_t len) {
  size_t i;
  unsigned hash = 0;
  for (i = 0; i < len; i++) {
    hash = hash * 239017 + (unsigned char)domain[i];
  }
  return domains + hash % DOMAIN_HASH_MOD;
}

static const struct domain_info *get_domain_info (const char *domain, size_t len) {
  struct domain_info *info = *get_domain_info_bucket (domain, len);
  while (info != NULL) {
    if (strlen (info->domain) == len && memcmp (domain, info->domain, len) == 0) {
      return info;
    }
    info = info->next;
  }
  return NULL;
}

/* Wider encrypted-data size variation defeats DPI that fingerprints the
   ServerHello response by its exact byte count.  Real TLS servers vary
   certificate chain / session ticket sizes by tens of bytes across
   connections.  We add uniform noise in [-32, +32] clamped to [1000, ∞). */
#define SH_ENCRYPTED_NOISE_RANGE 65   /* 2*32 + 1 */
#define SH_ENCRYPTED_NOISE_OFFSET 32
#define SH_ENCRYPTED_MIN_SIZE 1000

static int get_domain_server_hello_encrypted_size (const struct domain_info *info) {
  int base = info->server_hello_encrypted_size;
  if (info->use_random_encrypted_size) {
    int noise = (int)(rand () % SH_ENCRYPTED_NOISE_RANGE) - SH_ENCRYPTED_NOISE_OFFSET;
    int size = base + noise;
    if (size < SH_ENCRYPTED_MIN_SIZE) {
      size = SH_ENCRYPTED_MIN_SIZE;
    }
    return size;
  } else {
    return base;
  }
}

#define TLS_REQUEST_LENGTH 517

static BIGNUM *get_y2 (BIGNUM *x, const BIGNUM *mod, BN_CTX *big_num_context) {
  // returns y^2 = x^3 + 486662 * x^2 + x
  BIGNUM *y = BN_dup (x);
  assert (y != NULL);
  BIGNUM *coef = BN_new();
  assert (BN_set_word (coef, 486662) == 1);
  assert (BN_mod_add (y, y, coef, mod, big_num_context) == 1);
  assert (BN_mod_mul (y, y, x, mod, big_num_context) == 1);
  assert (BN_one (coef) == 1);
  assert (BN_mod_add (y, y, coef, mod, big_num_context) == 1);
  assert (BN_mod_mul (y, y, x, mod, big_num_context) == 1);
  BN_clear_free (coef);
  return y;
}

static BIGNUM *get_double_x (BIGNUM *x, const BIGNUM *mod, BN_CTX *big_num_context) {
  // returns x_2 = (x^2 - 1)^2/(4*y^2)
  BIGNUM *denominator = get_y2 (x, mod, big_num_context);
  assert (denominator != NULL);
  BIGNUM *coef = BN_new();
  assert (BN_set_word (coef, 4) == 1);
  assert (BN_mod_mul (denominator, denominator, coef, mod, big_num_context) == 1);

  BIGNUM *numerator = BN_new();
  assert (numerator != NULL);
  assert (BN_mod_mul (numerator, x, x, mod, big_num_context) == 1);
  assert (BN_one (coef) == 1);
  assert (BN_mod_sub (numerator, numerator, coef, mod, big_num_context) == 1);
  assert (BN_mod_mul (numerator, numerator, numerator, mod, big_num_context) == 1);

  assert (BN_mod_inverse (denominator, denominator, mod, big_num_context) == denominator);
  assert (BN_mod_mul (numerator, numerator, denominator, mod, big_num_context) == 1);

  BN_clear_free (coef);
  BN_clear_free (denominator);
  return numerator;
}

static void generate_public_key (unsigned char key[32]) {
  BIGNUM *mod = NULL;
  assert (BN_hex2bn (&mod, "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed") == 64);
  BIGNUM *pow = NULL;
  assert (BN_hex2bn (&pow, "3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff6") == 64);
  BN_CTX *big_num_context = BN_CTX_new();
  assert (big_num_context != NULL);

  BIGNUM *x = BN_new();
  while (1) {
    assert (RAND_bytes (key, 32) == 1);
    key[31] &= 127;
    BN_bin2bn (key, 32, x);
    assert (x != NULL);
    assert (BN_mod_mul (x, x, x, mod, big_num_context) == 1);

    BIGNUM *y = get_y2 (x, mod, big_num_context);

    BIGNUM *r = BN_new();
    assert (BN_mod_exp (r, y, pow, mod, big_num_context) == 1);
    BN_clear_free (y);
    if (BN_is_one (r)) {
      BN_clear_free (r);
      break;
    }
    BN_clear_free (r);
  }

  int i;
  for (i = 0; i < 3; i++) {
    BIGNUM *x2 = get_double_x (x, mod, big_num_context);
    BN_clear_free (x);
    x = x2;
  }

  int num_size = BN_num_bytes (x);
  assert (num_size <= 32);
  memset (key, '\0', 32 - num_size);
  assert (BN_bn2bin (x, key + (32 - num_size)) == num_size);
  for (i = 0; i < 16; i++) {
    unsigned char t = key[i];
    key[i] = key[31 - i];
    key[31 - i] = t;
  }

  BN_clear_free (x);
  BN_CTX_free (big_num_context);
  BN_clear_free (pow);
  BN_clear_free (mod);
}

static void add_string (unsigned char *str, int *pos, const char *data, int data_len) {
  assert (*pos + data_len <= TLS_REQUEST_LENGTH);
  memcpy (str + (*pos), data, data_len);
  (*pos) += data_len;
}

static void add_random (unsigned char *str, int *pos, int random_len) {
  assert (*pos + random_len <= TLS_REQUEST_LENGTH);
  assert (RAND_bytes (str + (*pos), random_len) == 1);
  (*pos) += random_len;
}

static void add_length (unsigned char *str, int *pos, int length) {
  assert (*pos + 2 <= TLS_REQUEST_LENGTH);
  str[*pos + 0] = (unsigned char)(length / 256);
  str[*pos + 1] = (unsigned char)(length % 256);
  (*pos) += 2;
}

static void add_grease (unsigned char *str, int *pos, const unsigned char *greases, int num) {
  assert (*pos + 2 <= TLS_REQUEST_LENGTH);
  str[*pos + 0] = greases[num];
  str[*pos + 1] = greases[num];
  (*pos) += 2;
}

static void add_public_key (unsigned char *str, int *pos) {
  assert (*pos + 32 <= TLS_REQUEST_LENGTH);
  generate_public_key (str + (*pos));
  (*pos) += 32;
}

static unsigned char *create_request (const char *domain) {
  unsigned char *result = malloc (TLS_REQUEST_LENGTH);
  int pos = 0;

#define MAX_GREASE 7
  unsigned char greases[MAX_GREASE];
  assert (RAND_bytes (greases, MAX_GREASE) == 1);
  int i;
  for (i = 0; i < MAX_GREASE; i++) {
    greases[i] = (unsigned char)((greases[i] & 0xF0) + 0x0A);
  }
  for (i = 1; i < MAX_GREASE; i += 2) {
    if (greases[i] == greases[i - 1]) {
      greases[i] = (unsigned char)(0x10 ^ greases[i]);
    }
  }
#undef MAX_GREASE

  int domain_length = (int)strlen (domain);

  add_string (result, &pos, "\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03", 11);
  add_random (result, &pos, 32);
  add_string (result, &pos, "\x20", 1);
  add_random (result, &pos, 32);
  add_string (result, &pos, "\x00\x22", 2);
  add_grease (result, &pos, greases, 0);
  add_string (result, &pos, "\x13\x01\x13\x02\x13\x03\xc0\x2b\xc0\x2f\xc0\x2c\xc0\x30\xcc\xa9\xcc\xa8"
                            "\xc0\x13\xc0\x14\x00\x9c\x00\x9d\x00\x2f\x00\x35\x00\x0a\x01\x00\x01\x91", 36);
  add_grease (result, &pos, greases, 2);
  add_string (result, &pos, "\x00\x00\x00\x00", 4);
  add_length (result, &pos, domain_length + 5);
  add_length (result, &pos, domain_length + 3);
  add_string (result, &pos, "\x00", 1);
  add_length (result, &pos, domain_length);
  add_string (result, &pos, domain, domain_length);
  add_string (result, &pos, "\x00\x17\x00\x00\xff\x01\x00\x01\x00\x00\x0a\x00\x0a\x00\x08", 15);
  add_grease (result, &pos, greases, 4);
  add_string (result, &pos, "\x00\x1d\x00\x17\x00\x18\x00\x0b\x00\x02\x01\x00\x00\x23\x00\x00\x00\x10"
                            "\x00\x0e\x00\x0c\x02\x68\x32\x08\x68\x74\x74\x70\x2f\x31\x2e\x31\x00\x05"
                            "\x00\x05\x01\x00\x00\x00\x00\x00\x0d\x00\x14\x00\x12\x04\x03\x08\x04\x04"
                            "\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01\x02\x01\x00\x12\x00\x00\x00"
                            "\x33\x00\x2b\x00\x29", 77);
  add_grease (result, &pos, greases, 4);
  add_string (result, &pos, "\x00\x01\x00\x00\x1d\x00\x20", 7);
  add_public_key (result, &pos);
  add_string (result, &pos, "\x00\x2d\x00\x02\x01\x01\x00\x2b\x00\x0b\x0a", 11);
  add_grease (result, &pos, greases, 6);
  add_string (result, &pos, "\x03\x04\x03\x03\x03\x02\x03\x01\x00\x1b\x00\x03\x02\x00\x02", 15);
  add_grease (result, &pos, greases, 3);
  add_string (result, &pos, "\x00\x01\x00\x00\x15", 5);

  int padding_length = TLS_REQUEST_LENGTH - 2 - pos;
  assert (padding_length >= 0);
  add_length (result, &pos, padding_length);
  memset (result + pos, 0, TLS_REQUEST_LENGTH - pos);
  return result;
}

static int update_domain_info (struct domain_info *info) {
  const char *domain = info->domain;

  // Try parsing as a literal IP address first
  struct in_addr addr4;
  struct in6_addr addr6;
  int af = 0;
  if (inet_pton (AF_INET, domain, &addr4) == 1) {
    af = AF_INET;
    info->target = addr4;
    memset (info->target_ipv6, 0, sizeof (info->target_ipv6));
  } else if (inet_pton (AF_INET6, domain, &addr6) == 1) {
    af = AF_INET6;
    info->target.s_addr = 0;
    memcpy (info->target_ipv6, &addr6, sizeof (info->target_ipv6));
  }

  struct hostent *host = NULL;
  if (!af) {
    host = kdb_gethostbyname (domain);
    if (host == NULL || host->h_addr == NULL) {
      kprintf ("Failed to resolve host %s\n", domain);
      return 0;
    }
    assert (host->h_addrtype == AF_INET || host->h_addrtype == AF_INET6);
    af = host->h_addrtype;
  }

  fd_set read_fd;
  fd_set write_fd;
  fd_set except_fd;
  FD_ZERO(&read_fd);
  FD_ZERO(&write_fd);
  FD_ZERO(&except_fd);

#define TRIES 20
  int sockets[TRIES];
  int i;
  for (i = 0; i < TRIES; i++) {
    sockets[i] = socket (af, SOCK_STREAM, IPPROTO_TCP);
    if (sockets[i] < 0) {
      kprintf ("Failed to open socket for %s: %s\n", domain, strerror (errno));
      return 0;
    }
    if (fcntl (sockets[i], F_SETFL, O_NONBLOCK) == -1) {
      kprintf ("Failed to make socket non-blocking: %s\n", strerror (errno));
      return 0;
    }

    int e_connect;
    if (af == AF_INET) {
      if (host) {
        info->target = *((struct in_addr *) host->h_addr);
        memset (info->target_ipv6, 0, sizeof (info->target_ipv6));
      }

      struct sockaddr_in addr;
      memset (&addr, 0, sizeof (addr));
      addr.sin_family = AF_INET;
      addr.sin_port = htons (info->port);
      memcpy (&addr.sin_addr, &info->target, sizeof (struct in_addr));

      e_connect = connect (sockets[i], (struct sockaddr *)&addr, sizeof (addr));
    } else {
      if (host) {
        assert (sizeof (struct in6_addr) == sizeof (info->target_ipv6));
        info->target.s_addr = 0;
        memcpy (info->target_ipv6, host->h_addr, sizeof (struct in6_addr));
      }

      struct sockaddr_in6 addr;
      memset (&addr, 0, sizeof (addr));
      addr.sin6_family = AF_INET6;
      addr.sin6_port = htons (info->port);
      memcpy (&addr.sin6_addr, info->target_ipv6, sizeof (struct in6_addr));

      e_connect = connect (sockets[i], (struct sockaddr *)&addr, sizeof (addr));
    }

    if (e_connect == -1 && errno != EINPROGRESS) {
      kprintf ("Failed to connect to %s: %s\n", domain, strerror (errno));
      return 0;
    }
  }

  unsigned char *requests[TRIES];
  for (i = 0; i < TRIES; i++) {
    requests[i] = create_request (domain);
  }
  unsigned char *responses[TRIES] = {};
  int response_len[TRIES] = {};
  int is_encrypted_application_data_length_read[TRIES] = {};

  int finished_count = 0;
  int is_written[TRIES] = {};
  int is_finished[TRIES] = {};
  int read_pos[TRIES] = {};
  double finish_time = get_utime_monotonic() + 5.0;
  int is_reversed_extension_order_min = 0;
  int is_reversed_extension_order_max = 0;
  int all_record_counts[TRIES] = {};
  int all_total_encrypted[TRIES] = {};
  int have_error = 0;
  while (get_utime_monotonic() < finish_time && finished_count < TRIES && !have_error) {
    struct timeval timeout_data;
    timeout_data.tv_sec = (int)(finish_time - precise_now + 1);
    timeout_data.tv_usec = 0;

    int max_fd = 0;
    for (i = 0; i < TRIES; i++) {
      if (is_finished[i]) {
        continue;
      }
      if (is_written[i]) {
        FD_SET(sockets[i], &read_fd);
        FD_CLR(sockets[i], &write_fd);
      } else {
        FD_CLR(sockets[i], &read_fd);
        FD_SET(sockets[i], &write_fd);
      }
      FD_SET(sockets[i], &except_fd);
      if (sockets[i] > max_fd) {
        max_fd = sockets[i];
      }
    }

    select (max_fd + 1, &read_fd, &write_fd, &except_fd, &timeout_data);

    for (i = 0; i < TRIES; i++) {
      if (is_finished[i]) {
        continue;
      }
      if (FD_ISSET(sockets[i], &read_fd)) {
        assert (is_written[i]);

        unsigned char header[5];
        if (responses[i] == NULL) {
          ssize_t read_res = read (sockets[i], header, sizeof (header));
          if (read_res != sizeof (header)) {
            kprintf ("Failed to read response header for checking domain %s: %s\n", domain, read_res == -1 ? strerror (errno) : "Read less bytes than expected");
            have_error = 1;
            break;
          }
          if (memcmp (header, "\x16\x03\x03", 3) != 0) {
            kprintf ("Non-TLS response, or TLS <= 1.1, or unsuccessful request to %s: receive \\x%02x\\x%02x\\x%02x\\x%02x\\x%02x...\n",
                     domain, header[0], header[1], header[2], header[3], header[4]);
            have_error = 1;
            break;
          }
          response_len[i] = 5 + header[3] * 256 + header[4] + 6 + 5;
          responses[i] = malloc (response_len[i]);
          memcpy (responses[i], header, sizeof (header));
          read_pos[i] = 5;
        } else {
          ssize_t read_res = read (sockets[i], responses[i] + read_pos[i], response_len[i] - read_pos[i]);
          if (read_res == -1) {
            kprintf ("Failed to read response from %s: %s\n", domain, strerror (errno));
            have_error = 1;
            break;
          }
          read_pos[i] += read_res;

          if (read_pos[i] == response_len[i]) {
            if (!is_encrypted_application_data_length_read[i]) {
              if (memcmp (responses[i] + response_len[i] - 11, "\x14\x03\x03\x00\x01\x01\x17\x03\x03", 9) != 0) {
                kprintf ("Not found TLS 1.3 support on domain %s\n", domain);
                have_error = 1;
                break;
              }

              is_encrypted_application_data_length_read[i] = 1;
              int encrypted_application_data_length = responses[i][response_len[i] - 2] * 256 + responses[i][response_len[i] - 1];
              response_len[i] += encrypted_application_data_length;
              unsigned char *new_buffer = realloc (responses[i], response_len[i]);
              assert (new_buffer != NULL);
              responses[i] = new_buffer;
              continue;
            }

            // Capture additional encrypted records from kernel buffer
            for (;;) {
              unsigned char extra_buf[16384];
              ssize_t extra = read (sockets[i], extra_buf, sizeof (extra_buf));
              if (extra <= 0) {
                break;
              }
              unsigned char *new_buf = realloc (responses[i], response_len[i] + extra);
              assert (new_buf != NULL);
              responses[i] = new_buf;
              memcpy (responses[i] + response_len[i], extra_buf, extra);
              response_len[i] += extra;
              read_pos[i] = response_len[i];
            }

            int is_reversed_extension_order = -1;
            int probe_record_sizes[MAX_ENCRYPTED_RECORDS];
            int probe_record_count = 0;
            if (tls_check_server_hello (responses[i], response_len[i], requests[i] + 44, &is_reversed_extension_order, probe_record_sizes, &probe_record_count)) {
              assert (is_reversed_extension_order != -1);
              assert (probe_record_count > 0);
              // Sum all record sizes into total encrypted size for this probe
              int total_encrypted = 0;
              int j;
              for (j = 0; j < probe_record_count && j < MAX_ENCRYPTED_RECORDS; j++) {
                total_encrypted += probe_record_sizes[j];
              }
              all_record_counts[finished_count] = probe_record_count;
              all_total_encrypted[finished_count] = total_encrypted;
              if (finished_count == 0) {
                is_reversed_extension_order_min = is_reversed_extension_order;
                is_reversed_extension_order_max = is_reversed_extension_order;
              } else {
                if (is_reversed_extension_order < is_reversed_extension_order_min) {
                  is_reversed_extension_order_min = is_reversed_extension_order;
                }
                if (is_reversed_extension_order > is_reversed_extension_order_max) {
                  is_reversed_extension_order_max = is_reversed_extension_order;
                }
              }

              FD_CLR(sockets[i], &write_fd);
              FD_CLR(sockets[i], &read_fd);
              FD_CLR(sockets[i], &except_fd);
              is_finished[i] = 1;
              finished_count++;
            } else {
              have_error = 1;
              break;
            }
          }
        }
      }
      if (FD_ISSET(sockets[i], &write_fd)) {
        assert (!is_written[i]);
        ssize_t write_res = write (sockets[i], requests[i], TLS_REQUEST_LENGTH);
        if (write_res != TLS_REQUEST_LENGTH) {
          kprintf ("Failed to write request for checking domain %s: %s", domain, write_res == -1 ? strerror (errno) : "Written less bytes than expected");
          have_error = 1;
          break;
        }
        is_written[i] = 1;
      }
      if (FD_ISSET(sockets[i], &except_fd)) {
        kprintf ("Failed to check domain %s: %s\n", domain, strerror (errno));
        have_error = 1;
        break;
      }
    }
  }

  for (i = 0; i < TRIES; i++) {
    close (sockets[i]);
    free (requests[i]);
    free (responses[i]);
  }

  if (finished_count != TRIES) {
    if (!have_error) {
      kprintf ("Failed to check domain %s in 5 seconds\n", domain);
    }
    return 0;
  }

  if (is_reversed_extension_order_min != is_reversed_extension_order_max) {
    kprintf ("Upstream server %s uses non-deterministic extension order\n", domain);
  }

  info->is_reversed_extension_order = (char)is_reversed_extension_order_min;

  // Aggregate total encrypted size across all probes
  int encrypted_size_min = all_total_encrypted[0];
  int encrypted_size_max = all_total_encrypted[0];
  int encrypted_size_sum = all_total_encrypted[0];
  for (i = 1; i < TRIES; i++) {
    if (all_total_encrypted[i] < encrypted_size_min) {
      encrypted_size_min = all_total_encrypted[i];
    }
    if (all_total_encrypted[i] > encrypted_size_max) {
      encrypted_size_max = all_total_encrypted[i];
    }
    encrypted_size_sum += all_total_encrypted[i];
  }

  if (encrypted_size_min == encrypted_size_max) {
    info->server_hello_encrypted_size = encrypted_size_min;
    info->use_random_encrypted_size = 0;
  } else if (encrypted_size_max - encrypted_size_min <= 3) {
    info->server_hello_encrypted_size = encrypted_size_max - 1;
    info->use_random_encrypted_size = 1;
  } else {
    kprintf ("Unrecognized encrypted application data length pattern with min = %d, max = %d, mean = %.3lf\n",
             encrypted_size_min, encrypted_size_max, encrypted_size_sum * 1.0 / TRIES);
    info->server_hello_encrypted_size = (int)(encrypted_size_sum * 1.0 / TRIES + 0.5);
    info->use_random_encrypted_size = 1;
  }

  vkprintf (0, "Successfully checked domain %s in %.3lf seconds: is_reversed_extension_order = %d, "
            "server_hello_encrypted_size = %d (from %d record(s)), use_random_encrypted_size = %d\n",
            domain, get_utime_monotonic() - (finish_time - 5.0), info->is_reversed_extension_order,
            info->server_hello_encrypted_size, all_record_counts[0], info->use_random_encrypted_size);
  return 1;
#undef TRIES
}

#undef TLS_REQUEST_LENGTH

static const struct domain_info *get_sni_domain_info (const unsigned char *request, int len) {
  char domain_buf[256];
  int domain_length = tls_parse_sni (request, len, domain_buf, sizeof (domain_buf));
  if (domain_length < 0) {
    return NULL;
  }
  const struct domain_info *info = get_domain_info (domain_buf, domain_length);
  if (info == NULL) {
    vkprintf (1, "Receive request for unknown domain %.*s\n", domain_length, domain_buf);
  }
  return info;
}

void tcp_rpc_add_proxy_domain (const char *domain) {
  assert (domain != NULL);

  struct domain_info *info = calloc (1, sizeof (struct domain_info));
  assert (info != NULL);
  info->port = 443;

  const char *host_start = domain;
  const char *host_end = NULL;

  if (domain[0] == '[') {
    // [IPv6]:port format
    host_end = strchr (domain, ']');
    if (host_end == NULL) {
      kprintf ("Invalid IPv6 address: %s\n", domain);
      free (info);
      return;
    }
    host_start = domain + 1;
    const char *after_bracket = host_end + 1;
    if (*after_bracket == ':') {
      info->port = atoi (after_bracket + 1);
    }
    info->domain = strndup (host_start, host_end - host_start);
  } else {
    // Check for host:port — but only if the last colon has digits after it
    // and there is at most one colon (to avoid matching bare IPv6 like ::1)
    const char *colon = strrchr (domain, ':');
    if (colon != NULL && strchr (domain, ':') == colon) {
      // Exactly one colon — treat as host:port
      info->port = atoi (colon + 1);
      info->domain = strndup (domain, colon - domain);
    } else {
      info->domain = strdup (domain);
    }
  }

  if (info->port <= 0 || info->port > 65535) {
    kprintf ("Invalid port in domain spec: %s\n", domain);
    free ((void *)info->domain);
    free (info);
    return;
  }

  kprintf ("Proxy domain: %s:%d\n", info->domain, info->port);

  struct domain_info **bucket = get_domain_info_bucket (info->domain, strlen (info->domain));
  info->next = *bucket;
  *bucket = info;

  if (!allow_only_tls) {
    allow_only_tls = 1;
    default_domain_info = info;
  }
}

void tcp_rpc_init_proxy_domains() {
  int i;
  for (i = 0; i < DOMAIN_HASH_MOD; i++) {
    struct domain_info *info = domains[i];
    while (info != NULL) {
      if (!update_domain_info (info)) {
        kprintf ("Failed to update response data about %s, so default response settings wiil be used\n", info->domain);
        // keep target addresses as is
        info->is_reversed_extension_order = 0;
        info->use_random_encrypted_size = 1;
        info->server_hello_encrypted_size = 2500 + rand() % 1120;
      }

      info = info->next;
    }
  }
}

struct client_random {
  unsigned char random[16];
  struct client_random *next_by_time;
  struct client_random *next_by_hash;
  int time;
};

#define RANDOM_HASH_BITS 14
static struct client_random *client_randoms[1 << RANDOM_HASH_BITS];

static struct client_random *first_client_random;
static struct client_random *last_client_random;

static struct client_random **get_client_random_bucket (unsigned char random[16]) {
  int i = RANDOM_HASH_BITS;
  int pos = 0;
  int id = 0;
  while (i > 0) {
    int bits = i < 8 ? i : 8;
    id = (id << bits) | (random[pos++] & ((1 << bits) - 1));
    i -= bits;
  }
  assert (0 <= id && id < (1 << RANDOM_HASH_BITS));
  return client_randoms + id;
}

static int have_client_random (unsigned char random[16]) {
  struct client_random *cur = *get_client_random_bucket (random);
  while (cur != NULL) {
    if (memcmp (random, cur->random, 16) == 0) {
      return 1;
    }
    cur = cur->next_by_hash;
  }
  return 0;
}

static void add_client_random (unsigned char random[16]) {
  struct client_random *entry = malloc (sizeof (struct client_random));
  memcpy (entry->random, random, 16);
  entry->time = now;
  entry->next_by_time = NULL;
  if (last_client_random == NULL) {
    assert (first_client_random == NULL);
    first_client_random = last_client_random = entry;
  } else {
    last_client_random->next_by_time = entry;
    last_client_random = entry;
  }

  struct client_random **bucket = get_client_random_bucket (random);
  entry->next_by_hash = *bucket;
  *bucket = entry;
}

#define MAX_CLIENT_RANDOM_CACHE_TIME 2 * 86400

static void delete_old_client_randoms() {
  while (first_client_random != last_client_random) {
    assert (first_client_random != NULL);
    if (first_client_random->time > now - MAX_CLIENT_RANDOM_CACHE_TIME) {
      return;
    }

    struct client_random *entry = first_client_random;
    assert (entry->next_by_hash == NULL);

    first_client_random = first_client_random->next_by_time;

    struct client_random **cur = get_client_random_bucket (entry->random);
    while (*cur != entry) {
      cur = &(*cur)->next_by_hash;
    }
    *cur = NULL;

    free (entry);
  }
}

static int is_allowed_timestamp (int timestamp) {
  if (timestamp > now + 3) {
    // do not allow timestamps in the future
    // after time synchronization client should always have time in the past
    vkprintf (1, "Disallow request with timestamp %d from the future, now is %d\n", timestamp, now);
    return 0;
  }

  // first_client_random->time is an exact time when corresponding request was received
  // if the timestamp is bigger than (first_client_random->time + 3), then the current request could be accepted
  // only after the request with first_client_random, so the client random still must be cached
  // if the request wasn't accepted, then the client_random still will be cached for MAX_CLIENT_RANDOM_CACHE_TIME seconds,
  // so we can miss duplicate request only after a lot of time has passed
  if (first_client_random != NULL && timestamp > first_client_random->time + 3) {
    vkprintf (1, "Allow new request with timestamp %d\n", timestamp);
    return 1;
  }

  // allow all requests with timestamp recently in past, regardless of ability to check repeating client random
  // the allowed error must be big enough to allow requests after time synchronization
  const int MAX_ALLOWED_TIMESTAMP_ERROR = 2 * 60;
  if (timestamp > now - MAX_ALLOWED_TIMESTAMP_ERROR) {
    // this can happen only first (MAX_ALLOWED_TIMESTAMP_ERROR + 3) sceonds after first_client_random->time
    vkprintf (1, "Allow recent request with timestamp %d without full check for client random duplication\n", timestamp);
    return 1;
  }

  // the request is too old to check client random, do not allow it to force client to synchronize it's time
  vkprintf (1, "Disallow too old request with timestamp %d\n", timestamp);
  return 0;
}

static int proxy_connection (connection_job_t C, const struct domain_info *info) {
  struct connection_info *c = CONN_INFO(C);

  /* No longer an MTProxy connection — clear secret tracking to prevent
     spurious decrement in mtproto_ext_rpc_close on failure paths. */
  TCP_RPC_DATA(C)->extra_int2 = 0;

  assert (check_conn_functions (&ct_proxy_pass, 0) >= 0);

  const char zero[16] = {};
  if (info->target.s_addr == 0 && !memcmp (info->target_ipv6, zero, 16)) {
    vkprintf (0, "failed to proxy request to %s\n", info->domain);
    fail_connection (C, -17);
    return 0;
  }

  int port = c->our_port == 80 ? 80 : info->port;

  int cfd = -1;
  if (info->target.s_addr) {
    cfd = client_socket (info->target.s_addr, port, 0);
  } else {
    cfd = client_socket_ipv6 (info->target_ipv6, port, SM_IPV6);
  }

  if (cfd < 0) {
    kprintf ("failed to create proxy pass connection: %d (%m)", errno);
    fail_connection (C, -27);
    return 0;
  }

  c->type->crypto_free (C);
  job_incref (C); 
  job_t EJ = alloc_new_connection (cfd, NULL, NULL, ct_outbound, &ct_proxy_pass, C, ntohl (*(int *)&info->target.s_addr), (void *)info->target_ipv6, port); 

  if (!EJ) {
    kprintf ("failed to create proxy pass connection (2)");
    job_decref_f (C);
    fail_connection (C, -37);
    return 0;
  }

  c->type = &ct_proxy_pass;
  c->extra = job_incref (EJ);
      
  assert (CONN_INFO(EJ)->io_conn);
  unlock_job (JOB_REF_PASS (EJ));

  return c->type->parse_execute (C);
}

int tcp_rpcs_ext_alarm (connection_job_t C) {
  if (CONN_INFO(C)->flags & C_PROXY_PROTOCOL) {
    proxy_protocol_errors_total++;
    vkprintf (1, "PROXY protocol header timeout from %s\n", show_remote_ip (C));
    fail_connection (C, -1);
    return 0;
  }
  struct tcp_rpc_data *D = TCP_RPC_DATA (C);
  if (D->in_packet_num == -3 && default_domain_info != NULL) {
    return proxy_connection (C, default_domain_info);
  } else {
    return 0;
  }
}

/* DRS alarm handler: handles both handshake timeout and inter-record delay resume.
   Both JS_RUN and JS_ALARM run on the NET-CPU thread, so calling read_write is safe. */
int tcp_rpcs_ext_drs_alarm (connection_job_t C) {
  struct connection_info *c = CONN_INFO (C);
  struct tcp_rpc_data *D = TCP_RPC_DATA (C);

  /* Rate limit resume (must be checked before other conditions) */
  if (rate_limit_resume (C)) { return 0; }

  /* Direct client retry: DC connection not yet established */
  if (c->type == &ct_direct_client_drs && !c->extra && D->extra_int > 0) {
    direct_retry_dc_connection (C);
    return 0;
  }

  /* PROXY protocol header timeout */
  if (c->flags & C_PROXY_PROTOCOL) {
    proxy_protocol_errors_total++;
    vkprintf (1, "PROXY protocol header timeout from %s\n", show_remote_ip (C));
    fail_connection (C, -1);
    return 0;
  }

  /* Handshake timeout (pre-handshake state) */
  if (D->in_packet_num == -3 && default_domain_info != NULL) {
    return proxy_connection (C, default_domain_info);
  }

  /* DRS delay resume: timer fired, process next record */
  if (c->flags & C_IS_TLS) {
    struct drs_state *drs = DRS_STATE (C);
    if (drs->delay_pending) {
      drs->delay_pending = 0;
      c->type->read_write (C);
    }
  }
  return 0;
}

int tcp_rpcs_ext_init_accepted (connection_job_t C) {
  if (proxy_protocol_enabled) {
    CONN_INFO(C)->flags |= C_PROXY_PROTOCOL;
  }
  job_timer_insert (C, precise_now + 10);
  return tcp_rpcs_init_accepted_nohs (C);
}

int tcp_rpcs_compact_parse_execute (connection_job_t C) {
#define RETURN_TLS_ERROR(info) \
  return proxy_connection (C, info);  

  struct tcp_rpc_data *D = TCP_RPC_DATA (C);
  if (D->crypto_flags & RPCF_COMPACT_OFF) {
    if (D->in_packet_num != -3) {
      job_timer_remove (C);
    }
    return tcp_rpcs_parse_execute (C);
  }

  struct connection_info *c = CONN_INFO (C);
  int len;

  vkprintf (4, "%s. in_total_bytes = %d\n", __func__, c->in.total_bytes);

  while (1) {
    if (D->in_packet_num != -3) {
      job_timer_remove (C);
    }
    if (c->flags & C_ERROR) {
      return NEED_MORE_BYTES;
    }
    if (c->flags & C_STOPPARSE) {
      return NEED_MORE_BYTES;
    }
    len = c->in.total_bytes; 
    if (len <= 0) {
      return NEED_MORE_BYTES;
    }

    int min_len = (D->flags & RPC_F_MEDIUM) ? 4 : 1;
    if (len < min_len + 8) {
      return min_len + 8 - len;
    }

    int packet_len = 0;
    if (rwm_fetch_lookup (&c->in, &packet_len, 4) != 4) { fail_connection (C, -1); return 0; }

    if (D->in_packet_num == -3) {
      /* PROXY protocol: strip header before any protocol detection */
      if (c->flags & C_PROXY_PROTOCOL) {
        struct proxy_protocol_result pp;
        int pp_ret = proxy_protocol_parse (&c->in, &pp);
        if (pp_ret == 0) {
          int need = 16 - c->in.total_bytes;
          return need > 0 ? need : NEED_MORE_BYTES;
        }
        if (pp_ret < 0) {
          proxy_protocol_errors_total++;
          vkprintf (1, "PROXY protocol parse error from %s:%d\n", show_remote_ip (C), c->remote_port);
          fail_connection (C, -1);
          return 0;
        }
        c->flags &= ~C_PROXY_PROTOCOL;
        proxy_protocol_connections_total++;
        if (pp.family == AF_INET) {
          c->remote_ip = pp.src_ip;
          memset (c->remote_ipv6, 0, 16);
          c->remote_port = pp.src_port;
          c->flags &= ~C_IPV6;
        } else if (pp.family == AF_INET6) {
          c->remote_ip = 0;
          memcpy (c->remote_ipv6, pp.src_ipv6, 16);
          c->remote_port = pp.src_port;
          c->flags |= C_IPV6;
        }
        /* family==0 (UNKNOWN/LOCAL): keep original IP */
        if (pp.family) {
          int acl_ok = c->remote_ip
            ? ip_acl_check_v4 (c->remote_ip)
            : ip_acl_check_v6 (c->remote_ipv6);
          if (!acl_ok) {
            vkprintf (1, "PROXY protocol: real client %s rejected by IP ACL\n", show_remote_ip (C));
            fail_connection (C, -1);
            return 0;
          }
        }
        vkprintf (1, "PROXY protocol: real client %s:%d\n", show_remote_ip (C), c->remote_port);
        len = c->in.total_bytes;
        if (len <= 0) {
          return NEED_MORE_BYTES;
        }
        if (len < min_len + 8) {
          return min_len + 8 - len;
        }
        if (rwm_fetch_lookup (&c->in, &packet_len, 4) != 4) { fail_connection (C, -1); return 0; }
      }
      vkprintf (1, "trying to determine type of connection from %s:%d\n", show_remote_ip (C), c->remote_port);
#if __ALLOW_UNOBFS__
      if ((packet_len & 0xff) == 0xef) {
        D->flags |= RPC_F_COMPACT;
        if (rwm_skip_data (&c->in, 1) != 1) { fail_connection (C, -1); return 0; }
        D->in_packet_num = 0;
        vkprintf (1, "Short type\n");
        continue;
      } 
      if (packet_len == 0xeeeeeeee) {
        D->flags |= RPC_F_MEDIUM;
        if (rwm_skip_data (&c->in, 4) != 4) { fail_connection (C, -1); return 0; }
        D->in_packet_num = 0;
        vkprintf (1, "Medium type\n");
        continue;
      }
      if (packet_len == 0xdddddddd) {
        D->flags |= RPC_F_MEDIUM | RPC_F_PAD;
        if (rwm_skip_data (&c->in, 4) != 4) { fail_connection (C, -1); return 0; }
        D->in_packet_num = 0;
        vkprintf (1, "Medium type\n");
        continue;
      }
        
      // http
      if ((packet_len == *(int *)"HEAD" || packet_len == *(int *)"POST" || packet_len == *(int *)"GET " || packet_len == *(int *)"OPTI") && TCP_RPCS_FUNC(C)->http_fallback_type) {
        D->crypto_flags |= RPCF_COMPACT_OFF;
        vkprintf (1, "HTTP type\n");
        return tcp_rpcs_parse_execute (C);
      }
#endif

      // fake tls
      if (c->flags & C_IS_TLS) {
        if (len < 11) {
          return 11 - len;
        }

        vkprintf (1, "Established TLS connection from %s:%d\n", show_remote_ip (C), c->remote_port);
        unsigned char header[11];
        if (rwm_fetch_lookup (&c->in, header, 11) != 11) { fail_connection (C, -1); return 0; }
        if (memcmp (header, "\x14\x03\x03\x00\x01\x01\x17\x03\x03", 9) != 0) {
          vkprintf (1, "error while parsing packet: bad client dummy ChangeCipherSpec\n");
          fail_connection (C, -1);
          return 0;
        }

        min_len = 11 + 256 * header[9] + header[10];
        if (len < min_len) {
          vkprintf (2, "Need %d bytes, but have only %d\n", min_len, len);
          return min_len - len;
        }

        if (rwm_skip_data (&c->in, 11) != 11) { fail_connection (C, -1); return 0; }
        len -= 11;
        c->left_tls_packet_length = 256 * header[9] + header[10]; // store left length of current TLS packet in extra_int3
        vkprintf (2, "Receive first TLS packet of length %d\n", c->left_tls_packet_length);

        if (c->left_tls_packet_length < 64) {
          vkprintf (1, "error while parsing packet: too short first TLS packet: %d\n", c->left_tls_packet_length);
          fail_connection (C, -1);
          return 0;
        }
        // now len >= c->left_tls_packet_length >= 64

        if (rwm_fetch_lookup (&c->in, &packet_len, 4) != 4) { fail_connection (C, -1); return 0; }

        c->left_tls_packet_length -= 64; // skip header length
      } else if ((packet_len & 0xFFFFFF) == 0x010316 && (packet_len >> 24) >= 2 && ext_secret_cnt > 0 && allow_only_tls) {
        unsigned char header[5];
        if (rwm_fetch_lookup (&c->in, header, 5) != 5) { fail_connection (C, -1); return 0; }
        min_len = 5 + 256 * header[3] + header[4];
        if (len < min_len) {
          return min_len - len;
        }

        int read_len = len <= 4096 ? len : 4096;
        unsigned char client_hello[read_len + 1]; // VLA
        if (rwm_fetch_lookup (&c->in, client_hello, read_len) != read_len) { fail_connection (C, -1); return 0; }

        const struct domain_info *info = get_sni_domain_info (client_hello, read_len);
        if (info == NULL) {
          RETURN_TLS_ERROR(default_domain_info);
        }

        vkprintf (1, "TLS type with domain %s from %s:%d\n", info->domain, show_remote_ip (C), c->remote_port);

        if (c->our_port == 80) {
          vkprintf (1, "Receive TLS request on port %d, proxying to %s\n", c->our_port, info->domain);
          RETURN_TLS_ERROR(info);
        }

        if (len > min_len) {
          vkprintf (1, "Too much data in ClientHello, receive %d instead of %d\n", len, min_len);
          RETURN_TLS_ERROR(info);
        }
        if (len != read_len) {
          vkprintf (1, "Too big ClientHello: receive %d bytes\n", len);
          RETURN_TLS_ERROR(info);
        }

        unsigned char client_random[32];
        memcpy (client_random, client_hello + 11, 32);
        memset (client_hello + 11, '\0', 32);

        if (have_client_random (client_random)) {
          vkprintf (1, "Receive again request with the same client random\n");
          RETURN_TLS_ERROR(info);
        }
        add_client_random (client_random);
        delete_old_client_randoms();

        unsigned char expected_random[32];
        int secret_id;
        for (secret_id = 0; secret_id < ext_secret_cnt; secret_id++) {
          if (ext_secret_state[secret_id] == SLOT_FREE) { continue; }
          sha256_hmac (ext_secret[secret_id], 16, client_hello, len, expected_random);
          if (CRYPTO_memcmp (expected_random, client_random, 28) == 0) {
            break;
          }
        }
        if (secret_id == ext_secret_cnt) {
          vkprintf (1, "Receive request with unmatched client random\n");
          RETURN_TLS_ERROR(info);
        }
        int timestamp = *(int *)(expected_random + 28) ^ *(int *)(client_random + 28);
        if (!is_allowed_timestamp (timestamp)) {
          RETURN_TLS_ERROR(info);
        }

        /* Don't set D->extra_int2 here.  The per-secret connection counter
           is only incremented in the obfs2 parser block below (after the TLS
           handshake completes and the client sends the encrypted obfs2 init).
           Setting extra_int2 too early would cause spurious counter
           decrements in the close handler if the connection dies between
           the TLS handshake and obfs2 init.  Local secret_id is sufficient
           for the rejection checks and HMAC computation below. */
        vkprintf (1, "TLS handshake matched secret [%s] from %s:%d\n", ext_secret_label[secret_id], show_remote_ip (C), c->remote_port);

        if (ext_secret_state[secret_id] == SLOT_DRAINING) {
          per_secret_rejected_draining[secret_id]++;
          vkprintf (1, "TLS connection rejected: secret [%s] draining from %s:%d\n", ext_secret_label[secret_id], show_remote_ip (C), c->remote_port);
          RETURN_TLS_ERROR(info);
        }

        if (secret_expired (secret_id)) {
          per_secret_rejected_expired[secret_id]++;
          vkprintf (1, "TLS connection rejected: secret [%s] expired from %s:%d\n", ext_secret_label[secret_id], show_remote_ip (C), c->remote_port);
          RETURN_TLS_ERROR(info);
        }

        if (secret_over_limit (secret_id)) {
          per_secret_connections_rejected[secret_id]++;
          vkprintf (1, "TLS connection rejected: secret [%s] at limit %d from %s:%d\n", ext_secret_label[secret_id], ext_secret_limit[secret_id], show_remote_ip (C), c->remote_port);
          RETURN_TLS_ERROR(info);
        }

        if (secret_over_quota (secret_id)) {
          per_secret_rejected_quota[secret_id]++;
          vkprintf (1, "TLS connection rejected: secret [%s] quota exhausted from %s:%d\n", ext_secret_label[secret_id], show_remote_ip (C), c->remote_port);
          RETURN_TLS_ERROR(info);
        }

        if (ip_over_limit (secret_id, c->remote_ip, c->remote_ipv6)) {
          per_secret_rejected_ips[secret_id]++;
          vkprintf (1, "TLS connection rejected: secret [%s] IP limit %d from %s:%d\n", ext_secret_label[secret_id], ext_secret_max_ips[secret_id], show_remote_ip (C), c->remote_port);
          RETURN_TLS_ERROR(info);
        }

        unsigned char cipher_suite_id;
        if (tls_parse_client_hello_ciphers (client_hello, read_len, &cipher_suite_id) < 0) {
          vkprintf (1, "Can't find supported cipher suite\n");
          RETURN_TLS_ERROR(info);
        }

        if (rwm_skip_data (&c->in, len) != len) { fail_connection (C, -1); return 0; }
        c->flags |= C_IS_TLS;
        c->left_tls_packet_length = -1;

        int encrypted_size = get_domain_server_hello_encrypted_size (info);
        int response_size = 127 + 6 + 5 + encrypted_size;
        unsigned char *buffer = malloc (32 + response_size);
        assert (buffer != NULL);
        memcpy (buffer, client_random, 32);
        unsigned char *response_buffer = buffer + 32;
        memcpy (response_buffer, "\x16\x03\x03\x00\x7a\x02\x00\x00\x76\x03\x03", 11);
        memset (response_buffer + 11, '\0', 32);
        response_buffer[43] = '\x20';
        memcpy (response_buffer + 44, client_hello + 44, 32);
        memcpy (response_buffer + 76, "\x13\x01\x00\x00\x2e", 5);
        response_buffer[77] = cipher_suite_id;

        int pos = 81;
        int tls_server_extensions[3] = {0x33, 0x2b, -1};
        if (info->is_reversed_extension_order) {
          int t = tls_server_extensions[0];
          tls_server_extensions[0] = tls_server_extensions[1];
          tls_server_extensions[1] = t;
        }
        int i;
        for (i = 0; tls_server_extensions[i] != -1; i++) {
          if (tls_server_extensions[i] == 0x33) {
            assert (pos + 40 <= response_size);
            memcpy (response_buffer + pos, "\x00\x33\x00\x24\x00\x1d\x00\x20", 8);
            generate_public_key (response_buffer + pos + 8);
            pos += 40;
          } else if (tls_server_extensions[i] == 0x2b) {
            assert (pos + 5 <= response_size);
            memcpy (response_buffer + pos, "\x00\x2b\x00\x02\x03\x04", 6);
            pos += 6;
          } else {
            assert (0);
          }
        }
        assert (pos == 127);
        memcpy (response_buffer + 127, "\x14\x03\x03\x00\x01\x01\x17\x03\x03", 9);
        pos += 9;
        response_buffer[pos++] = encrypted_size / 256;
        response_buffer[pos++] = encrypted_size % 256;
        assert (pos + encrypted_size == response_size);
        RAND_bytes (response_buffer + pos, encrypted_size);

        unsigned char server_random[32];
        sha256_hmac (ext_secret[secret_id], 16, buffer, 32 + response_size, server_random);
        memcpy (response_buffer + 11, server_random, 32);

        /* Send ServerHello and CCS+AppData as two separate messages.
           With TCP_NODELAY, the first write goes out before the second
           is queued, producing separate TCP segments.  This defeats DPI
           that pattern-matches the full handshake in a single packet. */
        struct raw_message *m1 = calloc (sizeof (struct raw_message), 1);
        rwm_create (m1, response_buffer, 127);              /* ServerHello record */
        mpq_push_w (c->out_queue, m1, 0);
        job_signal (JOB_REF_CREATE_PASS (C), JS_RUN);

        struct raw_message *m2 = calloc (sizeof (struct raw_message), 1);
        rwm_create (m2, response_buffer + 127, response_size - 127); /* CCS + AppData */
        mpq_push_w (c->out_queue, m2, 0);
        job_signal (JOB_REF_CREATE_PASS (C), JS_RUN);

        free (buffer);
        return 11; // waiting for dummy ChangeCipherSpec and first packet
      }

      if (allow_only_tls && !(c->flags & C_IS_TLS)) {
        vkprintf (1, "Expected TLS-transport\n");
        RETURN_TLS_ERROR(default_domain_info);
      }

#if __ALLOW_UNOBFS__
      int tmp[2];
      if (rwm_fetch_lookup (&c->in, &tmp, 8) != 8) { fail_connection (C, -1); return 0; }
      if (!tmp[1] && !(c->flags & C_IS_TLS)) {
        D->crypto_flags |= RPCF_COMPACT_OFF;
        vkprintf (1, "Long type\n");
        return tcp_rpcs_parse_execute (C);
      }
#endif

      if (len < 64) {
        assert (!(c->flags & C_IS_TLS));
#if __ALLOW_UNOBFS__
        vkprintf (1, "random 64-byte header: first 0x%08x 0x%08x, need %d more bytes to distinguish\n", tmp[0], tmp[1], 64 - len);
#else
        vkprintf (1, "\"random\" 64-byte header: have %d bytes, need %d more bytes to distinguish\n", len, 64 - len);
#endif
        return 64 - len;
      }

      unsigned char random_header[64];
      if (rwm_fetch_lookup (&c->in, random_header, 64) != 64) { fail_connection (C, -1); return 0; }

      /* Save ciphertext — needed to re-init crypto with counter at byte 64 */
      unsigned char random_header_ct[64];
      memcpy (random_header_ct, random_header, 64);

      /* Compact non-FREE slots into a temporary array so the parser sees a
         contiguous list, then translate the matched index back to the real
         slot id.  Without this, FREE slots in the middle (caused by reload
         draining) would cause a wasted HMAC against zeroed key bytes. */
      unsigned char compact_secrets[EXT_SECRET_MAX_SLOTS][16];
      int compact_to_slot[EXT_SECRET_MAX_SLOTS];
      int compact_n = 0;
      for (int s = 0; s < ext_secret_cnt; s++) {
        if (ext_secret_state[s] == SLOT_FREE) { continue; }
        memcpy (compact_secrets[compact_n], ext_secret[s], 16);
        compact_to_slot[compact_n] = s;
        compact_n++;
      }

      struct obfs2_parse_result pr;
      int ok = (obfs2_parse_header (random_header,
                  compact_n > 0 ? (const unsigned char (*)[16])compact_secrets : NULL,
                  compact_n, ext_rand_pad_only, &pr) == 0);

      if (ok) {
          unsigned tag = pr.tag;
          int secret_id = compact_to_slot[pr.secret_id];

          if (tag != OBFS2_TAG_PAD && allow_only_tls) {
            vkprintf (1, "Expected random padding mode\n");
            RETURN_TLS_ERROR(default_domain_info);
          }

          /* Set up connection crypto and advance CTR counter past the 64-byte header */
          aes_crypto_ctr128_init (C, &pr.keys, sizeof (pr.keys));
          assert (c->crypto);
          struct aes_crypto *T = c->crypto;
          evp_crypt (T->read_aeskey, random_header_ct, random_header_ct, 64);

          if (rwm_skip_data (&c->in, 64) != 64) { fail_connection (C, -1); return 0; }
          rwm_union (&c->in_u, &c->in);
          rwm_init (&c->in, 0);
          D->in_packet_num = 0;
          switch (tag) {
            case OBFS2_TAG_MEDIUM:
              D->flags |= RPC_F_MEDIUM | RPC_F_EXTMODE2;
              break;
            case OBFS2_TAG_PAD:
              D->flags |= RPC_F_MEDIUM | RPC_F_EXTMODE2 | RPC_F_PAD;
              break;
            case OBFS2_TAG_COMPACT:
              D->flags |= RPC_F_COMPACT | RPC_F_EXTMODE2;
              break;
          }
          if (c->type->crypto_decrypt_input (C) < 0) {
            vkprintf (0, "ext-server: crypto_decrypt_input failed after handshake for connection %d\n", c->fd);
            fail_connection (C, -1);
            return 0;
          }

          D->extra_int4 = pr.dc;
          D->extra_int2 = secret_id + 1;
          D->extra_int3 = (int)tag;  /* client transport tag for direct mode */
          vkprintf (1, "tcp opportunistic encryption mode detected, tag = %08x, target=%d, secret [%s]\n", tag, pr.dc, ext_secret_label[secret_id]);
      }

      if (ok) {
        /* Per-secret checks (non-TLS; TLS checks happen during handshake above) */
        if (!(c->flags & C_IS_TLS)) {
          int _sid = D->extra_int2;
          if (_sid > 0 && _sid <= EXT_SECRET_MAX_SLOTS) {
            if (ext_secret_state[_sid - 1] == SLOT_DRAINING) {
              per_secret_rejected_draining[_sid - 1]++;
              vkprintf (1, "connection rejected: secret [%s] draining from %s:%d\n", ext_secret_label[_sid - 1], show_remote_ip (C), c->remote_port);
              D->extra_int2 = 0;
              fail_connection (C, -1);
              return 0;
            }
            if (secret_expired (_sid - 1)) {
              per_secret_rejected_expired[_sid - 1]++;
              vkprintf (1, "connection rejected: secret [%s] expired from %s:%d\n", ext_secret_label[_sid - 1], show_remote_ip (C), c->remote_port);
              D->extra_int2 = 0;
              fail_connection (C, -1);
              return 0;
            }
            if (secret_over_limit (_sid - 1)) {
              per_secret_connections_rejected[_sid - 1]++;
              vkprintf (1, "connection rejected: secret [%s] at limit %d from %s:%d\n", ext_secret_label[_sid - 1], ext_secret_limit[_sid - 1], show_remote_ip (C), c->remote_port);
              D->extra_int2 = 0;
              fail_connection (C, -1);
              return 0;
            }
            if (secret_over_quota (_sid - 1)) {
              per_secret_rejected_quota[_sid - 1]++;
              vkprintf (1, "connection rejected: secret [%s] quota exhausted from %s:%d\n", ext_secret_label[_sid - 1], show_remote_ip (C), c->remote_port);
              D->extra_int2 = 0;
              fail_connection (C, -1);
              return 0;
            }
            if (ip_over_limit (_sid - 1, c->remote_ip, c->remote_ipv6)) {
              per_secret_rejected_ips[_sid - 1]++;
              vkprintf (1, "connection rejected: secret [%s] IP limit %d from %s:%d\n", ext_secret_label[_sid - 1], ext_secret_max_ips[_sid - 1], show_remote_ip (C), c->remote_port);
              D->extra_int2 = 0;
              fail_connection (C, -1);
              return 0;
            }
          }
        }

        /* Per-secret connection counter: increment here for all modes.
           Decrement: mtproto_ext_rpc_close (non-direct / direct failure)
           or tcp_direct_close (direct success). */
        {
          int _sid = D->extra_int2;
          if (_sid > 0 && _sid <= EXT_SECRET_MAX_SLOTS) {
            per_secret_connections[_sid - 1]++;
            per_secret_connections_created[_sid - 1]++;
            ip_track_connect (_sid - 1, c->remote_ip, c->remote_ipv6);
            tcp_rpcs_account_connect (_sid - 1, c->remote_ip, c->remote_ipv6);
          }
        }

        /* Activate DRS for TLS connections */
        if (c->flags & C_IS_TLS) {
          static int drs_types_checked;
          if (!drs_types_checked) {
            assert (check_conn_functions (&ct_tcp_rpc_ext_server_drs, 0) >= 0);
            assert (check_conn_functions (&ct_direct_client_drs, 0) >= 0);
            drs_types_checked = 1;
          }
          c->type = &ct_tcp_rpc_ext_server_drs;
          struct drs_state *drs = DRS_STATE (C);
          drs->record_index = 0;
          drs->total_records = 0;
          drs->last_record_time = precise_now;
          drs->delay_pending = 0;
          vkprintf (1, "DRS activated for TLS connection\n");
        }
        if (direct_mode) {
          return direct_connect_to_dc (C, D->extra_int4);
        }
        continue;
      }

      /* TLS connections have extra_int2 set from the TLS handshake phase.
         Clear it to prevent spurious decrement in mtproto_ext_rpc_close
         since we never incremented the per-secret counter. */
      if (c->flags & C_IS_TLS) {
        D->extra_int2 = 0;
      }
      if (ext_secret_cnt > 0) {
        vkprintf (1, "invalid \"random\" 64-byte header, entering global skip mode\n");
        return ((int)0xF0000000u);
      }

#if __ALLOW_UNOBFS__
      vkprintf (1, "short type with 64-byte header: first 0x%08x 0x%08x\n", tmp[0], tmp[1]);
      D->flags |= RPC_F_COMPACT | RPC_F_EXTMODE1;
      D->in_packet_num = 0;

      assert (len >= 64);
      if (rwm_skip_data (&c->in, 64) != 64) { fail_connection (C, -1); return 0; }
      continue;
#else
      vkprintf (1, "invalid \"random\" 64-byte header, entering global skip mode\n");
      return ((int)0xF0000000u);
#endif
    }

    int packet_len_bytes = 4;
    if (D->flags & RPC_F_MEDIUM) {
      /* Transport error codes: DCs send a raw negative 4-byte int
         (e.g. -404, -429) in place of a normal packet length.
         Detect before QUICKACK masking destroys the sign. */
      if (packet_len < 0 && packet_len > -1000) {
        vkprintf (1, "transport error %d from %s:%d\n", packet_len, show_remote_ip (C), c->remote_port);
        transport_errors_received++;
        fail_connection (C, -1);
        return 0;
      }
      D->flags = (D->flags & ~RPC_F_QUICKACK) | (packet_len & RPC_F_QUICKACK);
      packet_len &= ~RPC_F_QUICKACK;
      if (D->flags & RPC_F_QUICKACK) {
        quickack_packets_received++;
      }
    } else {
      /* compact mode */
      if (packet_len & 0x80) {
        D->flags |= RPC_F_QUICKACK;
        packet_len &= ~0x80;
        quickack_packets_received++;
      } else {
        D->flags &= ~RPC_F_QUICKACK;
      }
      if ((packet_len & 0xff) == 0x7f) {
        packet_len = ((unsigned) packet_len >> 8);
        if (packet_len < 0x7f) {
          vkprintf (1, "error while parsing compact packet: got length %d in overlong encoding\n", packet_len);
          fail_connection (C, -1);
          return 0;
        }
      } else {
        packet_len &= 0x7f;
        packet_len_bytes = 1;
      }
      packet_len <<= 2;
    }

    if (packet_len <= 0 || (packet_len & 0xc0000000) || (!(D->flags & RPC_F_PAD) && (packet_len & 3))) {
      vkprintf (1, "error while parsing packet: bad packet length %d\n", packet_len);
      fail_connection (C, -1);
      return 0;
    }

    if ((packet_len > TCP_RPCS_FUNC(C)->max_packet_len && TCP_RPCS_FUNC(C)->max_packet_len > 0))  {
      vkprintf (1, "error while parsing packet: bad packet length %d\n", packet_len);
      fail_connection (C, -1);
      return 0;
    }

    if (len < packet_len + packet_len_bytes) {
      return packet_len + packet_len_bytes - len;
    }

    if (rwm_skip_data (&c->in, packet_len_bytes) != packet_len_bytes) { fail_connection (C, -1); return 0; }
    
    struct raw_message msg;
    int packet_type;

    rwm_split_head (&msg, &c->in, packet_len);
    if (D->flags & RPC_F_PAD) {
      rwm_trunc (&msg, packet_len & -4);
    }

    if (rwm_fetch_lookup (&msg, &packet_type, 4) != 4) { rwm_free (&msg); fail_connection (C, -1); return 0; }

    if (D->in_packet_num < 0) {
      assert (D->in_packet_num == -3);
      D->in_packet_num = 0;
    }

    if (verbosity > 2) {
      kprintf ("received packet from connection %d (length %d, num %d, type %08x)\n", c->fd, packet_len, D->in_packet_num, packet_type);
      rwm_dump (&msg);
    }

    int res = -1;

    /* main case */
    c->last_response_time = precise_now;
    if (packet_type == RPC_PING) {
      res = tcp_rpcs_default_execute (C, packet_type, &msg);
    } else {
      res = TCP_RPCS_FUNC(C)->execute (C, packet_type, &msg);
    }
    if (res <= 0) {
      rwm_free (&msg);
    }

    D->in_packet_num++;
  }
  return NEED_MORE_BYTES;
#undef RETURN_TLS_ERROR
}

/*
 *
 *                END (EXTERNAL RPC SERVER)
 *
 */
