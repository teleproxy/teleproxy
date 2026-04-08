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
 *      DIRECT-TO-DC RELAY
 *
 */

extern int direct_mode;
extern int ipv6_enabled;
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
extern long long transport_errors_received;

extern long long quickack_packets_received;

#define DIRECT_MAX_RETRIES 3
#define DIRECT_RETRY_BASE_SEC 0.2  /* 200ms, 400ms, 800ms */

/* ── SOCKS5 upstream proxy ────────────────────────────────────── */

enum {
  SOCKS5_NONE = 0,             /* no SOCKS5 or handshake complete */
  SOCKS5_GREETING_SENT,        /* awaiting method selection */
  SOCKS5_AUTH_SENT,            /* awaiting auth response */
  SOCKS5_CONNECT_SENT,         /* awaiting CONNECT response */
};

static struct {
  int enabled;
  int resolve_remote;          /* socks5h:// — send ATYP_DOMAIN in CONNECT */
  in_addr_t addr;
  int port;
  char user[256];
  char pass[256];
} socks5_config;

long long socks5_connects_attempted, socks5_connects_succeeded, socks5_connects_failed;

int socks5_is_enabled (void) {
  return socks5_config.enabled;
}

/* Parse socks5://[user:pass@]host:port or socks5h://... */
int socks5_set_proxy (const char *url) {
  memset (&socks5_config, 0, sizeof (socks5_config));

  const char *p = url;
  if (strncmp (p, "socks5h://", 10) == 0) {
    socks5_config.resolve_remote = 1;
    p += 10;
  } else if (strncmp (p, "socks5://", 9) == 0) {
    p += 9;
  } else {
    return -1;
  }

  /* Check for user:pass@ */
  const char *at = strchr (p, '@');
  if (at) {
    const char *colon = memchr (p, ':', at - p);
    if (!colon || colon == p) {
      return -1;  /* missing username */
    }
    int ulen = colon - p;
    int plen = at - colon - 1;
    if (ulen <= 0 || ulen > 255 || plen < 0 || plen > 255) {
      return -1;
    }
    memcpy (socks5_config.user, p, ulen);
    socks5_config.user[ulen] = '\0';
    if (plen > 0) {
      memcpy (socks5_config.pass, colon + 1, plen);
    }
    socks5_config.pass[plen] = '\0';
    p = at + 1;
  }

  /* Parse host:port */
  const char *colon = strrchr (p, ':');
  if (!colon || colon == p) {
    return -1;
  }
  int port = atoi (colon + 1);
  if (port <= 0 || port > 65535) {
    return -1;
  }

  char host[256];
  int hlen = colon - p;
  if (hlen <= 0 || hlen >= (int)sizeof (host)) {
    return -1;
  }
  memcpy (host, p, hlen);
  host[hlen] = '\0';

  struct addrinfo hints = {.ai_family = AF_INET, .ai_socktype = SOCK_STREAM};
  struct addrinfo *ai;
  if (getaddrinfo (host, NULL, &hints, &ai) != 0) {
    return -1;
  }
  socks5_config.addr = ((struct sockaddr_in *)ai->ai_addr)->sin_addr.s_addr;
  freeaddrinfo (ai);
  socks5_config.port = port;
  socks5_config.enabled = 1;

  vkprintf (0, "SOCKS5 upstream proxy: %s:%d%s%s\n", host, port,
            socks5_config.user[0] ? " (auth)" : "",
            socks5_config.resolve_remote ? " (resolve remote)" : "");
  return 0;
}

static int tcp_direct_client_parse_execute (connection_job_t C);
static int tcp_direct_dc_parse_execute (connection_job_t C);
static int tcp_direct_dc_connected (connection_job_t C);
static void tcp_direct_dc_send_obfs2_init (connection_job_t C);
static int socks5_handle_response (connection_job_t C);
static int tcp_direct_close (connection_job_t C, int who);
static int tcp_direct_client_alarm (connection_job_t C);

/* Client-side relay: keeps the client's AES-CTR crypto active */
conn_type_t ct_direct_client = {
  .magic = CONN_FUNC_MAGIC,
  .flags = C_RAWMSG,
  .title = "direct_client",
  .parse_execute = tcp_direct_client_parse_execute,
  .close = tcp_direct_close,
  .write_packet = tcp_proxy_pass_write_packet,
  .connected = server_noop,
  .alarm = tcp_direct_client_alarm,
  .crypto_init = aes_crypto_ctr128_init,
  .crypto_free = aes_crypto_free,
  .crypto_encrypt_output = cpu_tcp_aes_crypto_ctr128_encrypt_output,
  .crypto_decrypt_input = cpu_tcp_aes_crypto_ctr128_decrypt_input,
  .crypto_needed_output_bytes = cpu_tcp_aes_crypto_ctr128_needed_output_bytes,
};

/* DRS variant of client-side relay for TLS connections */
conn_type_t ct_direct_client_drs = {
  .magic = CONN_FUNC_MAGIC,
  .flags = C_RAWMSG,
  .title = "direct_client_drs",
  .parse_execute = tcp_direct_client_parse_execute,
  .close = tcp_direct_close,
  .write_packet = tcp_proxy_pass_write_packet,
  .connected = server_noop,
  .alarm = tcp_rpcs_ext_drs_alarm,
  .crypto_init = aes_crypto_ctr128_init,
  .crypto_free = aes_crypto_free,
  .crypto_encrypt_output = cpu_tcp_aes_crypto_ctr128_encrypt_output_drs,
  .crypto_decrypt_input = cpu_tcp_aes_crypto_ctr128_decrypt_input,
  .crypto_needed_output_bytes = cpu_tcp_aes_crypto_ctr128_needed_output_bytes,
};

/* DC-side alarm handler: handles rate limit resume for DC→client throttling. */
static int tcp_direct_dc_alarm (connection_job_t C) {
  rate_limit_resume (C);
  return 0;
}

/* DC-side relay: its own AES-CTR crypto for the proxy→DC obfuscated2 connection */
conn_type_t ct_direct_dc = {
  .magic = CONN_FUNC_MAGIC,
  .flags = C_RAWMSG,
  .title = "direct_dc",
  .init_accepted = server_failed,
  .parse_execute = tcp_direct_dc_parse_execute,
  .connected = tcp_direct_dc_connected,
  .close = tcp_direct_close,
  .write_packet = tcp_proxy_pass_write_packet,
  .alarm = tcp_direct_dc_alarm,
  .crypto_init = aes_crypto_ctr128_init,
  .crypto_free = aes_crypto_free,
  .crypto_encrypt_output = cpu_tcp_aes_crypto_ctr128_encrypt_output,
  .crypto_decrypt_input = cpu_tcp_aes_crypto_ctr128_decrypt_input,
  .crypto_needed_output_bytes = cpu_tcp_aes_crypto_ctr128_needed_output_bytes,
};

/* Relay bytes from one end to the other (client→DC or DC→client).
   Identical to tcp_proxy_pass_parse_execute but the paired connection
   has crypto enabled, so the engine will encrypt before flushing. */
static int tcp_direct_relay (connection_job_t C) {
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
  vkprintf (3, "direct relay %d bytes to %s:%d\n", r->total_bytes, show_remote_ip (E), e->remote_port);
  mpq_push_w (e->out_queue, PTR_MOVE(r), 0);
  job_signal (JOB_REF_PASS (E), JS_RUN);
  return 0;
}

static int tcp_direct_client_parse_execute (connection_job_t C) {
  struct connection_info *c = CONN_INFO(C);
  if (!c->extra) {
    /* No DC connection — either retry pending or permanent failure */
    if (TCP_RPC_DATA(C)->extra_int > 0) {
      return NEED_MORE_BYTES;  /* retry timer will fire */
    }
    fail_connection (C, -1);
    return 0;
  }
  /* Don't relay until the DC connection has sent its obfuscated2 init.
     The connected callback sets crypto when it's done and signals us. */
  struct connection_info *dc = CONN_INFO((connection_job_t) c->extra);
  if (!dc->crypto) {
    vkprintf (2, "direct client: DC not ready yet, deferring %d bytes\n", c->in.total_bytes);
    return NEED_MORE_BYTES;
  }
  int sid = TCP_RPC_DATA(C)->extra_int2;
  long long relay_bytes = c->in.total_bytes;
  if (sid > 0 && sid <= EXT_SECRET_MAX_SLOTS && relay_bytes > 0) {
    per_secret_bytes_received[sid - 1] += relay_bytes;
    tcp_rpcs_account_bytes (sid - 1, c->remote_ip, c->remote_ipv6, relay_bytes, 0);
    if (secret_over_quota (sid - 1)) {
      per_secret_rejected_quota[sid - 1]++;
      vkprintf (1, "direct client: secret #%d quota exhausted, closing from %s:%d\n", sid - 1, show_remote_ip (C), c->remote_port);
      fail_connection (C, -1);
      return 0;
    }
  }
  int res = tcp_direct_relay (C);
  if (sid > 0 && sid <= EXT_SECRET_MAX_SLOTS && relay_bytes > 0) {
    rate_limit_after_relay (C, sid - 1, relay_bytes, c->remote_ip, c->remote_ipv6);
  }
  return res;
}

static int tcp_direct_dc_parse_execute (connection_job_t C) {
  struct connection_info *c = CONN_INFO(C);
  struct tcp_rpc_data *D = TCP_RPC_DATA(C);

  /* SOCKS5 handshake in progress — handle before any relay logic */
  if (D->extra_int > 0) {
    int res = socks5_handle_response (C);
    if (res > 0) {
      return NEED_MORE_BYTES;
    }
    if (res < 0) {
      socks5_connects_failed++;
      fail_connection (C, -1);
      return 0;
    }
    /* res == 0: handshake complete, send obfs2 init */
    tcp_direct_dc_send_obfs2_init (C);
    return 0;
  }

  /* Detect transport error codes from DC: a single 4-byte negative int
     (e.g. -404 "auth key not found", -429 "flood", -444 "invalid DC") */
  if (c->in.total_bytes == 4) {
    int code;
    if (rwm_fetch_lookup (&c->in, &code, 4) == 4 && code < 0 && code > -1000) {
      int target_dc = TCP_RPC_DATA(C)->extra_int4;
      kprintf ("direct mode: DC %d sent transport error %d\n", target_dc, code);
      transport_errors_received++;
    }
  }

  int rl_sid = 0;
  long long relay_bytes = 0;
  unsigned rl_ip = 0;
  const unsigned char *rl_ipv6 = NULL;
  if (c->extra && c->in.total_bytes > 0) {
    connection_job_t client = (connection_job_t) c->extra;
    int sid = TCP_RPC_DATA(client)->extra_int2;
    if (sid > 0 && sid <= EXT_SECRET_MAX_SLOTS) {
      relay_bytes = c->in.total_bytes;
      per_secret_bytes_sent[sid - 1] += relay_bytes;
      tcp_rpcs_account_bytes (sid - 1, CONN_INFO(client)->remote_ip,
                              CONN_INFO(client)->remote_ipv6, relay_bytes, 1);
      if (secret_over_quota (sid - 1)) {
        per_secret_rejected_quota[sid - 1]++;
        vkprintf (1, "direct DC: secret #%d quota exhausted, closing\n", sid - 1);
        fail_connection (C, -1);
        return 0;
      }
      rl_sid = sid;
      rl_ip = CONN_INFO(client)->remote_ip;
      rl_ipv6 = CONN_INFO(client)->remote_ipv6;
    }
  }
  int res = tcp_direct_relay (C);
  if (rl_sid > 0 && relay_bytes > 0) {
    rate_limit_after_relay (C, rl_sid - 1, relay_bytes, rl_ip, rl_ipv6);
  }
  return res;
}

static int direct_schedule_retry (connection_job_t C, int target_dc, int attempt);

static int tcp_direct_close (connection_job_t C, int who) {
  struct connection_info *c = CONN_INFO(C);
  int is_client = (c->type == &ct_direct_client || c->type == &ct_direct_client_drs);
  int is_dc = (c->type == &ct_direct_dc);
  int target_dc = TCP_RPC_DATA(C)->extra_int4;
  double duration = precise_now - c->query_start_time;

  vkprintf (1, "direct: closing %s connection #%d (DC %d) after %.1fs, %s:%d -> %s:%d, who=%d\n",
            is_client ? "client" : "DC", c->fd, target_dc, duration,
            show_our_ip (C), c->our_port, show_remote_ip (C), c->remote_port, who);

  /* DC connection failed before handshake completed — eligible for retry */
  if (is_dc && c->extra && !c->crypto) {
    connection_job_t client = (connection_job_t) c->extra;
    int attempt = TCP_RPC_DATA(client)->extra_int;
    if (attempt < DIRECT_MAX_RETRIES) {
      vkprintf (1, "direct mode: DC %d connection failed (async), scheduling retry %d/%d\n",
                target_dc, attempt + 1, DIRECT_MAX_RETRIES);
      /* Detach client from this dying DC connection */
      CONN_INFO(client)->extra = NULL;
      job_t E = PTR_MOVE (c->extra);
      direct_dc_connections_failed++;
      direct_schedule_retry (client, target_dc, attempt);
      job_decref (JOB_REF_PASS (E));
      return cpu_server_close_connection (C, who);
    }
  }

  if (is_client && direct_dc_connections_active > 0) {
    direct_dc_connections_active--;
    int sid = TCP_RPC_DATA(C)->extra_int2;
    if (sid > 0 && sid <= EXT_SECRET_MAX_SLOTS) {
      per_secret_connections[sid - 1]--;
      ip_track_disconnect_impl (sid - 1, c->remote_ip, c->remote_ipv6);
      tcp_rpcs_account_disconnect (sid - 1, c->remote_ip, c->remote_ipv6);
    }
  }
  if (is_dc && who != 0) {
    /* DC side closed unexpectedly (not by us tearing down the pair) */
    direct_dc_connections_dc_closed++;
  }
  if (c->extra) {
    job_t E = PTR_MOVE (c->extra);
    fail_connection (E, -23);
    job_decref (JOB_REF_PASS (E));
  }
  return cpu_server_close_connection (C, who);
}

/* Alarm handler for non-DRS direct client connections (obfs2).
   Handles rate limit resume and DC retry. */
static int tcp_direct_client_alarm (connection_job_t C) {
  if (rate_limit_resume (C)) { return 0; }
  struct connection_info *c = CONN_INFO(C);
  if (!c->extra && TCP_RPC_DATA(C)->extra_int > 0) {
    direct_retry_dc_connection (C);
    return 0;
  }
  return 0;
}

/* Send obfuscated2 init payload to a DC and set up AES-CTR crypto.
   Called either directly from tcp_direct_dc_connected() (no SOCKS5)
   or after the SOCKS5 handshake completes (SOCKS5 mode). */
static void tcp_direct_dc_send_obfs2_init (connection_job_t C) {
  struct connection_info *c = CONN_INFO(C);
  struct tcp_rpc_data *D = TCP_RPC_DATA(C);
  int target_dc = D->extra_int4;

  vkprintf (1, "direct DC: sending obfuscated2 init (fd=%d, DC=%d)\n", c->fd, target_dc);

  /* Generate 64-byte obfuscated2 init payload */
  unsigned char init[64];
  do {
    RAND_bytes (init, 64);
  } while (
    init[0] == 0xef ||
    *(unsigned *)init == 0x44414548 ||   /* "HEAD" */
    *(unsigned *)init == 0x54534f50 ||   /* "POST" */
    *(unsigned *)init == 0x20544547 ||   /* "GET " */
    *(unsigned *)init == 0x4954504f ||   /* "OPTI" */
    *(unsigned *)init == 0xeeeeeeee ||
    *(unsigned *)init == 0xdddddddd ||
    *(unsigned *)init == 0xefefefef ||
    *(unsigned *)(init + 4) == 0x00000000
  );

  /* Set protocol tag matching the client's transport and target DC */
  unsigned client_tag = (unsigned)D->extra_int3;
  if (!client_tag) {
    client_tag = 0xeeeeeeee;  /* fallback: intermediate */
  }
  *(unsigned *)(init + 56) = client_tag;
  *(short *)(init + 60) = (short)target_dc;

  /* Derive AES keys -- NO secret mixing (DCs don't know proxy secret).
     Proxy is acting as client:
       write (encrypt outgoing) = forward direction from init
       read (decrypt incoming)  = reversed direction from init */
  struct aes_key_data key_data;
  memcpy (key_data.write_key, init + 8, 32);
  memcpy (key_data.write_iv, init + 40, 16);
  int i;
  for (i = 0; i < 32; i++) {
    key_data.read_key[i] = init[55 - i];
  }
  for (i = 0; i < 16; i++) {
    key_data.read_iv[i] = init[23 - i];
  }

  /* Encrypt all 64 bytes with write key to produce the encrypted init.
     Only bytes 56-63 get replaced in the sent payload (obfuscated2 protocol). */
  unsigned char encrypted[64];
  EVP_CIPHER_CTX *tmp_ctx = EVP_CIPHER_CTX_new ();
  assert (tmp_ctx);
  assert (EVP_EncryptInit_ex (tmp_ctx, EVP_aes_256_ctr (), NULL, key_data.write_key, key_data.write_iv));
  int outlen = 0;
  assert (EVP_EncryptUpdate (tmp_ctx, encrypted, &outlen, init, 64));
  assert (outlen == 64);

  /* Replace bytes 56-63 with their encrypted version */
  memcpy (init + 56, encrypted + 56, 8);

  /* Send the 64-byte init as raw bytes, bypassing the crypto layer.
     We write to out_p (post-crypto buffer) because c->crypto will be set
     below — anything in c->out would be AES-encrypted on flush. */
  if (rwm_push_data (&c->out_p, init, 64) != 64) { fail_connection (C, -1); return; }

  /* Now set up the AES-CTR crypto context for ongoing communication.
     The write counter must start at position 64 (we already "used" 64 bytes
     for the init). We achieve this by using the temp context's state. */
  struct aes_crypto *T = NULL;
  assert (!posix_memalign ((void **)&T, 16, sizeof (struct aes_crypto)));
  T->write_aeskey = tmp_ctx;   /* counter already at 64 */
  T->read_aeskey = evp_cipher_ctx_init (EVP_aes_256_ctr (), key_data.read_key, key_data.read_iv, 1);
  c->crypto = T;

  /* Flush deferred client data: the client's parse_execute returned
     NEED_MORE_BYTES while waiting for this DC init, which set skip_bytes.
     Reset it so the reader re-enters parse_execute on the next signal. */
  if (c->extra) {
    CONN_INFO((connection_job_t) c->extra)->skip_bytes = 0;
    job_signal (JOB_REF_CREATE_PASS (c->extra), JS_RUN);
  }
}

/* ── SOCKS5 handshake helpers ───────────────────────────────── */

/* SOCKS5 data goes to c->out (pre-crypto buffer).  Without crypto,
   the writer flushes c->out directly.  c->out_p is only flushed when
   crypto is set — which happens after the SOCKS5 handshake. */

static void socks5_send_greeting (connection_job_t C) {
  struct connection_info *c = CONN_INFO(C);
  if (socks5_config.user[0]) {
    unsigned char buf[] = {0x05, 0x02, 0x00, 0x02};  /* no-auth + user/pass */
    rwm_push_data (&c->out, buf, 4);
  } else {
    unsigned char buf[] = {0x05, 0x01, 0x00};  /* no-auth only */
    rwm_push_data (&c->out, buf, 3);
  }
}

static void socks5_send_auth (connection_job_t C) {
  struct connection_info *c = CONN_INFO(C);
  int ulen = strlen (socks5_config.user);
  int plen = strlen (socks5_config.pass);
  unsigned char buf[515];  /* 1 + 1 + 255 + 1 + 255 */
  buf[0] = 0x01;           /* auth version */
  buf[1] = (unsigned char) ulen;
  memcpy (buf + 2, socks5_config.user, ulen);
  buf[2 + ulen] = (unsigned char) plen;
  memcpy (buf + 3 + ulen, socks5_config.pass, plen);
  rwm_push_data (&c->out, buf, 3 + ulen + plen);
}

static void socks5_send_connect (connection_job_t C) {
  struct connection_info *c = CONN_INFO(C);
  struct tcp_rpc_data *D = TCP_RPC_DATA(C);
  int dc_id = D->extra_int4;
  int addr_idx = D->extra_int2;

  const struct dc_entry *dc = direct_dc_lookup (dc_id);
  assert (dc && addr_idx < dc->addr_count);
  const struct dc_addr *addr = &dc->addrs[addr_idx];

  static const unsigned char zero_ipv6[16] = {};
  int has_ipv6 = memcmp (addr->ipv6, zero_ipv6, 16) != 0;
  int use_ipv6 = ipv6_enabled && has_ipv6;

  unsigned char buf[22];  /* max: 4 header + 16 ipv6 + 2 port */
  buf[0] = 0x05;          /* SOCKS version */
  buf[1] = 0x01;          /* CONNECT */
  buf[2] = 0x00;          /* reserved */
  int len;
  if (use_ipv6) {
    buf[3] = 0x04;         /* ATYP: IPv6 */
    memcpy (buf + 4, addr->ipv6, 16);
    buf[20] = (addr->port >> 8) & 0xff;
    buf[21] = addr->port & 0xff;
    len = 22;
  } else {
    buf[3] = 0x01;         /* ATYP: IPv4 */
    memcpy (buf + 4, &addr->ipv4, 4);
    buf[8] = (addr->port >> 8) & 0xff;
    buf[9] = addr->port & 0xff;
    len = 10;
  }
  rwm_push_data (&c->out, buf, len);
}

/* Process SOCKS5 handshake responses.  Returns:
   1  = handshake still in progress (NEED_MORE_BYTES)
   0  = handshake complete — caller should proceed with obfs2 init
   -1 = error — connection should be failed */
static int socks5_handle_response (connection_job_t C) {
  struct connection_info *c = CONN_INFO(C);
  struct tcp_rpc_data *D = TCP_RPC_DATA(C);
  int state = D->extra_int;

  if (state == SOCKS5_GREETING_SENT) {
    if (c->in.total_bytes < 2) {
      return 1;
    }
    unsigned char resp[2];
    if (rwm_fetch_data (&c->in, resp, 2) != 2) { fail_connection (C, -1); return 0; }
    if (resp[0] != 0x05) {
      vkprintf (0, "socks5: bad version %d in greeting response\n", resp[0]);
      return -1;
    }
    if (resp[1] == 0x00) {
      /* No auth — send CONNECT directly */
      socks5_send_connect (C);
      D->extra_int = SOCKS5_CONNECT_SENT;
      return 1;
    } else if (resp[1] == 0x02) {
      /* Username/password auth */
      if (!socks5_config.user[0]) {
        vkprintf (0, "socks5: server requires auth but no credentials configured\n");
        return -1;
      }
      socks5_send_auth (C);
      D->extra_int = SOCKS5_AUTH_SENT;
      return 1;
    } else {
      vkprintf (0, "socks5: no acceptable auth method (server chose 0x%02x)\n", resp[1]);
      return -1;
    }
  }

  if (state == SOCKS5_AUTH_SENT) {
    if (c->in.total_bytes < 2) {
      return 1;
    }
    unsigned char resp[2];
    if (rwm_fetch_data (&c->in, resp, 2) != 2) { fail_connection (C, -1); return 0; }
    if (resp[1] != 0x00) {
      vkprintf (0, "socks5: auth failed (status 0x%02x)\n", resp[1]);
      return -1;
    }
    socks5_send_connect (C);
    D->extra_int = SOCKS5_CONNECT_SENT;
    return 1;
  }

  if (state == SOCKS5_CONNECT_SENT) {
    /* Minimum CONNECT response: ver(1) + rep(1) + rsv(1) + atyp(1) + addr + port(2).
       Peek at first 5 bytes to determine total length. */
    if (c->in.total_bytes < 5) {
      return 1;
    }
    unsigned char peek[5];
    if (rwm_fetch_lookup (&c->in, peek, 5) != 5) { fail_connection (C, -1); return 0; }

    int addr_len;
    if (peek[3] == 0x01) {
      addr_len = 4;   /* IPv4 */
    } else if (peek[3] == 0x04) {
      addr_len = 16;  /* IPv6 */
    } else if (peek[3] == 0x03) {
      addr_len = 1 + peek[4];  /* length byte + domain */
    } else {
      vkprintf (0, "socks5: unknown address type 0x%02x in CONNECT response\n", peek[3]);
      return -1;
    }

    int total = 4 + addr_len + 2;
    if (c->in.total_bytes < total) {
      return 1;
    }

    /* Consume the full response */
    unsigned char discard[280];
    if (rwm_fetch_data (&c->in, discard, total) != total) { fail_connection (C, -1); return 0; }

    if (peek[1] != 0x00) {
      vkprintf (0, "socks5: CONNECT failed (reply 0x%02x)\n", peek[1]);
      return -1;
    }

    D->extra_int = SOCKS5_NONE;
    socks5_connects_succeeded++;
    vkprintf (1, "socks5: CONNECT succeeded (fd=%d)\n", c->fd);
    return 0;  /* handshake complete */
  }

  return -1;  /* unknown state */
}

/* Called when the outbound TCP connection is established.
   If SOCKS5 is enabled, starts the SOCKS5 handshake; otherwise
   sends the obfuscated2 init directly. */
static int tcp_direct_dc_connected (connection_job_t C) {
  struct connection_info *c = CONN_INFO(C);
  struct tcp_rpc_data *D = TCP_RPC_DATA(C);

  if (socks5_config.enabled) {
    vkprintf (1, "direct DC: connected to SOCKS5 proxy (fd=%d), starting handshake for DC=%d\n", c->fd, D->extra_int4);
    socks5_connects_attempted++;
    socks5_send_greeting (C);
    D->extra_int = SOCKS5_GREETING_SENT;
    return 0;
  }

  tcp_direct_dc_send_obfs2_init (C);
  return 0;
}

/* Try to establish a DC connection using one of the entry's addresses.
   Returns the connection job on success, or NULL if all addresses failed. */
static job_t direct_try_dc_addrs (connection_job_t C, const struct dc_entry *dc, int target_dc) {
  static const unsigned char zero_ipv6[16] = {};

  for (int i = 0; i < dc->addr_count; i++) {
    const struct dc_addr *addr = &dc->addrs[i];
    int has_ipv6 = memcmp (addr->ipv6, zero_ipv6, 16) != 0;
    int use_ipv6 = ipv6_enabled && has_ipv6;

    if (use_ipv6) {
      char addr_buf[INET6_ADDRSTRLEN];
      inet_ntop (AF_INET6, addr->ipv6, addr_buf, sizeof (addr_buf));
      vkprintf (1, "direct mode: trying DC %d addr %d/%d ([%s]:%d)%s\n",
                target_dc, i + 1, dc->addr_count, addr_buf, addr->port,
                socks5_config.enabled ? " via SOCKS5" : " via IPv6");
    } else if (addr->ipv4) {
      vkprintf (1, "direct mode: trying DC %d addr %d/%d (%s:%d)%s\n",
                target_dc, i + 1, dc->addr_count,
                inet_ntoa (*(struct in_addr *)&addr->ipv4), addr->port,
                socks5_config.enabled ? " via SOCKS5" : "");
    } else {
      continue;  /* no usable address */
    }

    int cfd;
    if (socks5_config.enabled) {
      /* Connect to SOCKS5 proxy instead of DC directly */
      cfd = client_socket (socks5_config.addr, socks5_config.port, 0);
    } else if (use_ipv6) {
      cfd = client_socket_ipv6 (addr->ipv6, addr->port, SM_IPV6);
    } else {
      cfd = client_socket (addr->ipv4, addr->port, 0);
    }
    if (cfd < 0) {
      vkprintf (1, "direct mode: DC %d addr %d/%d connect failed: %m\n",
                target_dc, i + 1, dc->addr_count);
      continue;
    }

    job_t EJ;
    if (socks5_config.enabled) {
      /* alloc_new_connection records the SOCKS5 server as the remote addr,
         which is fine — the DC addr is looked up from extra_int4 + extra_int2 */
      EJ = alloc_new_connection (cfd, NULL, NULL, ct_outbound, &ct_direct_dc, NULL,
                                  ntohl (socks5_config.addr), NULL, socks5_config.port);
    } else if (use_ipv6) {
      EJ = alloc_new_connection (cfd, NULL, NULL, ct_outbound, &ct_direct_dc, NULL,
                                  0, (unsigned char *)addr->ipv6, addr->port);
    } else {
      EJ = alloc_new_connection (cfd, NULL, NULL, ct_outbound, &ct_direct_dc, NULL,
                                  ntohl (addr->ipv4), NULL, addr->port);
    }
    if (!EJ) {
      vkprintf (1, "direct mode: DC %d addr %d/%d alloc_new_connection failed\n",
                target_dc, i + 1, dc->addr_count);
      continue;
    }
    if (socks5_config.enabled) {
      /* Store DC address index for the SOCKS5 CONNECT request */
      TCP_RPC_DATA(EJ)->extra_int2 = i;
    }
    return EJ;
  }
  return NULL;
}

static int direct_schedule_retry (connection_job_t C, int target_dc, int attempt) {
  if (attempt >= DIRECT_MAX_RETRIES) {
    kprintf ("direct mode: all %d retries exhausted for DC %d\n", DIRECT_MAX_RETRIES, target_dc);
    direct_dc_connections_failed++;
    fail_connection (C, -27);
    return 0;
  }
  TCP_RPC_DATA(C)->extra_int = attempt + 1;
  double backoff = DIRECT_RETRY_BASE_SEC * (1 << attempt);
  job_timer_insert (C, precise_now + backoff);
  direct_dc_retries++;
  vkprintf (1, "direct mode: DC %d connect failed, retry %d/%d in %.0fms\n",
            target_dc, attempt + 1, DIRECT_MAX_RETRIES, backoff * 1000.0);
  return 0;
}

void direct_retry_dc_connection (connection_job_t C) {
  struct connection_info *c = CONN_INFO(C);
  int target_dc = TCP_RPC_DATA(C)->extra_int4;
  int attempt = TCP_RPC_DATA(C)->extra_int;

  const struct dc_entry *dc = direct_dc_lookup (target_dc);
  if (!dc) {
    kprintf ("direct mode: DC %d not found during retry\n", target_dc);
    direct_dc_connections_failed++;
    TCP_RPC_DATA(C)->extra_int = 0;
    fail_connection (C, -1);
    return;
  }

  job_t EJ = direct_try_dc_addrs (C, dc, target_dc);
  if (EJ) {
    int outbound_dc = (target_dc < 0 ? -1 : 1) * dc->dc_id;
    TCP_RPC_DATA(EJ)->extra_int4 = outbound_dc;
    TCP_RPC_DATA(EJ)->extra_int3 = TCP_RPC_DATA(C)->extra_int3;
    c->extra = job_incref (EJ);
    CONN_INFO(EJ)->extra = job_incref (C);
    TCP_RPC_DATA(C)->extra_int = 0;  /* clear retry state */
    direct_dc_connections_created++;
    direct_dc_connections_active++;
    vkprintf (1, "direct mode: retry %d succeeded for DC %d\n", attempt, target_dc);
    assert (CONN_INFO(EJ)->io_conn);
    unlock_job (JOB_REF_PASS (EJ));
    return;
  }

  /* All addresses failed again */
  direct_dc_connections_failed++;
  direct_schedule_retry (C, target_dc, attempt);
}

/* Route a client connection directly to a Telegram DC.
   Called after the obfuscated2 handshake is parsed and the target DC is known. */
int direct_connect_to_dc (connection_job_t C, int target_dc) {
  struct connection_info *c = CONN_INFO(C);

  const struct dc_entry *dc = direct_dc_lookup (target_dc);
  if (!dc) {
    kprintf ("direct mode: unknown DC %d, closing connection\n", target_dc);
    direct_dc_connections_failed++;
    fail_connection (C, -1);
    return 0;
  }

  static int direct_types_checked;
  if (!direct_types_checked) {
    assert (check_conn_functions (&ct_direct_dc, 0) >= 0);
    assert (check_conn_functions (&ct_direct_client, 0) >= 0);
    assert (check_conn_functions (&ct_direct_client_drs, 0) >= 0);
    direct_types_checked = 1;
  }

  /* Switch client type early so alarm handler is available for retries */
  if (c->flags & C_IS_TLS) {
    c->type = &ct_direct_client_drs;
    struct drs_state *drs = DRS_STATE (C);
    drs->record_index = 0;
    drs->total_records = 0;
    drs->last_record_time = precise_now;
    drs->delay_pending = 0;
  } else {
    c->type = &ct_direct_client;
  }

  job_t EJ = direct_try_dc_addrs (C, dc, target_dc);
  if (!EJ) {
    /* All addresses failed synchronously — schedule retry */
    direct_dc_connections_failed++;
    return direct_schedule_retry (C, target_dc, 0);
  }

  /* Store resolved DC for the outbound init header.
     Preserve the media flag (negative sign) from the original target.
     CDN/test offsets are already stripped by direct_dc_lookup(). */
  int outbound_dc = (target_dc < 0 ? -1 : 1) * dc->dc_id;
  TCP_RPC_DATA(EJ)->extra_int4 = outbound_dc;
  TCP_RPC_DATA(EJ)->extra_int3 = TCP_RPC_DATA(C)->extra_int3;  /* client transport tag */

  c->extra = job_incref (EJ);

  /* Link DC connection back to client */
  CONN_INFO(EJ)->extra = job_incref (C);

  direct_dc_connections_created++;
  direct_dc_connections_active++;

  /* Per-secret increment already done in tcp_rpcs_compact_parse_execute
     before direct_connect_to_dc is called. */

  assert (CONN_INFO(EJ)->io_conn);
  unlock_job (JOB_REF_PASS (EJ));

  return 0;
}

/*
 *
 *      END DIRECT-TO-DC RELAY
 *
 */
