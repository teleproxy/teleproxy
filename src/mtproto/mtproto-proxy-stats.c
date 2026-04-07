/*
    This file is part of Teleproxy.

    Teleproxy is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    This program is released under the GPL with the additional exemption
    that compiling, linking, and/or using OpenSSL is allowed.
    You are free to remove this exemption from derived works.
*/

#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "common/common-stats.h"
#include "net/net-events.h"
#include "net/net-connections.h"
#include "net/net-http-server.h"
#include "net/net-msg-buffers.h"
#include "net/net-crypto-aes.h"
#include "net/net-crypto-dh.h"
#include "net/net-tcp-rpc-ext-server.h"
#include "net/net-proxy-protocol.h"
#include "net/net-tcp-drs.h"
#include "precise-time.h"
#include "server-functions.h"
#include "mtproto-config.h"
#include "mtproto-dc-probes.h"
#include "mtproto-proxy-stats.h"
#include "qrcode/qrcodegen.h"
#include "common/toml-config.h"

#ifndef COMMIT
#define COMMIT "unknown"
#endif

#ifndef VERSION
#define VERSION "unknown"
#endif

#define VERSION_STR	"teleproxy-" VERSION

/* globals defined in mtproto-proxy.c */
extern int proxy_mode;
extern int http_port[];
extern struct toml_config toml_cfg;
extern long long ext_connections, ext_connections_created;
extern long long per_secret_connections[], per_secret_connections_created[];
extern long long per_secret_connections_rejected[];
extern long long per_secret_bytes_received[], per_secret_bytes_sent[];
extern long long per_secret_rejected_quota[];
extern long long per_secret_rejected_ips[];
extern long long per_secret_rejected_expired[];
extern long long per_secret_unique_ips[];
extern long long per_secret_rate_limited[];
extern long long per_secret_rejected_draining[];
extern long long per_secret_drain_forced[];
extern long long connections_failed_lru, connections_failed_flood;

struct worker_stats *WStats, SumStats;
int worker_id, workers, slave_mode, parent_pid;
int pids[MAX_WORKERS];

/* Cross-worker merge buffer for per-IP top-N metrics (issue #46).
   Populated by compute_stats_sum() in multi-worker mode and by
   prepare_master_top_ips() directly in single-process mode.  Same IP from
   different workers (e.g. after reconnect) is summed.  Size cap is soft —
   if more distinct IPs arrive than fit, the smallest bytes_total entry is
   evicted to make room. */
#define MASTER_TOP_IPS_CAP 128
static struct worker_top_ip MasterTopIps[16][MASTER_TOP_IPS_CAP];
static int MasterTopIpsCount[16];

static void master_top_ips_reset (void) {
  memset (MasterTopIps, 0, sizeof (MasterTopIps));
  memset (MasterTopIpsCount, 0, sizeof (MasterTopIpsCount));
}

static int worker_top_ip_match (const struct worker_top_ip *a,
                                const struct worker_top_ip *b) {
  if (a->ip != 0 || b->ip != 0) {
    return a->ip == b->ip;
  }
  return memcmp (a->ipv6, b->ipv6, 16) == 0;
}

static void merge_one_top_ip (int sid, const struct worker_top_ip *src) {
  /* Merge by (ip, ipv6) key into MasterTopIps[sid].  Sum on collision. */
  int *count = &MasterTopIpsCount[sid];
  for (int i = 0; i < *count; i++) {
    if (worker_top_ip_match (&MasterTopIps[sid][i], src)) {
      MasterTopIps[sid][i].connections += src->connections;
      MasterTopIps[sid][i].bytes_in    += src->bytes_in;
      MasterTopIps[sid][i].bytes_out   += src->bytes_out;
      return;
    }
  }
  if (*count < MASTER_TOP_IPS_CAP) {
    MasterTopIps[sid][*count] = *src;
    (*count)++;
    return;
  }
  /* Buffer full: evict the smallest-volume entry if it's smaller than src. */
  int victim = -1;
  long long victim_total = src->bytes_in + src->bytes_out;
  for (int i = 0; i < MASTER_TOP_IPS_CAP; i++) {
    long long t = MasterTopIps[sid][i].bytes_in + MasterTopIps[sid][i].bytes_out;
    if (t < victim_total) {
      victim = i;
      victim_total = t;
    }
  }
  if (victim >= 0) {
    MasterTopIps[sid][victim] = *src;
  }
}

static void merge_worker_top_ips (const struct worker_stats *W) {
  for (int sid = 0; sid < 16; sid++) {
    int n = W->top_ips_count[sid];
    if (n > WORKER_TOP_IPS_MAX) { n = WORKER_TOP_IPS_MAX; }
    for (int i = 0; i < n; i++) {
      merge_one_top_ip (sid, &W->top_ips[sid][i]);
    }
  }
}

long long get_queries;
extern long long http_queries;
int pending_http_queries;

long long active_rpcs, active_rpcs_created;
long long rpc_dropped_running, rpc_dropped_answers;
long long tot_forwarded_queries, expired_forwarded_queries, dropped_queries;
long long tot_forwarded_responses, dropped_responses;
long long tot_forwarded_simple_acks, dropped_simple_acks;
long long mtproto_proxy_errors;
long long direct_dc_connections_created, direct_dc_connections_active;
long long direct_dc_connections_failed, direct_dc_connections_dc_closed;
long long direct_dc_retries;
long long transport_errors_received;
long long quickack_packets_received;

char proxy_tag[16];
int proxy_tag_set;

static void update_local_stats_copy (struct worker_stats *S) {
  S->cnt++;
  __sync_synchronize();
  S->updated_at = now;
#define UPD(x)	S->x = x;
  fetch_tot_dh_rounds_stat (S->tot_dh_rounds);
  fetch_connections_stat (&S->conn);
  fetch_aes_crypto_stat (&S->allocated_aes_crypto, &S->allocated_aes_crypto_temp);
  fetch_buffers_stat (&S->bufs);

  UPD (ev_heap_size);

  UPD (get_queries);
  UPD (http_connections);
  UPD (pending_http_queries);
  UPD (active_rpcs);
  UPD (active_rpcs_created);
  UPD (rpc_dropped_running);
  UPD (rpc_dropped_answers);
  UPD (tot_forwarded_queries);
  UPD (expired_forwarded_queries);
  UPD (dropped_queries);
  UPD (tot_forwarded_responses);
  UPD (dropped_responses);
  UPD (tot_forwarded_simple_acks);
  UPD (dropped_simple_acks);
  UPD (mtproto_proxy_errors);
  UPD (direct_dc_connections_created);
  UPD (direct_dc_connections_active);
  UPD (direct_dc_connections_failed);
  UPD (direct_dc_connections_dc_closed);
  UPD (direct_dc_retries);
  UPD (socks5_connects_attempted);
  UPD (socks5_connects_succeeded);
  UPD (socks5_connects_failed);
  UPD (connections_failed_lru);
  UPD (connections_failed_flood);
  UPD (ext_connections);
  UPD (ext_connections_created);
  UPD (http_queries);
  UPD (http_bad_headers);
  UPD (drs_delays_applied);
  UPD (drs_delays_skipped);
  UPD (transport_errors_received);
  UPD (quickack_packets_received);
  { int _i; for (_i = 0; _i < EXT_SECRET_MAX_SLOTS; _i++) {
    UPD (per_secret_connections[_i]);
    UPD (per_secret_connections_created[_i]);
    UPD (per_secret_connections_rejected[_i]);
    UPD (per_secret_bytes_received[_i]);
    UPD (per_secret_bytes_sent[_i]);
    UPD (per_secret_rejected_quota[_i]);
    UPD (per_secret_rejected_ips[_i]);
    UPD (per_secret_rejected_expired[_i]);
    UPD (per_secret_unique_ips[_i]);
    UPD (per_secret_rate_limited[_i]);
    UPD (per_secret_rejected_draining[_i]);
    UPD (per_secret_drain_forced[_i]);
    tcp_rpcs_snapshot_top_ips (_i, S->top_ips[_i], &S->top_ips_count[_i], WORKER_TOP_IPS_MAX);
  }}
#undef UPD
  __sync_synchronize();
  S->cnt++;
  __sync_synchronize();
}

static inline void add_stats (struct worker_stats *W) {
#define UPD(x)	SumStats.x += W->x;
  UPD (tot_dh_rounds[0]);
  UPD (tot_dh_rounds[1]);
  UPD (tot_dh_rounds[2]);

  UPD (conn.active_connections);
  UPD (conn.active_dh_connections);
  UPD (conn.outbound_connections);
  UPD (conn.active_outbound_connections);
  UPD (conn.ready_outbound_connections);
  UPD (conn.active_special_connections);
  UPD (conn.max_special_connections);
  UPD (conn.allocated_connections);
  UPD (conn.allocated_outbound_connections);
  UPD (conn.allocated_inbound_connections);
  UPD (conn.allocated_socket_connections);
  UPD (conn.allocated_targets);
  UPD (conn.ready_targets);
  UPD (conn.active_targets);
  UPD (conn.inactive_targets);
  UPD (conn.tcp_readv_calls);
  UPD (conn.tcp_readv_intr);
  UPD (conn.tcp_readv_bytes);
  UPD (conn.tcp_writev_calls);
  UPD (conn.tcp_writev_intr);
  UPD (conn.tcp_writev_bytes);
  UPD (conn.accept_calls_failed);
  UPD (conn.accept_nonblock_set_failed);
  UPD (conn.accept_rate_limit_failed);
  UPD (conn.accept_init_accepted_failed);
  UPD (conn.accept_ip_acl_rejected);

  UPD (allocated_aes_crypto);
  UPD (allocated_aes_crypto_temp);

  UPD (bufs.total_used_buffers_size);
  UPD (bufs.allocated_buffer_bytes);
  UPD (bufs.total_used_buffers);
  UPD (bufs.allocated_buffer_chunks);
  UPD (bufs.max_allocated_buffer_chunks);
  UPD (bufs.max_allocated_buffer_bytes);
  UPD (bufs.max_buffer_chunks);
  UPD (bufs.buffer_chunk_alloc_ops);

  UPD (ev_heap_size);

  UPD (get_queries);
  UPD (http_connections);
  UPD (pending_http_queries);
  UPD (active_rpcs);
  UPD (active_rpcs_created);
  UPD (rpc_dropped_running);
  UPD (rpc_dropped_answers);
  UPD (tot_forwarded_queries);
  UPD (expired_forwarded_queries);
  UPD (dropped_queries);
  UPD (tot_forwarded_responses);
  UPD (dropped_responses);
  UPD (tot_forwarded_simple_acks);
  UPD (dropped_simple_acks);
  UPD (mtproto_proxy_errors);
  UPD (direct_dc_connections_created);
  UPD (direct_dc_connections_active);
  UPD (direct_dc_connections_failed);
  UPD (direct_dc_connections_dc_closed);
  UPD (direct_dc_retries);
  UPD (socks5_connects_attempted);
  UPD (socks5_connects_succeeded);
  UPD (socks5_connects_failed);
  UPD (connections_failed_lru);
  UPD (connections_failed_flood);
  UPD (ext_connections);
  UPD (ext_connections_created);
  UPD (http_queries);
  UPD (http_bad_headers);
  UPD (drs_delays_applied);
  UPD (drs_delays_skipped);
  UPD (transport_errors_received);
  UPD (quickack_packets_received);
  { int _i; for (_i = 0; _i < EXT_SECRET_MAX_SLOTS; _i++) {
    UPD (per_secret_connections[_i]);
    UPD (per_secret_connections_created[_i]);
    UPD (per_secret_connections_rejected[_i]);
    UPD (per_secret_bytes_received[_i]);
    UPD (per_secret_bytes_sent[_i]);
    UPD (per_secret_rejected_quota[_i]);
    UPD (per_secret_rejected_ips[_i]);
    UPD (per_secret_rejected_expired[_i]);
    UPD (per_secret_unique_ips[_i]);
    UPD (per_secret_rate_limited[_i]);
    UPD (per_secret_rejected_draining[_i]);
    UPD (per_secret_drain_forced[_i]);
  }}
#undef UPD
}

void update_local_stats (void) {
  if (!slave_mode) {
    return;
  }
  update_local_stats_copy (WStats + worker_id * 2);
  update_local_stats_copy (WStats + worker_id * 2 + 1);
}

void compute_stats_sum (void) {
  if (!workers) {
    return;
  }
  memset (&SumStats, 0, sizeof (SumStats));
  master_top_ips_reset ();
  int i;
  for (i = 0; i < workers; i++) {
    static struct worker_stats W;
    struct worker_stats *F;
    int s_cnt;
    do {
      F = WStats + i * 2;
      do {
	barrier ();
        s_cnt = (++F)->cnt;
        if (!(s_cnt & 1)) {
          break;
        }
        s_cnt = (--F)->cnt;
      } while (s_cnt & 1);
      barrier ();
      memcpy (&W, F, sizeof (W));
      barrier ();
    } while (s_cnt != F->cnt);
    add_stats (&W);
    merge_worker_top_ips (&W);
  }
}

/* Snapshot the worker-local ip_volume table directly into MasterTopIps.
   Used in single-process mode where compute_stats_sum is a no-op. */
static void prepare_master_top_ips_local (void) {
  master_top_ips_reset ();
  if (tcp_rpcs_get_top_ips_per_secret () <= 0) {
    return;
  }
  static struct worker_top_ip buf[WORKER_TOP_IPS_MAX];
  for (int sid = 0; sid < 16; sid++) {
    int count = 0;
    tcp_rpcs_snapshot_top_ips (sid, buf, &count, WORKER_TOP_IPS_MAX);
    for (int i = 0; i < count; i++) {
      merge_one_top_ip (sid, &buf[i]);
    }
  }
}

/* Comparator for sorting MasterTopIps[sid] by bytes_total descending. */
static int top_ip_cmp_desc (const void *a, const void *b) {
  const struct worker_top_ip *x = a;
  const struct worker_top_ip *y = b;
  long long tx = x->bytes_in + x->bytes_out;
  long long ty = y->bytes_in + y->bytes_out;
  if (tx > ty) { return -1; }
  if (tx < ty) { return  1; }
  return 0;
}

/*
 *
 *		SERVER
 *
 */


void mtfront_prepare_stats (stats_buffer_t *sb) {
  struct connections_stat conn;
  struct buffers_stat bufs;
  long long tot_dh_rounds[3];
  int allocated_aes_crypto, allocated_aes_crypto_temp;
  int uptime = now - start_time;
  compute_stats_sum ();
  fetch_connections_stat (&conn);
  fetch_buffers_stat (&bufs);
  fetch_tot_dh_rounds_stat (tot_dh_rounds);
  fetch_aes_crypto_stat (&allocated_aes_crypto, &allocated_aes_crypto_temp);

  sb_prepare (sb);
  sb_memory (sb, AM_GET_MEMORY_USAGE_SELF);

#define S(x)	((x)+(SumStats.x))
#define S1(x)	(SumStats.x)
#define SW(x)	(workers ? S1(x) : S(x))
  sb_printf (sb,
	     "config_filename\t%s\n"
	     "config_loaded_at\t%d\n"
	     "config_size\t%d\n"
	     "config_md5\t%s\n"
	     "config_auth_clusters\t%d\n"
	     "workers\t%d\n"
	     "queries_get\t%lld\n"
	     "qps_get\t%.3f\n"
	     "tot_forwarded_queries\t%lld\n"
	     "expired_forwarded_queries\t%lld\n"
	     "dropped_queries\t%lld\n"
	     "tot_forwarded_responses\t%lld\n"
	     "dropped_responses\t%lld\n"
	     "tot_forwarded_simple_acks\t%lld\n"
	     "dropped_simple_acks\t%lld\n"
	     "active_rpcs_created\t%lld\n"
	     "active_rpcs\t%lld\n"
	     "rpc_dropped_answers\t%lld\n"
	     "rpc_dropped_running\t%lld\n"
	     "window_clamp\t%d\n"
	     "total_ready_targets\t%d\n"
	     "total_allocated_targets\t%d\n"
	     "total_declared_targets\t%d\n"
	     "total_inactive_targets\t%d\n"
	     "total_connections\t%d\n"
	     "total_encrypted_connections\t%d\n"
	     "total_allocated_connections\t%d\n"
	     "total_allocated_outbound_connections\t%d\n"
	     "total_allocated_inbound_connections\t%d\n"
	     "total_allocated_socket_connections\t%d\n"
	     "total_dh_connections\t%d\n"
	     "total_dh_rounds\t%lld %lld %lld\n"
	     "total_special_connections\t%d\n"
	     "total_max_special_connections\t%d\n"
	     "total_accept_connections_failed\t%lld %lld %lld %lld %lld\n"
	     "accept_ip_acl_rejected\t%lld\n"
	     "ext_connections\t%lld\n"
	     "ext_connections_created\t%lld\n"
	     "total_active_network_events\t%d\n"
	     "total_network_buffers_used_size\t%lld\n"
	     "total_network_buffers_allocated_bytes\t%lld\n"
	     "total_network_buffers_used\t%d\n"
	     "total_network_buffer_chunks_allocated\t%d\n"
	     "total_network_buffer_chunks_allocated_max\t%d\n"
	     "mtproto_proxy_errors\t%lld\n"
	     "connections_failed_lru\t%lld\n"
	     "connections_failed_flood\t%lld\n"
	     "http_connections\t%d\n"
	     "pending_http_queries\t%d\n"
	     "http_queries\t%lld\n"
	     "http_bad_headers\t%lld\n"
	     "http_qps\t%.6f\n"
	     "proxy_mode\t%d\n"
	     "proxy_tag_set\t%d\n"
	     "direct_mode\t%d\n"
	     "direct_dc_connections_created\t%lld\n"
	     "direct_dc_connections_active\t%lld\n"
	     "direct_dc_connections_failed\t%lld\n"
	     "direct_dc_connections_dc_closed\t%lld\n"
	     "direct_dc_retries\t%lld\n"
	     "socks5_enabled\t%d\n"
	     "socks5_connects_attempted\t%lld\n"
	     "socks5_connects_succeeded\t%lld\n"
	     "socks5_connects_failed\t%lld\n"
	     "proxy_protocol_enabled\t%d\n"
	     "proxy_protocol_connections\t%lld\n"
	     "proxy_protocol_errors\t%lld\n"
	     "drs_delays_enabled\t%d\n"
	     "drs_delays_applied\t%lld\n"
	     "drs_delays_skipped\t%lld\n"
	     "drs_weibull_k\t%.6f\n"
	     "drs_weibull_lambda\t%.6f\n"
	     "transport_errors_received\t%lld\n"
	     "quickack_packets_received\t%lld\n"
	     "version\t" VERSION_STR " compiled at " __DATE__ " " __TIME__ " by gcc " __VERSION__ " "
#ifdef __LP64__
	     "64-bit"
#else
	     "32-bit"
#endif
	     " after commit " COMMIT "\n",
	     config_filename ? config_filename : "(none)",
	     CurConf->config_loaded_at,
	     CurConf->config_bytes,
	     CurConf->config_md5_hex ? CurConf->config_md5_hex : "",
	     CurConf->auth_stats.tot_clusters,
	     workers,
	     S(get_queries),
	     safe_div (S(get_queries), uptime),
	     S(tot_forwarded_queries),
	     S(expired_forwarded_queries),
	     S(dropped_queries),
	     S(tot_forwarded_responses),
	     S(dropped_responses),
	     S(tot_forwarded_simple_acks),
	     S(dropped_simple_acks),
	     S(active_rpcs_created),
	     S(active_rpcs),
	     S(rpc_dropped_answers),
	     S(rpc_dropped_running),
	     window_clamp,
	     SW(conn.ready_targets),
	     SW(conn.allocated_targets),
	     SW(conn.active_targets),
	     SW(conn.inactive_targets),
	     S(conn.active_connections),
	     S(allocated_aes_crypto),
	     S(conn.allocated_connections),
	     S(conn.allocated_outbound_connections),
	     S(conn.allocated_inbound_connections),
	     S(conn.allocated_socket_connections),
	     S(conn.active_dh_connections),
	     S(tot_dh_rounds[0]),
	     S(tot_dh_rounds[1]),
	     S(tot_dh_rounds[2]),
	     SW(conn.active_special_connections),
	     SW(conn.max_special_connections),
	     S(conn.accept_init_accepted_failed),
	     S(conn.accept_calls_failed),
	     S(conn.accept_connection_limit_failed),
	     S(conn.accept_rate_limit_failed),
	     S(conn.accept_nonblock_set_failed),
	     S(conn.accept_ip_acl_rejected),
	     S(ext_connections),
	     S(ext_connections_created),
	     S(ev_heap_size),
	     SW(bufs.total_used_buffers_size),
	     SW(bufs.allocated_buffer_bytes),
	     SW(bufs.total_used_buffers),
	     SW(bufs.allocated_buffer_chunks),
	     SW(bufs.max_allocated_buffer_chunks),
	     S(mtproto_proxy_errors),
	     S(connections_failed_lru),
	     S(connections_failed_flood),
	     S(http_connections),
	     S(pending_http_queries),
	     S(http_queries),
	     S(http_bad_headers),
	     safe_div (S(http_queries), uptime),
	     proxy_mode,
	     proxy_tag_set,
	     direct_mode,
	     S(direct_dc_connections_created),
	     S(direct_dc_connections_active),
	     S(direct_dc_connections_failed),
	     S(direct_dc_connections_dc_closed),
	     S(direct_dc_retries),
	     socks5_is_enabled (),
	     S(socks5_connects_attempted),
	     S(socks5_connects_succeeded),
	     S(socks5_connects_failed),
	     proxy_protocol_enabled,
	     proxy_protocol_connections_total,
	     proxy_protocol_errors_total,
	     drs_delays_enabled,
	     S(drs_delays_applied),
	     S(drs_delays_skipped),
	     drs_delay_get_k (),
	     drs_delay_get_lambda (),
	     S(transport_errors_received),
	     S(quickack_packets_received)
  );

  { int _sc = tcp_rpcs_get_ext_secret_count();
    int _i;
    for (_i = 0; _i < _sc; _i++) {
      int _state = tcp_rpcs_get_ext_secret_state (_i);
      if (_state == SLOT_FREE) { continue; }
      const char *_lbl = tcp_rpcs_get_ext_secret_label (_i);
      sb_printf (sb,
	       "secret_%s_connections\t%lld\n"
	       "secret_%s_connections_created\t%lld\n"
	       "secret_%s_rejected\t%lld\n"
	       "secret_%s_bytes_total\t%lld\n"
	       "secret_%s_unique_ips\t%lld\n"
	       "secret_%s_rejected_quota\t%lld\n"
	       "secret_%s_rejected_ips\t%lld\n"
	       "secret_%s_rejected_expired\t%lld\n",
	       _lbl, S(per_secret_connections[_i]),
	       _lbl, S(per_secret_connections_created[_i]),
	       _lbl, S(per_secret_connections_rejected[_i]),
	       _lbl, S(per_secret_bytes_received[_i]) + S(per_secret_bytes_sent[_i]),
	       _lbl, S(per_secret_unique_ips[_i]),
	       _lbl, S(per_secret_rejected_quota[_i]),
	       _lbl, S(per_secret_rejected_ips[_i]),
	       _lbl, S(per_secret_rejected_expired[_i]));
      int _lim = tcp_rpcs_get_ext_secret_limit (_i);
      if (_lim > 0) {
        sb_printf (sb, "secret_%s_limit\t%d\n", _lbl, _lim);
      }
      long long _quota = tcp_rpcs_get_ext_secret_quota (_i);
      if (_quota > 0) {
        sb_printf (sb, "secret_%s_quota\t%lld\n", _lbl, _quota);
      }
      int _mips = tcp_rpcs_get_ext_secret_max_ips (_i);
      if (_mips > 0) {
        sb_printf (sb, "secret_%s_max_ips\t%d\n", _lbl, _mips);
      }
      int64_t _exp = tcp_rpcs_get_ext_secret_expires (_i);
      if (_exp > 0) {
        sb_printf (sb, "secret_%s_expires\t%lld\n", _lbl, (long long) _exp);
      }
      long long _rl = tcp_rpcs_get_ext_secret_rate_limit (_i);
      if (_rl > 0) {
        sb_printf (sb, "secret_%s_rate_limit\t%lld\n", _lbl, _rl);
      }
      sb_printf (sb, "secret_%s_rate_limited\t%lld\n", _lbl, S(per_secret_rate_limited[_i]));
      sb_printf (sb, "secret_%s_draining\t%d\n", _lbl, _state == SLOT_DRAINING ? 1 : 0);
      sb_printf (sb, "secret_%s_rejected_draining\t%lld\n", _lbl, S(per_secret_rejected_draining[_i]));
      sb_printf (sb, "secret_%s_drain_forced\t%lld\n", _lbl, S(per_secret_drain_forced[_i]));
      if (_state == SLOT_DRAINING) {
        double _started = tcp_rpcs_get_ext_secret_drain_started (_i);
        if (_started > 0) {
          sb_printf (sb, "secret_%s_drain_age_seconds\t%.0f\n", _lbl, precise_now - _started);
        }
      }
    }
  }
  dc_probes_write_text_stats (sb);
#undef S
#undef S1
#undef SW
}

void mtfront_prepare_prometheus_stats (stats_buffer_t *sb) {
  struct connections_stat conn;
  struct buffers_stat bufs;
  int uptime = now - start_time;
  compute_stats_sum ();
  if (!workers) {
    prepare_master_top_ips_local ();
  }
  fetch_connections_stat (&conn);
  fetch_buffers_stat (&bufs);

#define S(x)	((x)+(SumStats.x))
#define S1(x)	(SumStats.x)
#define SW(x)	(workers ? S1(x) : S(x))

  /* counters */
  sb_printf (sb,
	     "# HELP teleproxy_queries_total Total client queries received.\n"
	     "# TYPE teleproxy_queries_total counter\n"
	     "teleproxy_queries_total %lld\n"
	     "# HELP teleproxy_forwarded_queries_total Total queries forwarded to Telegram DCs.\n"
	     "# TYPE teleproxy_forwarded_queries_total counter\n"
	     "teleproxy_forwarded_queries_total %lld\n"
	     "# HELP teleproxy_expired_queries_total Queries that expired waiting for a response.\n"
	     "# TYPE teleproxy_expired_queries_total counter\n"
	     "teleproxy_expired_queries_total %lld\n"
	     "# HELP teleproxy_dropped_queries_total Queries dropped with nowhere to forward.\n"
	     "# TYPE teleproxy_dropped_queries_total counter\n"
	     "teleproxy_dropped_queries_total %lld\n"
	     "# HELP teleproxy_forwarded_responses_total Total responses forwarded back to clients.\n"
	     "# TYPE teleproxy_forwarded_responses_total counter\n"
	     "teleproxy_forwarded_responses_total %lld\n"
	     "# HELP teleproxy_dropped_responses_total Responses that failed to forward.\n"
	     "# TYPE teleproxy_dropped_responses_total counter\n"
	     "teleproxy_dropped_responses_total %lld\n"
	     "# HELP teleproxy_forwarded_acks_total Total simple ACKs forwarded.\n"
	     "# TYPE teleproxy_forwarded_acks_total counter\n"
	     "teleproxy_forwarded_acks_total %lld\n"
	     "# HELP teleproxy_dropped_acks_total Simple ACKs that failed to forward.\n"
	     "# TYPE teleproxy_dropped_acks_total counter\n"
	     "teleproxy_dropped_acks_total %lld\n"
	     "# HELP teleproxy_rpcs_created_total Total RPC connections created.\n"
	     "# TYPE teleproxy_rpcs_created_total counter\n"
	     "teleproxy_rpcs_created_total %lld\n"
	     "# HELP teleproxy_rpc_dropped_answers_total RPC answers dropped.\n"
	     "# TYPE teleproxy_rpc_dropped_answers_total counter\n"
	     "teleproxy_rpc_dropped_answers_total %lld\n"
	     "# HELP teleproxy_rpc_dropped_running_total RPC connections dropped while running.\n"
	     "# TYPE teleproxy_rpc_dropped_running_total counter\n"
	     "teleproxy_rpc_dropped_running_total %lld\n"
	     "# HELP teleproxy_ext_connections_created_total Total external connections created.\n"
	     "# TYPE teleproxy_ext_connections_created_total counter\n"
	     "teleproxy_ext_connections_created_total %lld\n"
	     "# HELP teleproxy_proxy_errors_total Internal proxy errors.\n"
	     "# TYPE teleproxy_proxy_errors_total counter\n"
	     "teleproxy_proxy_errors_total %lld\n"
	     "# HELP teleproxy_connections_failed_lru_total Connections dropped by LRU eviction.\n"
	     "# TYPE teleproxy_connections_failed_lru_total counter\n"
	     "teleproxy_connections_failed_lru_total %lld\n"
	     "# HELP teleproxy_connections_failed_flood_total Connections dropped due to flood detection.\n"
	     "# TYPE teleproxy_connections_failed_flood_total counter\n"
	     "teleproxy_connections_failed_flood_total %lld\n"
	     "# HELP teleproxy_http_queries_total Total HTTP queries processed.\n"
	     "# TYPE teleproxy_http_queries_total counter\n"
	     "teleproxy_http_queries_total %lld\n"
	     "# HELP teleproxy_http_bad_headers_total HTTP requests with malformed headers.\n"
	     "# TYPE teleproxy_http_bad_headers_total counter\n"
	     "teleproxy_http_bad_headers_total %lld\n"
	     "# HELP teleproxy_ip_acl_rejected_total Connections rejected by IP ACL.\n"
	     "# TYPE teleproxy_ip_acl_rejected_total counter\n"
	     "teleproxy_ip_acl_rejected_total %lld\n"
	     "# HELP teleproxy_direct_dc_connections_created_total Direct DC connections created.\n"
	     "# TYPE teleproxy_direct_dc_connections_created_total counter\n"
	     "teleproxy_direct_dc_connections_created_total %lld\n"
	     "# HELP teleproxy_direct_dc_connections_failed_total Direct DC connections that failed to establish.\n"
	     "# TYPE teleproxy_direct_dc_connections_failed_total counter\n"
	     "teleproxy_direct_dc_connections_failed_total %lld\n"
	     "# HELP teleproxy_direct_dc_connections_dc_closed_total Direct DC connections closed by the DC side.\n"
	     "# TYPE teleproxy_direct_dc_connections_dc_closed_total counter\n"
	     "teleproxy_direct_dc_connections_dc_closed_total %lld\n"
	     "# HELP teleproxy_direct_dc_retries_total DC connection retry attempts.\n"
	     "# TYPE teleproxy_direct_dc_retries_total counter\n"
	     "teleproxy_direct_dc_retries_total %lld\n"
	     "# HELP teleproxy_socks5_connects_attempted_total SOCKS5 upstream connect attempts.\n"
	     "# TYPE teleproxy_socks5_connects_attempted_total counter\n"
	     "teleproxy_socks5_connects_attempted_total %lld\n"
	     "# HELP teleproxy_socks5_connects_succeeded_total SOCKS5 upstream connects succeeded.\n"
	     "# TYPE teleproxy_socks5_connects_succeeded_total counter\n"
	     "teleproxy_socks5_connects_succeeded_total %lld\n"
	     "# HELP teleproxy_socks5_connects_failed_total SOCKS5 upstream connects failed.\n"
	     "# TYPE teleproxy_socks5_connects_failed_total counter\n"
	     "teleproxy_socks5_connects_failed_total %lld\n"
	     "# HELP teleproxy_proxy_protocol_enabled Whether PROXY protocol is enabled.\n"
	     "# TYPE teleproxy_proxy_protocol_enabled gauge\n"
	     "teleproxy_proxy_protocol_enabled %d\n"
	     "# HELP teleproxy_proxy_protocol_connections_total Connections with PROXY protocol header parsed.\n"
	     "# TYPE teleproxy_proxy_protocol_connections_total counter\n"
	     "teleproxy_proxy_protocol_connections_total %lld\n"
	     "# HELP teleproxy_proxy_protocol_errors_total PROXY protocol parse failures.\n"
	     "# TYPE teleproxy_proxy_protocol_errors_total counter\n"
	     "teleproxy_proxy_protocol_errors_total %lld\n"
	     "# HELP teleproxy_drs_delays_total Total inter-record delays injected.\n"
	     "# TYPE teleproxy_drs_delays_total counter\n"
	     "teleproxy_drs_delays_total %lld\n"
	     "# HELP teleproxy_drs_delays_skipped_total Inter-record delays skipped during bulk transfers.\n"
	     "# TYPE teleproxy_drs_delays_skipped_total counter\n"
	     "teleproxy_drs_delays_skipped_total %lld\n"
	     "# HELP teleproxy_drs_weibull_k Current Weibull shape parameter.\n"
	     "# TYPE teleproxy_drs_weibull_k gauge\n"
	     "teleproxy_drs_weibull_k %.6f\n"
	     "# HELP teleproxy_drs_weibull_lambda Current Weibull scale parameter (ms).\n"
	     "# TYPE teleproxy_drs_weibull_lambda gauge\n"
	     "teleproxy_drs_weibull_lambda %.6f\n"
	     "# HELP teleproxy_transport_errors_total Transport-level error codes received from DCs.\n"
	     "# TYPE teleproxy_transport_errors_total counter\n"
	     "teleproxy_transport_errors_total %lld\n"
	     "# HELP teleproxy_quickack_packets_total Packets received with quick ACK flag set.\n"
	     "# TYPE teleproxy_quickack_packets_total counter\n"
	     "teleproxy_quickack_packets_total %lld\n",
	     S(get_queries),
	     S(tot_forwarded_queries),
	     S(expired_forwarded_queries),
	     S(dropped_queries),
	     S(tot_forwarded_responses),
	     S(dropped_responses),
	     S(tot_forwarded_simple_acks),
	     S(dropped_simple_acks),
	     S(active_rpcs_created),
	     S(rpc_dropped_answers),
	     S(rpc_dropped_running),
	     S(ext_connections_created),
	     S(mtproto_proxy_errors),
	     S(connections_failed_lru),
	     S(connections_failed_flood),
	     S(http_queries),
	     S(http_bad_headers),
	     S(conn.accept_ip_acl_rejected),
	     S(direct_dc_connections_created),
	     S(direct_dc_connections_failed),
	     S(direct_dc_connections_dc_closed),
	     S(direct_dc_retries),
	     S(socks5_connects_attempted),
	     S(socks5_connects_succeeded),
	     S(socks5_connects_failed),
	     proxy_protocol_enabled,
	     proxy_protocol_connections_total,
	     proxy_protocol_errors_total,
	     S(drs_delays_applied),
	     S(drs_delays_skipped),
	     drs_delay_get_k (),
	     drs_delay_get_lambda (),
	     S(transport_errors_received),
	     S(quickack_packets_received)
  );

  /* gauges */
  sb_printf (sb,
	     "# HELP teleproxy_uptime_seconds Time since proxy started in seconds.\n"
	     "# TYPE teleproxy_uptime_seconds gauge\n"
	     "teleproxy_uptime_seconds %d\n"
	     "# HELP teleproxy_workers Number of worker processes.\n"
	     "# TYPE teleproxy_workers gauge\n"
	     "teleproxy_workers %d\n"
	     "# HELP teleproxy_active_rpcs Currently active RPC connections.\n"
	     "# TYPE teleproxy_active_rpcs gauge\n"
	     "teleproxy_active_rpcs %lld\n"
	     "# HELP teleproxy_ext_connections Current external client connections.\n"
	     "# TYPE teleproxy_ext_connections gauge\n"
	     "teleproxy_ext_connections %lld\n"
	     "# HELP teleproxy_http_connections Current HTTP connections.\n"
	     "# TYPE teleproxy_http_connections gauge\n"
	     "teleproxy_http_connections %d\n"
	     "# HELP teleproxy_pending_http_queries HTTP queries awaiting processing.\n"
	     "# TYPE teleproxy_pending_http_queries gauge\n"
	     "teleproxy_pending_http_queries %d\n"
	     "# HELP teleproxy_active_connections Total active network connections.\n"
	     "# TYPE teleproxy_active_connections gauge\n"
	     "teleproxy_active_connections %d\n"
	     "# HELP teleproxy_allocated_connections Total allocated connection slots.\n"
	     "# TYPE teleproxy_allocated_connections gauge\n"
	     "teleproxy_allocated_connections %d\n"
	     "# HELP teleproxy_active_dh_connections Connections in DH key exchange.\n"
	     "# TYPE teleproxy_active_dh_connections gauge\n"
	     "teleproxy_active_dh_connections %d\n"
	     "# HELP teleproxy_ready_targets Backend DC targets ready for connections.\n"
	     "# TYPE teleproxy_ready_targets gauge\n"
	     "teleproxy_ready_targets %d\n"
	     "# HELP teleproxy_network_buffers_used_bytes Network buffer memory in use.\n"
	     "# TYPE teleproxy_network_buffers_used_bytes gauge\n"
	     "teleproxy_network_buffers_used_bytes %lld\n"
	     "# HELP teleproxy_network_buffers_allocated_bytes Network buffer memory allocated.\n"
	     "# TYPE teleproxy_network_buffers_allocated_bytes gauge\n"
	     "teleproxy_network_buffers_allocated_bytes %lld\n"
	     "# HELP teleproxy_direct_dc_connections_active Active direct DC connections.\n"
	     "# TYPE teleproxy_direct_dc_connections_active gauge\n"
	     "teleproxy_direct_dc_connections_active %lld\n",
	     uptime,
	     workers,
	     S(active_rpcs),
	     S(ext_connections),
	     S(http_connections),
	     S(pending_http_queries),
	     S(conn.active_connections),
	     S(conn.allocated_connections),
	     S(conn.active_dh_connections),
	     SW(conn.ready_targets),
	     SW(bufs.total_used_buffers_size),
	     SW(bufs.allocated_buffer_bytes),
	     S(direct_dc_connections_active)
  );

  { int _sc = tcp_rpcs_get_ext_secret_count();
    if (_sc > 0) {
      int _i;
      sb_printf (sb,
	       "# HELP teleproxy_secret_connections Current connections per configured secret.\n"
	       "# TYPE teleproxy_secret_connections gauge\n");
      for (_i = 0; _i < _sc; _i++) { if (tcp_rpcs_get_ext_secret_state (_i) == SLOT_FREE) { continue; }
        sb_printf (sb, "teleproxy_secret_connections{secret=\"%s\"} %lld\n",
	         tcp_rpcs_get_ext_secret_label (_i), S(per_secret_connections[_i]));
      }
      sb_printf (sb,
	       "# HELP teleproxy_secret_connections_created_total Total connections per configured secret.\n"
	       "# TYPE teleproxy_secret_connections_created_total counter\n");
      for (_i = 0; _i < _sc; _i++) { if (tcp_rpcs_get_ext_secret_state (_i) == SLOT_FREE) { continue; }
        sb_printf (sb, "teleproxy_secret_connections_created_total{secret=\"%s\"} %lld\n",
	         tcp_rpcs_get_ext_secret_label (_i), S(per_secret_connections_created[_i]));
      }
      sb_printf (sb,
	       "# HELP teleproxy_secret_connection_limit Configured connection limit per secret (0=unlimited).\n"
	       "# TYPE teleproxy_secret_connection_limit gauge\n");
      for (_i = 0; _i < _sc; _i++) { if (tcp_rpcs_get_ext_secret_state (_i) == SLOT_FREE) { continue; }
        sb_printf (sb, "teleproxy_secret_connection_limit{secret=\"%s\"} %d\n",
	         tcp_rpcs_get_ext_secret_label (_i), tcp_rpcs_get_ext_secret_limit (_i));
      }
      sb_printf (sb,
	       "# HELP teleproxy_secret_connections_rejected_total Connections rejected due to per-secret limit.\n"
	       "# TYPE teleproxy_secret_connections_rejected_total counter\n");
      for (_i = 0; _i < _sc; _i++) { if (tcp_rpcs_get_ext_secret_state (_i) == SLOT_FREE) { continue; }
        sb_printf (sb, "teleproxy_secret_connections_rejected_total{secret=\"%s\"} %lld\n",
	         tcp_rpcs_get_ext_secret_label (_i), S(per_secret_connections_rejected[_i]));
      }
      sb_printf (sb,
	       "# HELP teleproxy_secret_bytes_received_total Bytes received from clients per secret.\n"
	       "# TYPE teleproxy_secret_bytes_received_total counter\n");
      for (_i = 0; _i < _sc; _i++) { if (tcp_rpcs_get_ext_secret_state (_i) == SLOT_FREE) { continue; }
        sb_printf (sb, "teleproxy_secret_bytes_received_total{secret=\"%s\"} %lld\n",
	         tcp_rpcs_get_ext_secret_label (_i), S(per_secret_bytes_received[_i]));
      }
      sb_printf (sb,
	       "# HELP teleproxy_secret_bytes_sent_total Bytes sent to clients per secret.\n"
	       "# TYPE teleproxy_secret_bytes_sent_total counter\n");
      for (_i = 0; _i < _sc; _i++) { if (tcp_rpcs_get_ext_secret_state (_i) == SLOT_FREE) { continue; }
        sb_printf (sb, "teleproxy_secret_bytes_sent_total{secret=\"%s\"} %lld\n",
	         tcp_rpcs_get_ext_secret_label (_i), S(per_secret_bytes_sent[_i]));
      }
      sb_printf (sb,
	       "# HELP teleproxy_secret_bytes_total Total bytes transferred (rx+tx) per secret.\n"
	       "# TYPE teleproxy_secret_bytes_total counter\n");
      for (_i = 0; _i < _sc; _i++) { if (tcp_rpcs_get_ext_secret_state (_i) == SLOT_FREE) { continue; }
        sb_printf (sb, "teleproxy_secret_bytes_total{secret=\"%s\"} %lld\n",
	         tcp_rpcs_get_ext_secret_label (_i), S(per_secret_bytes_received[_i]) + S(per_secret_bytes_sent[_i]));
      }
      sb_printf (sb,
	       "# HELP teleproxy_secret_quota_bytes Configured byte quota per secret (0=unlimited).\n"
	       "# TYPE teleproxy_secret_quota_bytes gauge\n");
      for (_i = 0; _i < _sc; _i++) { if (tcp_rpcs_get_ext_secret_state (_i) == SLOT_FREE) { continue; }
        sb_printf (sb, "teleproxy_secret_quota_bytes{secret=\"%s\"} %lld\n",
	         tcp_rpcs_get_ext_secret_label (_i), tcp_rpcs_get_ext_secret_quota (_i));
      }
      sb_printf (sb,
	       "# HELP teleproxy_secret_max_ips Configured unique IP limit per secret (0=unlimited).\n"
	       "# TYPE teleproxy_secret_max_ips gauge\n");
      for (_i = 0; _i < _sc; _i++) { if (tcp_rpcs_get_ext_secret_state (_i) == SLOT_FREE) { continue; }
        sb_printf (sb, "teleproxy_secret_max_ips{secret=\"%s\"} %d\n",
	         tcp_rpcs_get_ext_secret_label (_i), tcp_rpcs_get_ext_secret_max_ips (_i));
      }
      sb_printf (sb,
	       "# HELP teleproxy_secret_unique_ips Current unique IPs connected per secret.\n"
	       "# TYPE teleproxy_secret_unique_ips gauge\n");
      for (_i = 0; _i < _sc; _i++) { if (tcp_rpcs_get_ext_secret_state (_i) == SLOT_FREE) { continue; }
        sb_printf (sb, "teleproxy_secret_unique_ips{secret=\"%s\"} %lld\n",
	         tcp_rpcs_get_ext_secret_label (_i), S(per_secret_unique_ips[_i]));
      }
      sb_printf (sb,
	       "# HELP teleproxy_secret_expires_timestamp Expiration Unix timestamp per secret (0=never).\n"
	       "# TYPE teleproxy_secret_expires_timestamp gauge\n");
      for (_i = 0; _i < _sc; _i++) { if (tcp_rpcs_get_ext_secret_state (_i) == SLOT_FREE) { continue; }
        sb_printf (sb, "teleproxy_secret_expires_timestamp{secret=\"%s\"} %lld\n",
	         tcp_rpcs_get_ext_secret_label (_i), (long long) tcp_rpcs_get_ext_secret_expires (_i));
      }
      sb_printf (sb,
	       "# HELP teleproxy_secret_rejected_quota_total Connections rejected due to byte quota.\n"
	       "# TYPE teleproxy_secret_rejected_quota_total counter\n");
      for (_i = 0; _i < _sc; _i++) { if (tcp_rpcs_get_ext_secret_state (_i) == SLOT_FREE) { continue; }
        sb_printf (sb, "teleproxy_secret_rejected_quota_total{secret=\"%s\"} %lld\n",
	         tcp_rpcs_get_ext_secret_label (_i), S(per_secret_rejected_quota[_i]));
      }
      sb_printf (sb,
	       "# HELP teleproxy_secret_rejected_ips_total Connections rejected due to unique IP limit.\n"
	       "# TYPE teleproxy_secret_rejected_ips_total counter\n");
      for (_i = 0; _i < _sc; _i++) { if (tcp_rpcs_get_ext_secret_state (_i) == SLOT_FREE) { continue; }
        sb_printf (sb, "teleproxy_secret_rejected_ips_total{secret=\"%s\"} %lld\n",
	         tcp_rpcs_get_ext_secret_label (_i), S(per_secret_rejected_ips[_i]));
      }
      sb_printf (sb,
	       "# HELP teleproxy_secret_rejected_expired_total Connections rejected due to secret expiration.\n"
	       "# TYPE teleproxy_secret_rejected_expired_total counter\n");
      for (_i = 0; _i < _sc; _i++) { if (tcp_rpcs_get_ext_secret_state (_i) == SLOT_FREE) { continue; }
        sb_printf (sb, "teleproxy_secret_rejected_expired_total{secret=\"%s\"} %lld\n",
	         tcp_rpcs_get_ext_secret_label (_i), S(per_secret_rejected_expired[_i]));
      }
      sb_printf (sb,
	       "# HELP teleproxy_secret_rate_limit_bytes Configured per-IP rate limit in bytes/sec (0=unlimited).\n"
	       "# TYPE teleproxy_secret_rate_limit_bytes gauge\n");
      for (_i = 0; _i < _sc; _i++) { if (tcp_rpcs_get_ext_secret_state (_i) == SLOT_FREE) { continue; }
        sb_printf (sb, "teleproxy_secret_rate_limit_bytes{secret=\"%s\"} %lld\n",
	         tcp_rpcs_get_ext_secret_label (_i), tcp_rpcs_get_ext_secret_rate_limit (_i));
      }
      sb_printf (sb,
	       "# HELP teleproxy_secret_rate_limited_total Times per-IP rate limiting was applied.\n"
	       "# TYPE teleproxy_secret_rate_limited_total counter\n");
      for (_i = 0; _i < _sc; _i++) { if (tcp_rpcs_get_ext_secret_state (_i) == SLOT_FREE) { continue; }
        sb_printf (sb, "teleproxy_secret_rate_limited_total{secret=\"%s\"} %lld\n",
	         tcp_rpcs_get_ext_secret_label (_i), S(per_secret_rate_limited[_i]));
      }
      sb_printf (sb,
	       "# HELP teleproxy_secret_draining 1 if the secret is draining after SIGHUP removal.\n"
	       "# TYPE teleproxy_secret_draining gauge\n");
      for (_i = 0; _i < _sc; _i++) { if (tcp_rpcs_get_ext_secret_state (_i) == SLOT_FREE) { continue; }
        sb_printf (sb, "teleproxy_secret_draining{secret=\"%s\"} %d\n",
	         tcp_rpcs_get_ext_secret_label (_i),
	         tcp_rpcs_get_ext_secret_state (_i) == SLOT_DRAINING ? 1 : 0);
      }
      sb_printf (sb,
	       "# HELP teleproxy_secret_drain_age_seconds Seconds since the secret entered draining state.\n"
	       "# TYPE teleproxy_secret_drain_age_seconds gauge\n");
      for (_i = 0; _i < _sc; _i++) { if (tcp_rpcs_get_ext_secret_state (_i) == SLOT_FREE) { continue; }
        double _age = 0;
        if (tcp_rpcs_get_ext_secret_state (_i) == SLOT_DRAINING) {
          double _started = tcp_rpcs_get_ext_secret_drain_started (_i);
          if (_started > 0) { _age = precise_now - _started; }
        }
        sb_printf (sb, "teleproxy_secret_drain_age_seconds{secret=\"%s\"} %.0f\n",
	         tcp_rpcs_get_ext_secret_label (_i), _age);
      }
      sb_printf (sb,
	       "# HELP teleproxy_secret_rejected_draining_total Connections rejected because the secret is draining.\n"
	       "# TYPE teleproxy_secret_rejected_draining_total counter\n");
      for (_i = 0; _i < _sc; _i++) { if (tcp_rpcs_get_ext_secret_state (_i) == SLOT_FREE) { continue; }
        sb_printf (sb, "teleproxy_secret_rejected_draining_total{secret=\"%s\"} %lld\n",
	         tcp_rpcs_get_ext_secret_label (_i), S(per_secret_rejected_draining[_i]));
      }
      sb_printf (sb,
	       "# HELP teleproxy_secret_drain_forced_total Connections force-closed when the drain timeout expired.\n"
	       "# TYPE teleproxy_secret_drain_forced_total counter\n");
      for (_i = 0; _i < _sc; _i++) { if (tcp_rpcs_get_ext_secret_state (_i) == SLOT_FREE) { continue; }
        sb_printf (sb, "teleproxy_secret_drain_forced_total{secret=\"%s\"} %lld\n",
	         tcp_rpcs_get_ext_secret_label (_i), S(per_secret_drain_forced[_i]));
      }

      /* Per-IP top-N metrics (issue #46).  Emitted only when the operator
         opts in via top_ips_per_secret > 0.  Sorted by bytes_in+bytes_out
         descending; ties broken by selection-sort order (stable enough). */
      int _top_n = tcp_rpcs_get_top_ips_per_secret ();
      if (_top_n > 0) {
        if (_top_n > MASTER_TOP_IPS_CAP) { _top_n = MASTER_TOP_IPS_CAP; }
        sb_printf (sb,
	       "# HELP teleproxy_secret_ip_connections Active connections per client IP (top N per secret by traffic).\n"
	       "# TYPE teleproxy_secret_ip_connections gauge\n");
        for (_i = 0; _i < _sc; _i++) { if (tcp_rpcs_get_ext_secret_state (_i) == SLOT_FREE) { continue; }
          int n = MasterTopIpsCount[_i];
          if (n <= 0) { continue; }
          qsort (MasterTopIps[_i], n, sizeof (MasterTopIps[_i][0]), top_ip_cmp_desc);
          if (n > _top_n) { n = _top_n; }
          for (int k = 0; k < n; k++) {
            char ipbuf[INET6_ADDRSTRLEN];
            const struct worker_top_ip *e = &MasterTopIps[_i][k];
            if (e->ip != 0) {
              unsigned ip_be = htonl (e->ip);
              inet_ntop (AF_INET, &ip_be, ipbuf, sizeof (ipbuf));
            } else {
              inet_ntop (AF_INET6, e->ipv6, ipbuf, sizeof (ipbuf));
            }
            sb_printf (sb, "teleproxy_secret_ip_connections{secret=\"%s\",ip=\"%s\"} %d\n",
                       tcp_rpcs_get_ext_secret_label (_i), ipbuf, e->connections);
          }
        }
        sb_printf (sb,
	       "# HELP teleproxy_secret_ip_bytes_received_total Bytes received from client IP (top N per secret by traffic).\n"
	       "# TYPE teleproxy_secret_ip_bytes_received_total counter\n");
        for (_i = 0; _i < _sc; _i++) { if (tcp_rpcs_get_ext_secret_state (_i) == SLOT_FREE) { continue; }
          int n = MasterTopIpsCount[_i];
          if (n <= 0) { continue; }
          if (n > _top_n) { n = _top_n; }
          for (int k = 0; k < n; k++) {
            char ipbuf[INET6_ADDRSTRLEN];
            const struct worker_top_ip *e = &MasterTopIps[_i][k];
            if (e->ip != 0) {
              unsigned ip_be = htonl (e->ip);
              inet_ntop (AF_INET, &ip_be, ipbuf, sizeof (ipbuf));
            } else {
              inet_ntop (AF_INET6, e->ipv6, ipbuf, sizeof (ipbuf));
            }
            sb_printf (sb, "teleproxy_secret_ip_bytes_received_total{secret=\"%s\",ip=\"%s\"} %lld\n",
                       tcp_rpcs_get_ext_secret_label (_i), ipbuf, e->bytes_in);
          }
        }
        sb_printf (sb,
	       "# HELP teleproxy_secret_ip_bytes_sent_total Bytes sent to client IP (top N per secret by traffic).\n"
	       "# TYPE teleproxy_secret_ip_bytes_sent_total counter\n");
        for (_i = 0; _i < _sc; _i++) { if (tcp_rpcs_get_ext_secret_state (_i) == SLOT_FREE) { continue; }
          int n = MasterTopIpsCount[_i];
          if (n <= 0) { continue; }
          if (n > _top_n) { n = _top_n; }
          for (int k = 0; k < n; k++) {
            char ipbuf[INET6_ADDRSTRLEN];
            const struct worker_top_ip *e = &MasterTopIps[_i][k];
            if (e->ip != 0) {
              unsigned ip_be = htonl (e->ip);
              inet_ntop (AF_INET, &ip_be, ipbuf, sizeof (ipbuf));
            } else {
              inet_ntop (AF_INET6, e->ipv6, ipbuf, sizeof (ipbuf));
            }
            sb_printf (sb, "teleproxy_secret_ip_bytes_sent_total{secret=\"%s\",ip=\"%s\"} %lld\n",
                       tcp_rpcs_get_ext_secret_label (_i), ipbuf, e->bytes_out);
          }
        }
      }
    }
  }

  dc_probes_write_prometheus (sb);

#undef S
#undef S1
#undef SW
}

/* ── /link endpoint: HTML page with SVG QR codes ─────────────── */

static void sb_qr_svg (stats_buffer_t *sb, const char *url) {
  uint8_t qrcode[qrcodegen_BUFFER_LEN_MAX];
  uint8_t temp[qrcodegen_BUFFER_LEN_MAX];

  if (!qrcodegen_encodeText (url, temp, qrcode, qrcodegen_Ecc_LOW,
                             qrcodegen_VERSION_MIN, qrcodegen_VERSION_MAX,
                             qrcodegen_Mask_AUTO, true)) {
    sb_printf (sb, "<p>QR encoding failed</p>\n");
    return;
  }

  int size = qrcodegen_getSize (qrcode);
  int margin = 2;
  int full = size + 2 * margin;

  sb_printf (sb, "<svg viewBox=\"0 0 %d %d\" xmlns=\"http://www.w3.org/2000/svg\">"
             "<rect width=\"%d\" height=\"%d\" fill=\"#fff\"/>",
             full, full, full, full);

  for (int y = 0; y < size; y++) {
    for (int x = 0; x < size; x++) {
      if (qrcodegen_getModule (qrcode, x, y)) {
        sb_printf (sb, "<rect x=\"%d\" y=\"%d\" width=\"1\" height=\"1\"/>",
                   x + margin, y + margin);
      }
    }
  }
  sb_printf (sb, "</svg>");
}

static void format_ipv4 (char *buf, int bufsz, unsigned ip) {
  snprintf (buf, bufsz, "%u.%u.%u.%u",
            ip >> 24, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
}

unsigned parse_text_ipv4 (char *str);

void mtfront_prepare_link_page (stats_buffer_t *sb,
                                const char *host, int host_len) {
  char server[256];
  int slen = host_len;
  if (slen >= (int)sizeof (server)) {
    slen = sizeof (server) - 1;
  }
  memcpy (server, host, slen);
  server[slen] = '\0';

  /* Strip port suffix (e.g., "1.2.3.4:8888" -> "1.2.3.4") */
  char *colon = strrchr (server, ':');
  if (colon && strchr (server, '.')) {
    *colon = '\0';
  }
  /* For IPv6 [::1]:8888, strip bracket+port */
  if (server[0] == '[') {
    char *bracket = strchr (server, ']');
    if (bracket) {
      *bracket = '\0';
      memmove (server, server + 1, strlen (server + 1) + 1);
    }
  }

  /* Fix unreachable Host values: loopback and Docker-internal IPs */
  if (!strcmp (server, "localhost")) {
    format_ipv4 (server, sizeof (server), get_external_ipv4 ());
  } else {
    unsigned ip = parse_text_ipv4 (server);
    if (ip) {
      unsigned translated = nat_translate_ip (ip);
      if (translated != ip) {
        format_ipv4 (server, sizeof (server), translated);
      } else if ((ip >> 24) == 127) {
        format_ipv4 (server, sizeof (server), get_external_ipv4 ());
      }
    }
  }

  int port = http_port[0];

  sb_printf (sb,
    "<!DOCTYPE html><html><head>"
    "<meta charset=\"utf-8\">"
    "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
    "<title>Teleproxy</title>"
    "<style>"
    "*{box-sizing:border-box;margin:0;padding:0}"
    "body{font-family:system-ui,-apple-system,sans-serif;background:#f5f5f5;"
    "min-height:100vh;display:flex;flex-direction:column;align-items:center;padding:2rem 1rem}"
    ".card{background:#fff;border-radius:12px;padding:1.5rem;margin:1rem 0;"
    "box-shadow:0 1px 3px rgba(0,0,0,.1);text-align:center;width:100%%;max-width:400px}"
    ".card svg{width:100%%;max-width:280px;height:auto;margin:1rem auto;display:block}"
    ".label{font-size:.85rem;font-weight:600;color:#666;margin-bottom:.5rem}"
    ".url{word-break:break-all;font-size:.8rem;color:#0066cc;text-decoration:none;"
    "display:block;margin-top:.75rem}"
    ".url:hover{text-decoration:underline}"
    "h1{font-size:1.25rem;color:#333;margin-bottom:.5rem}"
    "p.hint{font-size:.8rem;color:#999}"
    "</style></head><body>"
    "<h1>Connection Links</h1>"
    "<p class=\"hint\">Tap a QR code to open in Telegram</p>\n");

  int n = toml_cfg.secret_count;
  for (int i = 0; i < n; i++) {
    char secret_hex[1024];
    int pos = 0;

    if (toml_cfg.domain_count > 0 && toml_cfg.domains[0][0]) {
      pos += snprintf (secret_hex + pos, sizeof (secret_hex) - pos, "ee");
      for (int j = 0; j < 16; j++) {
        int rem = (int)sizeof (secret_hex) - pos;
        if (rem <= 0) break;
        int w = snprintf (secret_hex + pos, rem,
                          "%02x", toml_cfg.secrets[i].key[j]);
        if (w < 0 || w >= rem) break;
        pos += w;
      }
      const char *dom = toml_cfg.domains[0];
      const char *dom_colon = strchr (dom, ':');
      int dom_len = dom_colon ? (int)(dom_colon - dom) : (int)strlen (dom);
      for (int j = 0; j < dom_len; j++) {
        int rem = (int)sizeof (secret_hex) - pos;
        if (rem <= 0) break;
        int w = snprintf (secret_hex + pos, rem,
                          "%02x", (unsigned char)dom[j]);
        if (w < 0 || w >= rem) break;
        pos += w;
      }
    } else if (toml_cfg.random_padding_only == 1) {
      pos += snprintf (secret_hex + pos, sizeof (secret_hex) - pos, "dd");
      for (int j = 0; j < 16; j++) {
        int rem = (int)sizeof (secret_hex) - pos;
        if (rem <= 0) break;
        int w = snprintf (secret_hex + pos, rem,
                          "%02x", toml_cfg.secrets[i].key[j]);
        if (w < 0 || w >= rem) break;
        pos += w;
      }
    } else {
      for (int j = 0; j < 16; j++) {
        int rem = (int)sizeof (secret_hex) - pos;
        if (rem <= 0) break;
        int w = snprintf (secret_hex + pos, rem,
                          "%02x", toml_cfg.secrets[i].key[j]);
        if (w < 0 || w >= rem) break;
        pos += w;
      }
    }

    char url[2048];
    snprintf (url, sizeof (url),
              "https://t.me/proxy?server=%s&port=%d&secret=%s",
              server, port, secret_hex);

    char tg_url[2048];
    snprintf (tg_url, sizeof (tg_url),
              "tg://proxy?server=%s&port=%d&secret=%s",
              server, port, secret_hex);

    sb_printf (sb, "<div class=\"card\">\n");
    if (toml_cfg.secrets[i].label[0]) {
      sb_printf (sb, "<div class=\"label\">%s</div>\n", toml_cfg.secrets[i].label);
    }
    sb_printf (sb, "<a href=\"%s\">", tg_url);
    sb_qr_svg (sb, url);
    sb_printf (sb, "</a>\n");
    sb_printf (sb, "<a class=\"url\" href=\"%s\">%s</a>\n", tg_url, url);
    sb_printf (sb, "</div>\n");
  }

  if (n == 0) {
    sb_printf (sb, "<div class=\"card\"><p>No secrets configured</p></div>\n");
  }

  sb_printf (sb, "</body></html>\n");
}
