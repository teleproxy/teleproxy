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

#pragma once

#include "common/common-stats.h"
#include "net/net-connections.h"
#include "net/net-tcp-rpc-ext-server.h"

#define MAX_WORKERS	256

struct worker_stats {
  int cnt;
  int updated_at;

  struct buffers_stat bufs;
  struct connections_stat conn;
  int allocated_aes_crypto, allocated_aes_crypto_temp;
  long long tot_dh_rounds[3];

  int ev_heap_size;
  int http_connections;

  long long get_queries;
  int pending_http_queries;

  long long accept_calls_failed, accept_nonblock_set_failed, accept_connection_limit_failed,
            accept_rate_limit_failed, accept_init_accepted_failed;

  long long active_rpcs, active_rpcs_created;
  long long rpc_dropped_running, rpc_dropped_answers;
  long long tot_forwarded_queries, expired_forwarded_queries;
  long long tot_forwarded_responses;
  long long dropped_queries, dropped_responses;
  long long tot_forwarded_simple_acks, dropped_simple_acks;
  long long mtproto_proxy_errors;
  long long direct_dc_connections_created, direct_dc_connections_active;
  long long direct_dc_connections_failed, direct_dc_connections_dc_closed;
  long long direct_dc_retries;
  long long socks5_connects_attempted, socks5_connects_succeeded, socks5_connects_failed;

  long long connections_failed_lru, connections_failed_flood;

  long long ext_connections, ext_connections_created;
  long long http_queries, http_bad_headers;

  long long drs_delays_applied;
  long long drs_delays_skipped;

  long long transport_errors_received;
  long long quickack_packets_received;

  long long per_secret_connections[EXT_SECRET_MAX_SLOTS];
  long long per_secret_connections_created[EXT_SECRET_MAX_SLOTS];
  long long per_secret_connections_rejected[EXT_SECRET_MAX_SLOTS];
  long long per_secret_bytes_received[EXT_SECRET_MAX_SLOTS];
  long long per_secret_bytes_sent[EXT_SECRET_MAX_SLOTS];
  long long per_secret_rejected_quota[EXT_SECRET_MAX_SLOTS];
  long long per_secret_rejected_ips[EXT_SECRET_MAX_SLOTS];
  long long per_secret_rejected_expired[EXT_SECRET_MAX_SLOTS];
  long long per_secret_unique_ips[EXT_SECRET_MAX_SLOTS];
  long long per_secret_rate_limited[EXT_SECRET_MAX_SLOTS];
  long long per_secret_rejected_draining[EXT_SECRET_MAX_SLOTS];
  long long per_secret_drain_forced[EXT_SECRET_MAX_SLOTS];

  /* Per-IP top-N snapshot (issue #46).  Populated each refresh from the
     worker-local ip_volume table.  Master merges across workers in the
     Prometheus renderer.  Empty when top_ips_per_secret is 0. */
  struct worker_top_ip top_ips[EXT_SECRET_MAX_SLOTS][WORKER_TOP_IPS_MAX];
  int top_ips_count[EXT_SECRET_MAX_SLOTS];
};

extern struct worker_stats *WStats, SumStats;
extern int worker_id, workers, slave_mode, parent_pid;
extern int pids[];

extern long long get_queries;
extern int pending_http_queries;

extern long long active_rpcs, active_rpcs_created;
extern long long rpc_dropped_running, rpc_dropped_answers;
extern long long tot_forwarded_queries, expired_forwarded_queries, dropped_queries;
extern long long tot_forwarded_responses, dropped_responses;
extern long long tot_forwarded_simple_acks, dropped_simple_acks;
extern long long mtproto_proxy_errors;
extern long long direct_dc_connections_created, direct_dc_connections_active;
extern long long direct_dc_connections_failed, direct_dc_connections_dc_closed;
extern long long direct_dc_retries;
extern long long transport_errors_received;
extern long long quickack_packets_received;

extern char proxy_tag[16];
extern int proxy_tag_set;

extern int direct_mode;
extern int proxy_mode;
extern int window_clamp;

void update_local_stats (void);
void compute_stats_sum (void);
void mtfront_prepare_stats (stats_buffer_t *sb);
void mtfront_prepare_prometheus_stats (stats_buffer_t *sb);
void mtfront_prepare_link_page (stats_buffer_t *sb,
                                const char *host, int host_len);
