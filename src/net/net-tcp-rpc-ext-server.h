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

    Copyright 2016-2018 Telegram Messenger Inc                 
              2016-2018 Nikolai Durov
*/

#pragma once

#include <stdint.h>

#define __ALLOW_UNOBFS__ 0

#include "net/net-tcp-rpc-server.h"
#include "net/net-connections.h"

extern conn_type_t ct_tcp_rpc_ext_server;

int tcp_rpcs_compact_parse_execute (connection_job_t c);

#define EXT_SECRET_LABEL_MAX 32

/* Slot capacity.  Active secrets stay <= EXT_SECRET_MAX_ACTIVE; the extra
   slots host draining secrets after a SIGHUP reload removes them, until
   their connections finish or are force-closed by the drain sweeper. */
#define EXT_SECRET_MAX_ACTIVE 16
#define EXT_SECRET_MAX_SLOTS  32

enum {
  SLOT_FREE = 0,
  SLOT_ACTIVE = 1,
  SLOT_DRAINING = 2,
};

void tcp_rpcs_set_ext_secret(unsigned char secret[16], const char *label,
                             int limit, long long quota, long long rate_limit,
                             int max_ips, int64_t expires);
void tcp_rpcs_set_ext_rand_pad_only(int set);
const char *tcp_rpcs_get_ext_secret_label(int index);
int tcp_rpcs_get_ext_secret_limit(int index);
long long tcp_rpcs_get_ext_secret_quota(int index);
long long tcp_rpcs_get_ext_secret_rate_limit(int index);
int tcp_rpcs_get_ext_secret_max_ips(int index);
int64_t tcp_rpcs_get_ext_secret_expires(int index);
int tcp_rpcs_get_ext_secret_count(void);
int tcp_rpcs_get_ext_secret_pinned(void);
int tcp_rpcs_get_ext_secret_state(int index);
double tcp_rpcs_get_ext_secret_drain_started(int index);

void tcp_rpcs_pin_ext_secrets (void);
int tcp_rpcs_reload_ext_secrets (const unsigned char secrets[][16],
                                const char labels[][EXT_SECRET_LABEL_MAX + 1],
                                const int *limits, const long long *quotas,
                                const long long *rate_limits,
                                const int *max_ips_arr, const int64_t *expires_arr,
                                int count);

/* Drain helpers — engine thread only. */
void tcp_rpcs_drain_set_timeout (double secs);
double tcp_rpcs_drain_get_timeout (void);
void tcp_rpcs_drain_force_close_for_slot (int slot_id);
void tcp_rpcs_drain_release_slot_if_empty (int slot_id);

void tcp_rpcs_ip_track_disconnect (int secret_id, unsigned ip, const unsigned char *ipv6);
void tcp_rpcs_ip_track_clear_slot (int secret_id);

/* Per-IP volume tracking (issue #46).  Sidecar table populated only when
   top_ips_per_secret > 0.  See net-tcp-rpc-ext-server.c for details. */
#define WORKER_TOP_IPS_MAX 32

struct worker_top_ip {
  unsigned ip;                /* IPv4 host order; 0 means IPv6 entry */
  unsigned char ipv6[16];     /* IPv6 (zero if IPv4) */
  int connections;
  long long bytes_in;
  long long bytes_out;
};

void tcp_rpcs_set_top_ips_per_secret (int n);
int  tcp_rpcs_get_top_ips_per_secret (void);
void tcp_rpcs_account_connect (int secret_id, unsigned ip, const unsigned char *ipv6);
void tcp_rpcs_account_disconnect (int secret_id, unsigned ip, const unsigned char *ipv6);
void tcp_rpcs_account_bytes (int secret_id, unsigned ip, const unsigned char *ipv6,
                             long long bytes, int direction);
void tcp_rpcs_snapshot_top_ips (int secret_id, struct worker_top_ip *out,
                                int *out_count, int max);

/* Register a fake-TLS domain. `backend` is optional: NULL/empty means the
   camouflage traffic is forwarded back to the SNI domain itself (legacy).
   When set, it can be host:port or unix:/path for an off-host or local backend. */
void tcp_rpc_add_proxy_domain (const char *name, const char *backend);

void tcp_rpc_init_proxy_domains();

/* SOCKS5 upstream proxy */
int socks5_set_proxy (const char *url);
int socks5_is_enabled (void);

extern long long socks5_connects_attempted, socks5_connects_succeeded, socks5_connects_failed;
