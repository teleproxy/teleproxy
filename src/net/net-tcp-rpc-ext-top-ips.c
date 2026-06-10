/*
    This file is part of Teleproxy.

    Teleproxy is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    This program is released under the GPL with the additional exemption
    that compiling, linking, and/or using OpenSSL is allowed.
    You are free to remove this exemption from derived works.
*/

/*
 *  Per-IP volume tracking for top-N Prometheus metrics (issue #46).
 *
 *  Sidecar table, decoupled from the rate-limit/max_ips table in
 *  net-tcp-rpc-ext-server.c.  Populated only when top_ips_per_secret > 0.
 *  Tracks active connections and bytes per client IP per secret, so the
 *  master can render top-N to /metrics.
 *
 *  Eviction: when a table is full, the entry with the smallest bytes_total
 *  whose last_seen is older than IP_VOLUME_STALE_SEC and which has zero
 *  active connections is recycled.  If no slot is eligible, the new IP is
 *  dropped silently — losing one entry from a metrics sidecar is acceptable.
 */

#include <string.h>

#include "common/ip-utils.h"
#include "common/precise-time.h"
#include "net/net-connections.h"
#include "net/net-tcp-rpc-ext-server.h"

#define IP_VOLUME_TABLE_SIZE 64
#define IP_VOLUME_STALE_SEC 5.0

struct ip_volume_entry {
  unsigned ip;                /* IPv4 host order; 0 means slot is IPv6 or empty */
  unsigned char ipv6[16];     /* IPv6 (zero if IPv4 entry or empty) */
  int connections;            /* current active connections from this IP */
  long long bytes_in;
  long long bytes_out;
  double last_seen;           /* precise_now of most recent activity */
};

static struct ip_volume_entry ip_volume[16][IP_VOLUME_TABLE_SIZE];
static int top_ips_per_secret_runtime = 0;

void tcp_rpcs_set_top_ips_per_secret (int n) {
  if (n < 0) { n = 0; }
  if (n > WORKER_TOP_IPS_MAX) { n = WORKER_TOP_IPS_MAX; }
  top_ips_per_secret_runtime = n;
}

int tcp_rpcs_get_top_ips_per_secret (void) {
  return top_ips_per_secret_runtime;
}

/* Find an entry matching (ip, ipv6).  Empty slots have ip == 0 and zero ipv6. */
static struct ip_volume_entry *ip_volume_lookup (int sid, unsigned ip,
                                                 const unsigned char *ipv6) {
  for (int i = 0; i < IP_VOLUME_TABLE_SIZE; i++) {
    struct ip_volume_entry *e = &ip_volume[sid][i];
    if (ip != 0) {
      if (e->ip == ip) { return e; }
    } else if (ipv6 && memcmp (ipv6, zero_ipv6, 16) != 0) {
      if (e->ip == 0 && memcmp (e->ipv6, ipv6, 16) == 0 &&
          memcmp (e->ipv6, zero_ipv6, 16) != 0) {
        return e;
      }
    }
  }
  return NULL;
}

/* Find an empty slot or evict a stale one.  Returns NULL if the table is
   full of fresh / active entries — the caller silently drops the new IP. */
static struct ip_volume_entry *ip_volume_acquire_slot (int sid) {
  /* First pass: empty slot. */
  for (int i = 0; i < IP_VOLUME_TABLE_SIZE; i++) {
    struct ip_volume_entry *e = &ip_volume[sid][i];
    if (e->ip == 0) {
      if (memcmp (e->ipv6, zero_ipv6, 16) == 0) { return e; }
    }
  }
  /* Second pass: evict the entry with smallest bytes_total whose last_seen
     is older than the staleness threshold and which has no active connections. */
  struct ip_volume_entry *victim = NULL;
  long long victim_bytes = 0;
  double cutoff = precise_now - IP_VOLUME_STALE_SEC;
  for (int i = 0; i < IP_VOLUME_TABLE_SIZE; i++) {
    struct ip_volume_entry *e = &ip_volume[sid][i];
    if (e->connections > 0) { continue; }
    if (e->last_seen >= cutoff) { continue; }
    long long total = e->bytes_in + e->bytes_out;
    if (!victim || total < victim_bytes) {
      victim = e;
      victim_bytes = total;
    }
  }
  if (victim) {
    memset (victim, 0, sizeof (*victim));
  }
  return victim;
}

static struct ip_volume_entry *ip_volume_get_or_create (int sid, unsigned ip,
                                                        const unsigned char *ipv6) {
  struct ip_volume_entry *e = ip_volume_lookup (sid, ip, ipv6);
  if (e) { return e; }
  e = ip_volume_acquire_slot (sid);
  if (!e) { return NULL; }
  e->ip = ip;
  if (ip == 0 && ipv6) {
    memcpy (e->ipv6, ipv6, 16);
  } else {
    memset (e->ipv6, 0, 16);
  }
  e->connections = 0;
  e->bytes_in = 0;
  e->bytes_out = 0;
  e->last_seen = precise_now;
  return e;
}

void tcp_rpcs_account_connect (int sid, unsigned ip, const unsigned char *ipv6) {
  if (top_ips_per_secret_runtime <= 0) { return; }
  if (sid < 0 || sid >= 16) { return; }
  struct ip_volume_entry *e = ip_volume_get_or_create (sid, ip, ipv6);
  if (!e) { return; }
  e->connections++;
  e->last_seen = precise_now;
}

void tcp_rpcs_account_disconnect (int sid, unsigned ip, const unsigned char *ipv6) {
  if (top_ips_per_secret_runtime <= 0) { return; }
  if (sid < 0 || sid >= 16) { return; }
  struct ip_volume_entry *e = ip_volume_lookup (sid, ip, ipv6);
  if (!e) { return; }
  if (e->connections > 0) { e->connections--; }
  e->last_seen = precise_now;
  /* bytes_in/out preserved for late metric scrapes; entry will be evicted
     by ip_volume_acquire_slot once it goes stale. */
}

void tcp_rpcs_account_bytes (int sid, unsigned ip, const unsigned char *ipv6,
                             long long bytes, int direction) {
  if (top_ips_per_secret_runtime <= 0) { return; }
  if (sid < 0 || sid >= 16 || bytes <= 0) { return; }
  struct ip_volume_entry *e = ip_volume_get_or_create (sid, ip, ipv6);
  if (!e) { return; }
  if (direction == 0) {
    e->bytes_in += bytes;
  } else {
    e->bytes_out += bytes;
  }
  e->last_seen = precise_now;
}

/* Snapshot the top-`max` entries by bytes_total descending into `out`.
   Skips entries with zero bytes AND zero connections (nothing useful to report).
   Used by update_local_stats_copy in the stats thread; runs inside the
   cnt-parity barrier so the destination buffer is naturally protected. */
void tcp_rpcs_snapshot_top_ips (int sid, struct worker_top_ip *out,
                                int *out_count, int max) {
  *out_count = 0;
  if (top_ips_per_secret_runtime <= 0) { return; }
  if (sid < 0 || sid >= 16 || max <= 0) { return; }

  /* Selection sort: pick the next-largest entry up to `max` times.
     Cheaper than qsort for tiny N. */
  char picked[IP_VOLUME_TABLE_SIZE] = {0};
  for (int slot = 0; slot < max; slot++) {
    int best = -1;
    long long best_total = -1;
    for (int i = 0; i < IP_VOLUME_TABLE_SIZE; i++) {
      if (picked[i]) { continue; }
      struct ip_volume_entry *e = &ip_volume[sid][i];
      if (e->ip == 0) {
        if (memcmp (e->ipv6, zero_ipv6, 16) == 0) { continue; }
      }
      long long total = e->bytes_in + e->bytes_out;
      if (total == 0 && e->connections == 0) { continue; }
      if (total > best_total) {
        best = i;
        best_total = total;
      }
    }
    if (best < 0) { break; }
    picked[best] = 1;
    struct ip_volume_entry *e = &ip_volume[sid][best];
    out[slot].ip = e->ip;
    memcpy (out[slot].ipv6, e->ipv6, 16);
    out[slot].connections = e->connections;
    out[slot].bytes_in = e->bytes_in;
    out[slot].bytes_out = e->bytes_out;
    (*out_count)++;
  }
}
