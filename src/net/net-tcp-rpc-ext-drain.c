/*
    This file is part of Teleproxy.

    Teleproxy is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    Teleproxy is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with Teleproxy.  If not, see <http://www.gnu.org/licenses/>.
*/

/*
 * Graceful secret draining and SIGHUP-driven reload (issue #45).
 *
 * Owns the slot state machine (FREE / ACTIVE / DRAINING) and the rewritten
 * tcp_rpcs_reload_ext_secrets that preserves slot indices for in-flight
 * connections.  When a secret is removed from the TOML, its slot transitions
 * to DRAINING; new connections matching it are rejected at the accept gate
 * in net-tcp-rpc-ext-server.c, but existing ones keep working.  The 1 Hz
 * drain sweeper in mtproto-proxy.c calls into the helpers below to release
 * empty slots and force-close stragglers past drain_timeout_secs.
 *
 * Splits responsibility from net-tcp-rpc-ext-server.c, which keeps the
 * protocol parsing.  The ext_secret_* state arrays are defined as globals
 * over there and accessed via extern from this file.
 */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>

#include "common/kprintf.h"
#include "common/precise-time.h"
#include "jobs/jobs.h"
#include "net/net-connections.h"
#include "net/net-tcp-rpc-common.h"
#include "net/net-tcp-rpc-ext-server.h"
#include "net/net-tcp-direct-dc.h"

extern unsigned char ext_secret[EXT_SECRET_MAX_SLOTS][16];
extern int ext_secret_cnt;
extern int ext_secret_pinned;
extern char ext_secret_label[EXT_SECRET_MAX_SLOTS][EXT_SECRET_LABEL_MAX + 1];
extern int ext_secret_limit[EXT_SECRET_MAX_SLOTS];
extern long long ext_secret_quota[EXT_SECRET_MAX_SLOTS];
extern long long ext_secret_rate_limit[EXT_SECRET_MAX_SLOTS];
extern int ext_secret_max_ips[EXT_SECRET_MAX_SLOTS];
extern int64_t ext_secret_expires[EXT_SECRET_MAX_SLOTS];
extern int ext_secret_state[EXT_SECRET_MAX_SLOTS];
extern double ext_secret_drain_started_at[EXT_SECRET_MAX_SLOTS];

extern long long per_secret_connections[EXT_SECRET_MAX_SLOTS];
extern long long per_secret_connections_created[EXT_SECRET_MAX_SLOTS];
extern long long per_secret_connections_rejected[EXT_SECRET_MAX_SLOTS];
extern long long per_secret_bytes_received[EXT_SECRET_MAX_SLOTS];
extern long long per_secret_bytes_sent[EXT_SECRET_MAX_SLOTS];
extern long long per_secret_rejected_quota[EXT_SECRET_MAX_SLOTS];
extern long long per_secret_rejected_ips[EXT_SECRET_MAX_SLOTS];
extern long long per_secret_rejected_expired[EXT_SECRET_MAX_SLOTS];
extern long long per_secret_unique_ips[EXT_SECRET_MAX_SLOTS];
extern long long per_secret_rate_limited[EXT_SECRET_MAX_SLOTS];
extern long long per_secret_rejected_draining[EXT_SECRET_MAX_SLOTS];
extern long long per_secret_drain_forced[EXT_SECRET_MAX_SLOTS];

extern conn_type_t ct_tcp_rpc_ext_server;
extern conn_type_t ct_tcp_rpc_ext_server_drs;
extern conn_type_t ct_tcp_rpc_ext_server_mtfront;
extern int do_listening_connection_job (job_t job, int op, struct job_thread *JT);

static double drain_timeout_secs = 300.0;  /* 0 = infinite, never force-close */

void tcp_rpcs_pin_ext_secrets (void) {
  ext_secret_pinned = ext_secret_cnt;
}

int tcp_rpcs_get_ext_secret_pinned (void) {
  return ext_secret_pinned;
}

int tcp_rpcs_get_ext_secret_state (int index) {
  if (index < 0 || index >= EXT_SECRET_MAX_SLOTS) { return SLOT_FREE; }
  return ext_secret_state[index];
}

double tcp_rpcs_get_ext_secret_drain_started (int index) {
  if (index < 0 || index >= EXT_SECRET_MAX_SLOTS) { return 0; }
  return ext_secret_drain_started_at[index];
}

void tcp_rpcs_drain_set_timeout (double secs) {
  if (secs < 0) { secs = 0; }
  drain_timeout_secs = secs;
}

double tcp_rpcs_drain_get_timeout (void) {
  return drain_timeout_secs;
}

/* Reload ext secrets from config with graceful draining.

   Match-by-key: existing slots whose key reappears in the new config keep
   their slot index, counters, and IP tracking — clients holding extra_int2
   for that slot keep working without disruption.  Existing slots whose key
   is gone transition to SLOT_DRAINING; new connections for them are rejected
   but in-flight connections are kept until they close on their own or the
   drain sweeper force-closes them after drain_timeout_secs.  Brand-new keys
   take the lowest free slot.  Pinned CLI -S slots are immutable. */
int tcp_rpcs_reload_ext_secrets (const unsigned char secrets[][16],
                                const char labels[][EXT_SECRET_LABEL_MAX + 1],
                                const int *limits, const long long *quotas,
                                const long long *rate_limits,
                                const int *max_ips_arr, const int64_t *expires_arr,
                                int count) {
  int placed[EXT_SECRET_MAX_SLOTS] = {0};

  /* Reject collisions with pinned slots — pinned wins, log + drop the dup. */
  for (int i = 0; i < count; i++) {
    for (int p = 0; p < ext_secret_pinned; p++) {
      if (CRYPTO_memcmp (ext_secret[p], secrets[i], 16) == 0) {
        vkprintf (0, "secret reload: config secret #%d collides with pinned slot %d (label [%s]) — pinned wins, ignoring config entry\n",
                  i, p, ext_secret_label[p]);
        placed[i] = 1;
        break;
      }
    }
  }

  /* Pass A — mark current ACTIVE non-pinned slots as candidates to drain. */
  int candidate[EXT_SECRET_MAX_SLOTS] = {0};
  for (int s = ext_secret_pinned; s < EXT_SECRET_MAX_SLOTS; s++) {
    if (ext_secret_state[s] == SLOT_ACTIVE) { candidate[s] = 1; }
  }

  /* Pass B — for each new config secret, look for an existing slot with the
     same key (ACTIVE or DRAINING).  Refresh metadata in place; revive draining
     slots so their counters/byte totals/IP tracking carry over. */
  for (int i = 0; i < count; i++) {
    if (placed[i]) { continue; }
    for (int s = ext_secret_pinned; s < EXT_SECRET_MAX_SLOTS; s++) {
      if (ext_secret_state[s] == SLOT_FREE) { continue; }
      if (CRYPTO_memcmp (ext_secret[s], secrets[i], 16) != 0) { continue; }
      if (labels[i][0]) {
        snprintf (ext_secret_label[s], sizeof (ext_secret_label[s]), "%s", labels[i]);
      } else {
        snprintf (ext_secret_label[s], sizeof (ext_secret_label[s]), "secret_%d", s);
      }
      ext_secret_limit[s] = limits[i];
      ext_secret_quota[s] = quotas ? quotas[i] : 0;
      ext_secret_rate_limit[s] = rate_limits ? rate_limits[i] : 0;
      ext_secret_max_ips[s] = max_ips_arr ? max_ips_arr[i] : 0;
      ext_secret_expires[s] = expires_arr ? expires_arr[i] : 0;
      if (ext_secret_state[s] == SLOT_DRAINING) {
        vkprintf (0, "secret reload: revived draining slot %d (label [%s])\n", s, ext_secret_label[s]);
      }
      ext_secret_state[s] = SLOT_ACTIVE;
      ext_secret_drain_started_at[s] = 0;
      candidate[s] = 0;
      placed[i] = 1;
      break;
    }
  }

  /* Pass C — any candidate slot still set has been removed from the config:
     mark draining.  Counters, byte totals, and IP tracking stay intact so
     in-flight connections can keep paying quota and accumulating stats. */
  for (int s = ext_secret_pinned; s < EXT_SECRET_MAX_SLOTS; s++) {
    if (candidate[s]) {
      ext_secret_state[s] = SLOT_DRAINING;
      ext_secret_drain_started_at[s] = precise_now;
      vkprintf (0, "secret reload: draining slot %d (label [%s], %lld active connections)\n",
                s, ext_secret_label[s], per_secret_connections[s]);
    }
  }

  /* Pass D — allocate fresh slots for any new config secret not yet placed. */
  for (int i = 0; i < count; i++) {
    if (placed[i]) { continue; }
    int slot = -1;
    for (int s = ext_secret_pinned; s < EXT_SECRET_MAX_SLOTS; s++) {
      if (ext_secret_state[s] == SLOT_FREE) { slot = s; break; }
    }
    if (slot < 0) {
      vkprintf (0, "secret reload: no free slot for config secret #%d — drain in progress, %d slots in use, max %d\n",
                i, EXT_SECRET_MAX_SLOTS - ext_secret_pinned, EXT_SECRET_MAX_SLOTS);
      return -1;
    }
    memcpy (ext_secret[slot], secrets[i], 16);
    if (labels[i][0]) {
      snprintf (ext_secret_label[slot], sizeof (ext_secret_label[slot]), "%s", labels[i]);
    } else {
      snprintf (ext_secret_label[slot], sizeof (ext_secret_label[slot]), "secret_%d", slot);
    }
    ext_secret_limit[slot] = limits[i];
    ext_secret_quota[slot] = quotas ? quotas[i] : 0;
    ext_secret_rate_limit[slot] = rate_limits ? rate_limits[i] : 0;
    ext_secret_max_ips[slot] = max_ips_arr ? max_ips_arr[i] : 0;
    ext_secret_expires[slot] = expires_arr ? expires_arr[i] : 0;
    ext_secret_state[slot] = SLOT_ACTIVE;
    ext_secret_drain_started_at[slot] = 0;
    /* Brand-new logical secret — zero counters/byte totals/IP tracking. */
    per_secret_connections[slot] = 0;
    per_secret_connections_created[slot] = 0;
    per_secret_connections_rejected[slot] = 0;
    per_secret_bytes_received[slot] = 0;
    per_secret_bytes_sent[slot] = 0;
    per_secret_rejected_quota[slot] = 0;
    per_secret_rejected_ips[slot] = 0;
    per_secret_rejected_expired[slot] = 0;
    per_secret_unique_ips[slot] = 0;
    per_secret_rate_limited[slot] = 0;
    per_secret_rejected_draining[slot] = 0;
    per_secret_drain_forced[slot] = 0;
    tcp_rpcs_ip_track_clear_slot (slot);
    placed[i] = 1;
  }

  /* Validate active count after the dust settles. */
  int active_total = ext_secret_pinned;
  int high_water = ext_secret_pinned;
  for (int s = ext_secret_pinned; s < EXT_SECRET_MAX_SLOTS; s++) {
    if (ext_secret_state[s] == SLOT_ACTIVE) { active_total++; }
    if (ext_secret_state[s] != SLOT_FREE && s + 1 > high_water) { high_water = s + 1; }
  }
  if (active_total > EXT_SECRET_MAX_ACTIVE) {
    vkprintf (0, "secret reload: too many active secrets (%d, max %d)\n",
              active_total, EXT_SECRET_MAX_ACTIVE);
    return -1;
  }

  /* Write barrier before updating count — stats reader on a different
     thread snapshots cnt and then reads state/labels. */
  __sync_synchronize ();
  ext_secret_cnt = high_water;

  vkprintf (0, "secret reload: %d pinned + %d active (high-water slot %d)\n",
            ext_secret_pinned, active_total - ext_secret_pinned, high_water);
  return 0;
}

void tcp_rpcs_drain_release_slot_if_empty (int slot_id) {
  if (slot_id < ext_secret_pinned || slot_id >= EXT_SECRET_MAX_SLOTS) { return; }
  if (ext_secret_state[slot_id] != SLOT_DRAINING) { return; }
  if (per_secret_connections[slot_id] != 0) { return; }
  vkprintf (0, "secret drain: releasing slot %d (label [%s])\n",
            slot_id, ext_secret_label[slot_id]);
  ext_secret_state[slot_id] = SLOT_FREE;
  ext_secret_drain_started_at[slot_id] = 0;
  memset (ext_secret[slot_id], 0, 16);
  ext_secret_label[slot_id][0] = 0;
  ext_secret_limit[slot_id] = 0;
  ext_secret_quota[slot_id] = 0;
  ext_secret_rate_limit[slot_id] = 0;
  ext_secret_max_ips[slot_id] = 0;
  ext_secret_expires[slot_id] = 0;
  per_secret_connections[slot_id] = 0;
  per_secret_connections_created[slot_id] = 0;
  per_secret_connections_rejected[slot_id] = 0;
  per_secret_bytes_received[slot_id] = 0;
  per_secret_bytes_sent[slot_id] = 0;
  per_secret_rejected_quota[slot_id] = 0;
  per_secret_rejected_ips[slot_id] = 0;
  per_secret_rejected_expired[slot_id] = 0;
  per_secret_unique_ips[slot_id] = 0;
  per_secret_rate_limited[slot_id] = 0;
  per_secret_rejected_draining[slot_id] = 0;
  per_secret_drain_forced[slot_id] = 0;
  tcp_rpcs_ip_track_clear_slot (slot_id);

  /* Recompute high-water mark so ext_secret_cnt doesn't include trailing
     FREE slots. */
  int high_water = ext_secret_pinned;
  for (int s = ext_secret_pinned; s < EXT_SECRET_MAX_SLOTS; s++) {
    if (ext_secret_state[s] != SLOT_FREE && s + 1 > high_water) { high_water = s + 1; }
  }
  __sync_synchronize ();
  ext_secret_cnt = high_water;
}

/* Returns 1 if the connection_info type holds a per-secret extra_int2 set
   by tcp_rpcs_compact_parse_execute (the only sites that write it). */
static int conn_carries_secret_id (struct connection_info *ci) {
  return ci->type == &ct_tcp_rpc_ext_server_mtfront
      || ci->type == &ct_tcp_rpc_ext_server
      || ci->type == &ct_tcp_rpc_ext_server_drs
      || ci->type == &ct_direct_client
      || ci->type == &ct_direct_client_drs;
}

void tcp_rpcs_drain_force_close_for_slot (int slot_id) {
  if (slot_id < ext_secret_pinned || slot_id >= EXT_SECRET_MAX_SLOTS) { return; }
  int target = slot_id + 1;
  int closed = 0;
  for (int fd = 0; fd < MAX_CONNECTIONS; fd++) {
    connection_job_t C = connection_get_by_fd (fd);
    if (!C) { continue; }
    if (C->j_execute == do_listening_connection_job) {
      job_decref (JOB_REF_PASS (C));
      continue;
    }
    struct connection_info *ci = CONN_INFO (C);
    if (conn_carries_secret_id (ci) && TCP_RPC_DATA(C)->extra_int2 == target) {
      per_secret_drain_forced[slot_id]++;
      fail_connection (C, -500);
      closed++;
    }
    job_decref (JOB_REF_PASS (C));
  }
  if (closed > 0) {
    vkprintf (0, "secret drain: force-closed %d connections for slot %d (label [%s])\n",
              closed, slot_id, ext_secret_label[slot_id]);
  }
}
