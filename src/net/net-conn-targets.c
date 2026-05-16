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

    Copyright 2009-2013 Vkontakte Ltd
              2008-2013 Nikolai Durov
              2008-2013 Andrey Lopatin

    Copyright 2014      Telegram Messenger Inc
              2014      Nikolai Durov
              2014      Andrey Lopatin

    Copyright 2015-2016 Telegram Messenger Inc
              2015-2016 Vitaly Valtman
*/

#define _FILE_OFFSET_BITS 64

#include <arpa/inet.h>
#include <assert.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "jobs/jobs.h"
#include "net/net-events.h"
#include "kprintf.h"
#include "precise-time.h"
#include "server-functions.h"
#include "net/net-connections.h"
#include "vv/vv-io.h"
#include "vv/vv-tree.h"

#include "net/net-tcp-connections.h"

#define MODULE connections
#include "common/common-stats.h"
#include "net/net-conn-targets-internal.h"

extern __thread MODULE_STAT_TYPE *MODULE_STAT;

/* Tree template for connection treaps (same instantiation as net-connections.c) */
#define X_TYPE connection_job_t
#define X_CMP(a,b) (((a) < (b)) ? -1 : ((a) > (b)) ? 1 : 0)
#define TREE_NAME connection
#define TREE_MALLOC
#define TREE_PTHREAD
#define TREE_INCREF job_incref
#define TREE_DECREF job_decref_f
#include "vv/vv-tree.c"

/* Forward declaration for function in net-connections.c */
int check_conn_functions (conn_type_t *type, int listening);

void compute_next_reconnect (conn_target_job_t CT) {
  struct conn_target_info *S = CONN_TARGET_INFO (CT);
  if (S->next_reconnect_timeout < S->reconnect_timeout || S->active_outbound_connections) {
    S->next_reconnect_timeout = S->reconnect_timeout;
  }
  S->next_reconnect = precise_now + S->next_reconnect_timeout;
  if (!S->active_outbound_connections && S->next_reconnect_timeout < MAX_RECONNECT_INTERVAL) {
    S->next_reconnect_timeout = S->next_reconnect_timeout * 1.5 + drand48_j () * 0.2;
  }
}

static void count_connection_num (connection_job_t C, void *good_c, void *stopped_c, void *bad_c) {
  int cr = CONN_INFO(C)->type->check_ready (C);
  switch (cr) {
    case cr_notyet:
    case cr_busy:
      break;
    case cr_ok:
      (*(int *)good_c)++;
      break;
    case cr_stopped:
      (*(int *)stopped_c)++;
      break;
    case cr_failed:
      (*(int *)bad_c)++;
      break;
    default:
      assert (0);
  }
}

static void find_bad_connection (connection_job_t C, void *x) {
  connection_job_t *T = x;
  if (*T) { return; }
  if (CONN_INFO(C)->flags & C_ERROR) {
    *T = C;
  }
}

void destroy_dead_target_connections (conn_target_job_t CTJ) {
  struct conn_target_info *CT = CONN_TARGET_INFO (CTJ);

  struct tree_connection *T = CT->conn_tree;
  if (T) {
    __sync_fetch_and_add (&T->refcnt, 1);
  }

  while (1) {
    connection_job_t CJ = NULL;
    tree_act_ex_connection (T, find_bad_connection, &CJ);
    if (!CJ) { break; }

    if (connection_is_active (CONN_INFO (CJ)->flags)) {
      __sync_fetch_and_add (&CT->active_outbound_connections, -1);
    }
    __sync_fetch_and_add (&CT->outbound_connections, -1);

    T = tree_delete_connection (T, CJ);
  }

  int good_c = 0, bad_c = 0, stopped_c = 0;

  tree_act_ex3_connection (T, count_connection_num, &good_c, &stopped_c, &bad_c);

  int was_ready = CT->ready_outbound_connections;
  CT->ready_outbound_connections = good_c;

  if (was_ready != CT->ready_outbound_connections) {
    MODULE_STAT->ready_outbound_connections += CT->ready_outbound_connections - was_ready;
  }

  if (was_ready && !CT->ready_outbound_connections) {
    MODULE_STAT->ready_targets --;
  }
  if (!was_ready && CT->ready_outbound_connections) {
    MODULE_STAT->ready_targets ++;
  }

  if (T == CT->conn_tree) {
    tree_free_connection (T);
  } else {
    struct tree_connection *old = CT->conn_tree;
    CT->conn_tree = T;
    barrier ();
    __sync_synchronize ();
    free_tree_ptr_connection (old);
  }
}

int create_new_connections (conn_target_job_t CTJ) {
  assert_main_thread ();

  destroy_dead_target_connections (CTJ);
  struct conn_target_info *CT = CONN_TARGET_INFO (CTJ);

  int count = 0, good_c = 0, bad_c = 0, stopped_c = 0, need_c;

  tree_act_ex3_connection (CT->conn_tree, count_connection_num, &good_c, &stopped_c, &bad_c);

  int was_ready = CT->ready_outbound_connections;
  CT->ready_outbound_connections = good_c;

  if (was_ready != CT->ready_outbound_connections) {
    MODULE_STAT->ready_outbound_connections += CT->ready_outbound_connections - was_ready;
  }

  if (was_ready && !CT->ready_outbound_connections) {
    MODULE_STAT->ready_targets --;
  }
  if (!was_ready && CT->ready_outbound_connections) {
    MODULE_STAT->ready_targets ++;
  }

  need_c = CT->min_connections + bad_c + ((stopped_c + 1) >> 1);
  if (need_c > CT->max_connections) {
    need_c = CT->max_connections;
  }

  if (precise_now >= CT->next_reconnect || CT->active_outbound_connections) {
    struct tree_connection *T = CT->conn_tree;
    if (T) {
      __sync_fetch_and_add (&T->refcnt, 1);
    }

    while (CT->outbound_connections < need_c) {
      int cfd = -1;
      if (CT->target.s_addr) {
        cfd = client_socket (CT->target.s_addr, CT->port, 0);
        vkprintf (1, "Created NEW connection #%d to %s:%d\n", cfd, inet_ntoa (CT->target), CT->port);
      } else {
        cfd = client_socket_ipv6 (CT->target_ipv6, CT->port, SM_IPV6);
        vkprintf (1, "Created NEW ipv6 connection #%d to [%s]:%d\n", cfd, show_ipv6 (CT->target_ipv6), CT->port);
      }
      if (cfd < 0) {
        if (CT->target.s_addr) {
          vkprintf (1, "error connecting to %s:%d: %m\n", inet_ntoa (CT->target), CT->port);
        } else {
          vkprintf (1, "error connecting to [%s]:%d\n", show_ipv6 (CT->target_ipv6), CT->port);
        }
        break;
      }

      connection_job_t C = alloc_new_connection (cfd, CTJ, NULL, ct_outbound, CT->type, CT->extra,
          ntohl (CT->target.s_addr), CT->target_ipv6, CT->port);

      if (C) {
        assert (CONN_INFO(C)->io_conn);
        count ++;
        unlock_job (JOB_REF_CREATE_PASS (C));
        T = tree_insert_connection (T, C, lrand48_j ());
      } else {
        break;
      }
    }

    if (T == CT->conn_tree) {
      tree_free_connection (T);
    } else {
      struct tree_connection *old = CT->conn_tree;
      CT->conn_tree = T;
      __sync_synchronize ();
      free_tree_ptr_connection (old);
    }

    compute_next_reconnect (CTJ);
  }

  return count;
}

conn_target_job_t HTarget[PRIME_TARGETS];
pthread_mutex_t TargetsLock = PTHREAD_MUTEX_INITIALIZER;

/* mode = 0 -- lookup, mode = 1 -- insert, mode = -1 -- delete */
static conn_target_job_t find_target (struct in_addr ad, int port, conn_type_t *type, void *extra, int mode, conn_target_job_t new_target) {
  assert (ad.s_addr);
  unsigned h1 = ((unsigned long) type * 0xabacaba + ad.s_addr) % PRIME_TARGETS;
  h1 = (h1 * 239 + port) % PRIME_TARGETS;
  conn_target_job_t *prev = HTarget + h1, cur;
  while ((cur = *prev) != 0) {
    struct conn_target_info *S = CONN_TARGET_INFO (cur);
    if (S->target.s_addr == ad.s_addr && S->port == port && S->type == type && S->extra == extra) {
      if (mode < 0) {
        *prev = S->hnext;
        S->hnext = 0;
        return cur;
      }
      assert (!mode);
      return cur;
    }
    prev = &S->hnext;
  }
  assert (mode >= 0);
  if (mode > 0) {
    CONN_TARGET_INFO (new_target)->hnext = HTarget[h1];
    HTarget[h1] = new_target;
    return new_target;
  }
  return 0;
}

/* mode = 0 -- lookup, mode = 1 -- insert, mode = -1 -- delete */
static conn_target_job_t find_target_ipv6 (unsigned char ad_ipv6[16], int port, conn_type_t *type, void *extra, int mode, conn_target_job_t new_target) {
  assert (*(long long *)ad_ipv6 || ((long long *) ad_ipv6)[1]);
  unsigned h1 = ((unsigned long) type * 0xabacaba) % PRIME_TARGETS;
  int i;
  for (i = 0; i < 4; i++) {
    h1 = ((unsigned long long) h1 * 17239 + ((unsigned *) ad_ipv6)[i]) % PRIME_TARGETS;
  }
  h1 = (h1 * 239 + port) % PRIME_TARGETS;
  conn_target_job_t *prev = HTarget + h1, cur;
  while ((cur = *prev) != 0) {
    struct conn_target_info *S = CONN_TARGET_INFO (cur);
    if (
        ((long long *)S->target_ipv6)[1] == ((long long *)ad_ipv6)[1] &&
        *(long long *)S->target_ipv6 == *(long long *)ad_ipv6 &&
        S->port == port && S->type == type && !S->target.s_addr && S->extra == extra) {
      if (mode < 0) {
        *prev = S->hnext;
        S->hnext = 0;
        return cur;
      }
      assert (!mode);
      return cur;
    }
    prev = &S->hnext;
  }
  assert (mode >= 0);
  if (mode > 0) {
    CONN_TARGET_INFO (new_target)->hnext = HTarget[h1];
    HTarget[h1] = new_target;
    return new_target;
  }
  return 0;
}

static int free_target (conn_target_job_t CTJ) {
  pthread_mutex_lock (&TargetsLock);
  struct conn_target_info *CT = CONN_TARGET_INFO (CTJ);
  if (!CT || CT->global_refcnt > 0 || CT->conn_tree) {
    pthread_mutex_unlock (&TargetsLock);
    return -1;
  }

  assert (CT->type && !CT->global_refcnt);
  assert (!CT->conn_tree);
  if (CT->target.s_addr) {
    vkprintf (1, "Freeing unused target to %s:%d\n", inet_ntoa (CT->target), CT->port);
    assert (CTJ == find_target (CT->target, CT->port, CT->type, CT->extra, -1, 0));
  } else {
    vkprintf (1, "Freeing unused ipv6 target to [%s]:%d\n", show_ipv6 (CT->target_ipv6), CT->port);
    assert (CTJ == find_target_ipv6 (CT->target_ipv6, CT->port, CT->type, CT->extra, -1, 0));
  }

  pthread_mutex_unlock (&TargetsLock);

  MODULE_STAT->inactive_targets --;
  MODULE_STAT->free_targets ++;

  job_decref (JOB_REF_PASS (CTJ));

  return 1;
}

static void fail_connection_gw (connection_job_t C) {
  fail_connection (C, -17);
}

int clean_unused_target (conn_target_job_t CTJ) {
  assert (CTJ);
  struct conn_target_info *CT = CONN_TARGET_INFO (CTJ);
  assert (CT->type);
  if (CT->global_refcnt) {
    return 0;
  }
  if (CT->conn_tree) {
    tree_act_connection (CT->conn_tree, fail_connection_gw);
    return 0;
  }
  job_timer_remove (CTJ);
  return 0;
}

int destroy_target (JOB_REF_ARG (CTJ)) {
  struct conn_target_info *CT = CONN_TARGET_INFO (CTJ);
  assert (CT);
  assert (CT->type);
  assert (CT->global_refcnt > 0);

  int r;
  if (!((r = __sync_add_and_fetch (&CT->global_refcnt, -1)))) {
    MODULE_STAT->active_targets--;
    MODULE_STAT->inactive_targets++;

    job_signal (JOB_REF_PASS (CTJ), JS_RUN);
  } else {
    job_decref (JOB_REF_PASS (CTJ));
  }
  return r;
}

int do_conn_target_job (job_t job, int op, struct job_thread *JT) {
  if (epoll_fd <= 0) {
    job_timer_insert (job, precise_now + 0.01);
    return 0;
  }
  conn_target_job_t CTJ = job;
  struct conn_target_info *CT = CONN_TARGET_INFO (CTJ);

  if (op == JS_ALARM || op == JS_RUN) {
    if (op == JS_ALARM && !job_timer_check (job)) {
      return 0;
    }
    if (!CT->global_refcnt) {
      destroy_dead_target_connections (CTJ);
      clean_unused_target (CTJ);
      compute_next_reconnect (CTJ);
    } else {
      create_new_connections (CTJ);
    }

    if (CTJ->j_flags & JF_COMPLETED) { return 0; }

    if (CT->global_refcnt || CT->conn_tree) {
      job_timer_insert (CTJ, precise_now + 0.1);
      return 0;
    } else {
      if (free_target (CTJ) >= 0) {
        return JOB_COMPLETED;
      } else {
        job_timer_insert (CTJ, precise_now + 0.1);
        return 0;
      }
    }
  }
  if (op == JS_FINISH) {
    assert (CTJ->j_flags & JF_COMPLETED);
    MODULE_STAT->allocated_targets --;
    return job_free (JOB_REF_PASS (job));
  }

  return JOB_ERROR;
}

conn_target_job_t create_target (struct conn_target_info *source, int *was_created) {
  if (check_conn_functions (source->type, 0) < 0) {
    return NULL;
  }
  pthread_mutex_lock (&TargetsLock);

  conn_target_job_t T =
    source->target.s_addr ?
    find_target (source->target, source->port, source->type, source->extra, 0, 0) :
    find_target_ipv6 (source->target_ipv6, source->port, source->type, source->extra, 0, 0);

  if (T) {
    struct conn_target_info *t = CONN_TARGET_INFO (T);

    t->min_connections = source->min_connections;
    t->max_connections = source->max_connections;
    t->reconnect_timeout = source->reconnect_timeout;

    if (!__sync_fetch_and_add (&t->global_refcnt, 1)) {
      MODULE_STAT->active_targets++;
      MODULE_STAT->inactive_targets--;

      if (was_created) {
        *was_created = 2;
      }
    } else {
      if (was_created) {
        *was_created = 0;
      }
    }

    job_incref (T);
  } else {
    T = create_async_job (do_conn_target_job, JSC_ALLOW (JC_EPOLL, JS_RUN) | JSC_ALLOW (JC_EPOLL, JS_ABORT) | JSC_ALLOW (JC_EPOLL, JS_ALARM) | JSC_ALLOW (JC_EPOLL, JS_FINISH), -2, sizeof (struct conn_target_info), JT_HAVE_TIMER, JOB_REF_NULL);
    T->j_refcnt = 2;

    struct conn_target_info *t = CONN_TARGET_INFO (T);
    memcpy (t, source, sizeof (*source));
    job_timer_init (T);

    MODULE_STAT->active_targets ++;
    MODULE_STAT->allocated_targets ++;

    if (source->target.s_addr) {
      find_target (source->target, source->port, source->type, source->extra, 1, T);
    } else {
      find_target_ipv6 (source->target_ipv6, source->port, source->type, source->extra, 1, T);
    }

    if (was_created) {
      *was_created = 1;
    }
    t->global_refcnt = 1;
    schedule_job (JOB_REF_CREATE_PASS (T));
  }

  pthread_mutex_unlock (&TargetsLock);

  return T;
}
