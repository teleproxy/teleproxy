/*
    This file is part of MTProto-proxy

    MTProto-proxy is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    MTProto-Server is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with MTProto-Server.  If not, see <http://www.gnu.org/licenses/>.

    This program is released under the GPL with the additional exemption
    that compiling, linking, and/or using OpenSSL is allowed.
    You are free to remove this exemption from derived works.

    Copyright 2012-2018 Nikolai Durov
              2012-2014 Andrey Lopatin
              2014-2018 Telegram Messenger Inc
*/
#define	_FILE_OFFSET_BITS	64

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include "common/platform.h"
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <netdb.h>
#include <ctype.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#include "crc32.h"
#include "md5.h"
#include "resolver.h"
#include "net/net-events.h"
#include "kprintf.h"
#include "precise-time.h"
#include "server-functions.h"
#include "net/net-tcp-connections.h"
#include "net/net-rpc-targets.h"
#include "net/net-http-server.h"
#include "net/net-tcp-rpc-server.h"
#include "net/net-tcp-rpc-client.h"
#include "net/net-tcp-rpc-ext-server.h"
#include "net/net-proxy-protocol.h"
#include "net/net-crypto-aes.h"
#include "net/net-crypto-dh.h"
#include "mtproto-check.h"
#include "mtproto-link.h"
#include "mtproto-common.h"
#include "mtproto-config.h"
#include "mtproto-dc-table.h"
#include "mtproto-dc-probes.h"
#include "common/tl-parse.h"
#include "engine/engine.h"
#include "engine/engine-net.h"
#include "jobs/jobs.h"
#include "net/net-ip-acl.h"
#include "net/net-tcp-drs.h"
#include "common/toml-config.h"
#include "mtproto-proxy-stats.h"
#include "mtproto-proxy-http.h"

#ifndef COMMIT
#define COMMIT "unknown"
#endif

#ifndef VERSION
#define VERSION "unknown"
#endif

#define VERSION_STR	"teleproxy-" VERSION
const char FullVersionStr[] = VERSION_STR " compiled at " __DATE__ " " __TIME__ " by gcc " __VERSION__ " "
#ifdef __LP64__
  "64-bit"
#else
  "32-bit"
#endif
" after commit " COMMIT;

#define EXT_CONN_TABLE_SIZE	(1 << 22)
#define EXT_CONN_HASH_SHIFT	20
#define EXT_CONN_HASH_SIZE	(1 << EXT_CONN_HASH_SHIFT)

#define	RPC_TIMEOUT_INTERVAL	5.0

#define	MAX_HTTP_LISTEN_PORTS	128

#define	HTTP_MAX_WAIT_TIMEOUT	960.0

#define PING_INTERVAL 5.0
#define STOP_INTERVAL (2 * ping_interval)
#define FAIL_INTERVAL (20 * ping_interval)
#define RESPONSE_FAIL_TIMEOUT 5
#define CONNECT_TIMEOUT 3

#define	MAX_POST_SIZE	(262144 * 4 - 4096)

#define	DEFAULT_WINDOW_CLAMP	131072

// #define DEFAULT_OUTBOUND_CONNECTION_CREATION_RATE	1000000

#if 0
#define	MAX_CONNECTION_BUFFER_SPACE	(1 << 10) //(1 << 25)
#define MAX_MTFRONT_NB			1 //((NB_max * 3) >> 2)
#else
#define	MAX_CONNECTION_BUFFER_SPACE	(1 << 25)
#define MAX_MTFRONT_NB			((NB_max * 3) >> 2)
#endif

static double ping_interval = PING_INTERVAL;
int window_clamp;

#define	PROXY_MODE_OUT	2
int proxy_mode;
int direct_mode;
int ipv6_enabled;
static int dc_probe_interval_from_cli = -1;

#define IS_PROXY_IN	0
#define IS_PROXY_OUT	1
#define IS_PROXY_INOUT	1

#define TL_HTTP_QUERY_INFO 0xd45ab381
#define TL_PROXY_TAG	0xdb1e26ae

conn_type_t ct_http_server_mtfront, ct_tcp_rpc_ext_server_mtfront, ct_tcp_rpc_server_mtfront;

long long connections_failed_lru, connections_failed_flood;
long long api_invoke_requests;

volatile int sigpoll_cnt;

#define STATS_BUFF_SIZE	(1 << 20)

int stats_buff_len;
char stats_buff[STATS_BUFF_SIZE];


// current HTTP query headers
char cur_http_origin[1024], cur_http_referer[1024], cur_http_user_agent[1024];
int cur_http_origin_len, cur_http_referer_len, cur_http_user_agent_len;

int check_conn_buffers (connection_job_t c);
void lru_insert_conn (connection_job_t c);

/*
 *
 *	CONFIGURATION PARSER SETUP
 *
 */

#define	DEFAULT_CFG_MIN_CONNECTIONS	4
#define	DEFAULT_CFG_MAX_CONNECTIONS	8

int default_cfg_min_connections = DEFAULT_CFG_MIN_CONNECTIONS;
int default_cfg_max_connections = DEFAULT_CFG_MAX_CONNECTIONS;

struct tcp_rpc_client_functions mtfront_rpc_client;

conn_type_t ct_tcp_rpc_client_mtfront;

struct conn_target_info default_cfg_ct = {
.min_connections = DEFAULT_CFG_MIN_CONNECTIONS,
.max_connections = DEFAULT_CFG_MAX_CONNECTIONS,
.type = &ct_tcp_rpc_client_mtfront,
.extra = (void *)&mtfront_rpc_client,
.reconnect_timeout = 17
};


/*
 *
 *		EXTERNAL CONNECTIONS TABLE
 *
 */

struct ext_connection {
  struct ext_connection *o_prev, *o_next; // list of all with same out_fd
  struct ext_connection *i_prev, *i_next; // list of all with same in_fd
  struct ext_connection *h_next; // next in hash on (in_fd, in_conn_id)
  int in_fd, in_gen;
  int out_fd, out_gen;
  long long in_conn_id;
  long long out_conn_id;
  long long auth_key_id;
  struct ext_connection *lru_prev, *lru_next;
};

struct ext_connection_ref {
  struct ext_connection *ref;
  long long out_conn_id;
};

long long ext_connections, ext_connections_created;
long long per_secret_connections[EXT_SECRET_MAX_SLOTS], per_secret_connections_created[EXT_SECRET_MAX_SLOTS];
long long per_secret_connections_rejected[EXT_SECRET_MAX_SLOTS];
long long per_secret_bytes_received[EXT_SECRET_MAX_SLOTS], per_secret_bytes_sent[EXT_SECRET_MAX_SLOTS];
long long per_secret_rejected_quota[EXT_SECRET_MAX_SLOTS];
long long per_secret_rejected_ips[EXT_SECRET_MAX_SLOTS];
long long per_secret_rejected_expired[EXT_SECRET_MAX_SLOTS];
long long per_secret_unique_ips[EXT_SECRET_MAX_SLOTS];
long long per_secret_rate_limited[EXT_SECRET_MAX_SLOTS];
long long per_secret_rejected_draining[EXT_SECRET_MAX_SLOTS];
long long per_secret_drain_forced[EXT_SECRET_MAX_SLOTS];

struct ext_connection_ref OutExtConnections[EXT_CONN_TABLE_SIZE];
struct ext_connection *InExtConnectionHash[EXT_CONN_HASH_SIZE];
struct ext_connection ExtConnectionHead[MAX_CONNECTIONS];

void lru_delete_ext_conn (struct ext_connection *Ext);

static inline void check_engine_class (void) {
  check_thread_class (JC_ENGINE);
}

static inline int ext_conn_hash (int in_fd, long long in_conn_id) {
  unsigned long long h = (unsigned long long) in_fd * 11400714819323198485ULL + (unsigned long long) in_conn_id * 13043817825332782213ULL;
  return (h >> (64 - EXT_CONN_HASH_SHIFT));
}

// makes sense only for !IS_PROXY_IN
// returns the only ext_connection with given in_fd
struct ext_connection *get_ext_connection_by_in_fd (int in_fd) {
  check_engine_class ();
  assert ((unsigned) in_fd < MAX_CONNECTIONS);
  struct ext_connection *H = &ExtConnectionHead[in_fd];
  struct ext_connection *Ex = H->i_next;
  assert (H->i_next == H->i_prev);
  if (!Ex || Ex == H) {
    return 0;
  }
  assert (Ex->in_fd == in_fd);
  return Ex;
}

// mode: 0 = find, 1 = delete, 2 = create if not found, 3 = find or create
struct ext_connection *get_ext_connection_by_in_conn_id (int in_fd, int in_gen, long long in_conn_id, int mode, int *created) {
  check_engine_class ();
  int h = ext_conn_hash (in_fd, in_conn_id);
  struct ext_connection **prev = &InExtConnectionHash[h], *cur = *prev;
  for (; cur; cur = *prev) {
    if (cur->in_fd == in_fd && cur->in_conn_id == in_conn_id) {
      assert (cur->out_conn_id);
      if (mode == 0 || mode == 3) {
	return cur;
      }
      if (mode != 1) {
	return 0;
      }
      if (cur->i_next) {
	cur->i_next->i_prev = cur->i_prev;
	cur->i_prev->i_next = cur->i_next;
	cur->i_next = cur->i_prev = 0;
      }
      if (cur->o_next) {
	cur->o_next->o_prev = cur->o_prev;
	cur->o_prev->o_next = cur->o_next;
	cur->o_next = cur->o_prev = 0;
      }
      lru_delete_ext_conn (cur);
      *prev = cur->h_next;
      cur->h_next = 0;
      int h = cur->out_conn_id & (EXT_CONN_TABLE_SIZE - 1);
      assert (OutExtConnections[h].ref == cur);
      assert (OutExtConnections[h].out_conn_id == cur->out_conn_id);
      OutExtConnections[h].ref = 0;
      cur->out_conn_id = 0;
      memset (cur, 0, sizeof (struct ext_connection));
      free (cur);
      ext_connections--;
      return (void *) -1L;
    }
    prev = &(cur->h_next);
  }
  if (mode != 2 && mode != 3) {
    return 0;
  }
  assert (ext_connections < EXT_CONN_TABLE_SIZE / 2);
  cur = calloc (sizeof (struct ext_connection), 1);
  assert (cur);
  cur->h_next = InExtConnectionHash[h];
  InExtConnectionHash[h] = cur;
  cur->in_fd = in_fd;
  cur->in_gen = in_gen;
  cur->in_conn_id = in_conn_id;
  assert ((unsigned) in_fd < MAX_CONNECTIONS);
  if (in_fd) {
    struct ext_connection *H = &ExtConnectionHead[in_fd];
    if (!H->i_next) {
      H->i_next = H->i_prev = H;
    }
    assert (H->i_next == H);
    cur->i_next = H;
    cur->i_prev = H->i_prev;
    H->i_prev->i_next = cur;
    H->i_prev = cur;
  }
  h = in_conn_id ? lrand48() : in_fd;
  while (OutExtConnections[h &= (EXT_CONN_TABLE_SIZE - 1)].ref) {
    h = lrand48();
  }
  OutExtConnections[h].ref = cur;
  cur->out_conn_id = OutExtConnections[h].out_conn_id = (OutExtConnections[h].out_conn_id | (EXT_CONN_TABLE_SIZE - 1)) + 1 + h;
  assert (cur->out_conn_id);
  if (created) {
    ++*created;
  }
  ext_connections++;
  ext_connections_created++;
  return cur;
}

struct ext_connection *find_ext_connection_by_out_conn_id (long long out_conn_id) {
 check_engine_class ();
  int h = out_conn_id & (EXT_CONN_TABLE_SIZE - 1);
  struct ext_connection *cur = OutExtConnections[h].ref;
  if (!cur || OutExtConnections[h].out_conn_id != out_conn_id) {
    return 0;
  }
  assert (cur->out_conn_id == out_conn_id);
  return cur;
}

// MUST be new
struct ext_connection *create_ext_connection (connection_job_t CI, long long in_conn_id, connection_job_t CO, long long auth_key_id) {
  check_engine_class ();
  struct ext_connection *Ex = get_ext_connection_by_in_conn_id (CONN_INFO(CI)->fd, CONN_INFO(CI)->generation, in_conn_id, 2, 0);
  assert (Ex && "ext_connection already exists");
  assert (!Ex->out_fd && !Ex->o_next && !Ex->auth_key_id);
  assert (!CO || (unsigned) CONN_INFO(CO)->fd < MAX_CONNECTIONS);
  assert (CO != CI);
  if (CO) {
    struct ext_connection *H = &ExtConnectionHead[CONN_INFO(CO)->fd];
    assert (H->o_next);
    Ex->o_next = H;
    Ex->o_prev = H->o_prev;
    H->o_prev->o_next = Ex;
    H->o_prev = Ex;
    Ex->out_fd = CONN_INFO(CO)->fd;
    Ex->out_gen = CONN_INFO(CO)->generation;
  }
  Ex->auth_key_id = auth_key_id;
  return Ex;
}

static int _notify_remote_closed (JOB_REF_ARG(C), long long out_conn_id);

void remove_ext_connection (struct ext_connection *Ex, int send_notifications) {
  assert (Ex);
  assert (Ex->out_conn_id);
  assert (Ex == find_ext_connection_by_out_conn_id (Ex->out_conn_id));
  if (Ex->out_fd) {
    assert ((unsigned) Ex->out_fd < MAX_CONNECTIONS);
    assert (Ex->o_next);
    if (send_notifications & 1) {
      connection_job_t CO = connection_get_by_fd_generation (Ex->out_fd, Ex->out_gen);
      if (CO) {
	_notify_remote_closed (JOB_REF_PASS (CO), Ex->out_conn_id);
      }
    }
  }
  if (Ex->in_fd) {
    assert ((unsigned) Ex->in_fd < MAX_CONNECTIONS);
    assert (Ex->i_next);
    if (send_notifications & 2) {
      connection_job_t CI = connection_get_by_fd_generation (Ex->in_fd, Ex->in_gen);
      if (Ex->in_conn_id) {
	assert (0);
      } else {
	if (CI) {
	  fail_connection (CI, -33);
	  job_decref (JOB_REF_PASS (CI));
	}
      }
    }
  }
  assert (get_ext_connection_by_in_conn_id (Ex->in_fd, Ex->in_gen, Ex->in_conn_id, 1, 0) == (void *) -1L);
}

/* Stats globals and functions are in mtproto-proxy-stats.c */



/*
 *
 *      JOB UTILS
 *
 */

typedef int (*job_callback_func_t)(void *data, int len);
void schedule_job_callback (int context, job_callback_func_t func, void *data, int len);

struct job_callback_info {
  job_callback_func_t func;
  void *data[0];
};

int callback_job_run (job_t job, int op, struct job_thread *JT) {
  struct job_callback_info *D = (struct job_callback_info *)(job->j_custom);
  switch (op) {
  case JS_RUN:
    return D->func (D->data, job->j_custom_bytes - offsetof (struct job_callback_info, data));
    // return JOB_COMPLETED;
  case JS_FINISH:
    return job_free (JOB_REF_PASS (job));
  default:
    assert (0);
  }
}

void schedule_job_callback (int context, job_callback_func_t func, void *data, int len) {
  job_t job = create_async_job (callback_job_run, JSP_PARENT_RWE | JSC_ALLOW (context, JS_RUN) | JSIG_FAST (JS_FINISH), -2, offsetof (struct job_callback_info, data) + len, 0, JOB_REF_NULL);
  assert (job);
  struct job_callback_info *D = (struct job_callback_info *)(job->j_custom);
  D->func = func;
  memcpy (D->data, data, len);
  schedule_job (JOB_REF_PASS (job));
}


/*
 *
 *	RPC CLIENT
 *
 */

int mtfront_client_ready (connection_job_t C);
int mtfront_client_close (connection_job_t C, int who);
int rpcc_execute (connection_job_t C, int op, struct raw_message *msg);
int tcp_rpcc_check_ready (connection_job_t C);

struct tcp_rpc_client_functions mtfront_rpc_client = {
  .execute = rpcc_execute,
  .check_ready = tcp_rpcc_default_check_ready,
  .flush_packet = tcp_rpc_flush_packet,
  .rpc_check_perm = tcp_rpcc_default_check_perm,
  .rpc_init_crypto = tcp_rpcc_init_crypto,
  .rpc_start_crypto = tcp_rpcc_start_crypto,
  .rpc_ready = mtfront_client_ready,
  .rpc_close = mtfront_client_close
};

int rpcc_exists;

static int _notify_remote_closed (JOB_REF_ARG(C), long long out_conn_id) {
  TLS_START (JOB_REF_PASS(C)) {
    tl_store_int (RPC_CLOSE_CONN);
    tl_store_long (out_conn_id);
  } TLS_END;
  return 1;
}

void push_rpc_confirmation (JOB_REF_ARG (C), int confirm) {

  if ((lrand48_j() & 1) || !(TCP_RPC_DATA(C)->flags & RPC_F_PAD)) {
    struct raw_message *msg = malloc (sizeof (struct raw_message));
    rwm_create (msg, "\xdd", 1);
    rwm_push_data (msg, &confirm, 4);
    mpq_push_w (CONN_INFO(C)->out_queue, msg, 0);
    job_signal (JOB_REF_PASS (C), JS_RUN);
  } else {
    int x = -1;
    struct raw_message m;
    assert (rwm_create (&m, &x, 4) == 4);
    assert (rwm_push_data (&m, &confirm, 4) == 4);

    int z = lrand48_j() & 1;
    while (z-- > 0) {
      int t = lrand48_j();
      assert (rwm_push_data (&m, &t, 4) == 4);
    }

    tcp_rpc_conn_send (JOB_REF_CREATE_PASS (C), &m, 0);

    x = 0;
    assert (rwm_create (&m, &x, 4) == 4);

    z = lrand48_j() & 1;
    while (z-- > 0) {
      int t = lrand48_j();
      assert (rwm_push_data (&m, &t, 4) == 4);
    }

    tcp_rpc_conn_send (JOB_REF_PASS (C), &m, 0);
  }
}

struct client_packet_info {
  struct event_timer ev;
  struct raw_message msg;
  connection_job_t conn;
  int type;
};

int process_client_packet (struct tl_in_state *tlio_in, int op, connection_job_t C) {
  int len = tl_fetch_unread ();
  assert (op == tl_fetch_int ());

  switch (op) {
  case RPC_PONG:
    return 1;
  case RPC_PROXY_ANS:
    if (len >= 16) {
      int flags = tl_fetch_int ();
      long long out_conn_id = tl_fetch_long ();
      assert (tl_fetch_unread () == len - 16);
      vkprintf (2, "got RPC_PROXY_ANS from connection %d:%llx, data size = %d, flags = %d\n", CONN_INFO(C)->fd, out_conn_id, tl_fetch_unread (), flags);
      struct ext_connection *Ex = find_ext_connection_by_out_conn_id (out_conn_id);
      connection_job_t D = 0;
      if (Ex && Ex->out_fd == CONN_INFO(C)->fd && Ex->out_gen == CONN_INFO(C)->generation) {
	D = connection_get_by_fd_generation (Ex->in_fd, Ex->in_gen);
      }
      if (D) {
	vkprintf (2, "proxying answer into connection %d:%llx\n", Ex->in_fd, Ex->in_conn_id);
	tot_forwarded_responses++;
	client_send_message (JOB_REF_PASS(D), Ex->in_conn_id, tlio_in, flags);
      } else {
	vkprintf (2, "external connection not found, dropping proxied answer\n");
	dropped_responses++;
	_notify_remote_closed (JOB_REF_CREATE_PASS(C), out_conn_id);
      }
      return 1;
    }
    break;
  case RPC_SIMPLE_ACK:
    if (len == 16) {
      long long out_conn_id = tl_fetch_long ();
      int confirm = tl_fetch_int ();
      vkprintf (2, "got RPC_SIMPLE_ACK for connection = %llx, value %08x\n", out_conn_id, confirm);
      struct ext_connection *Ex = find_ext_connection_by_out_conn_id (out_conn_id);
      connection_job_t D = 0;
      if (Ex && Ex->out_fd == CONN_INFO(C)->fd && Ex->out_gen == CONN_INFO(C)->generation) {
	D = connection_get_by_fd_generation (Ex->in_fd, Ex->in_gen);
      }
      if (D) {
	vkprintf (2, "proxying simple ack %08x into connection %d:%llx\n", confirm, Ex->in_fd, Ex->in_conn_id);
	if (Ex->in_conn_id) {
	  assert (0);
	} else {
	  if (TCP_RPC_DATA(D)->flags & RPC_F_COMPACT) {
	    confirm = __builtin_bswap32 (confirm);
	  }
	  push_rpc_confirmation (JOB_REF_PASS (D), confirm);
	}
	tot_forwarded_simple_acks++;
      } else {
	vkprintf (2, "external connection not found, dropping simple ack\n");
	dropped_simple_acks++;
	_notify_remote_closed (JOB_REF_CREATE_PASS (C), out_conn_id);
      }
      return 1;
    }
    break;
  case RPC_CLOSE_EXT:
    if (len == 12) { 
      long long out_conn_id = tl_fetch_long ();
      vkprintf (2, "got RPC_CLOSE_EXT for connection = %llx\n", out_conn_id);
      struct ext_connection *Ex = find_ext_connection_by_out_conn_id (out_conn_id);
      if (Ex) {
	remove_ext_connection (Ex, 2);
      }
      return 1;
    }
    break;
  default:
    vkprintf (1, "unknown RPC operation %08x, ignoring\n", op);
  }

  return 0;
}

int client_packet_job_run (job_t job, int op, struct job_thread *JT) {
  struct client_packet_info *D = (struct client_packet_info *)(job->j_custom);
  
  switch (op) {
  case JS_RUN: {
    struct tl_in_state *tlio_in = tl_in_state_alloc ();
    tlf_init_raw_message (tlio_in, &D->msg, D->msg.total_bytes, 0);
    process_client_packet (tlio_in, D->type, D->conn);
    tl_in_state_free (tlio_in);
    return JOB_COMPLETED;
  }
  case JS_ALARM:
    if (!job->j_error) {
      job->j_error = ETIMEDOUT;
    }
    return JOB_COMPLETED;
  case JS_ABORT:
    if (!job->j_error) {
      job->j_error = ECANCELED;
    }
    return JOB_COMPLETED;
  case JS_FINISH:
    if (D->conn) {
      job_decref (JOB_REF_PASS (D->conn));
    }
    if (D->msg.magic) {
      rwm_free (&D->msg);
    }
    return job_free (JOB_REF_PASS (job));
  default:
    return JOB_ERROR;
  }
}

int rpcc_execute (connection_job_t C, int op, struct raw_message *msg) {
  vkprintf (2, "rpcc_execute: fd=%d, op=%08x, len=%d\n", CONN_INFO(C)->fd, op, msg->total_bytes);
  CONN_INFO(C)->last_response_time = precise_now;

  switch (op) {
  case RPC_PONG:
    break;
  case RPC_PROXY_ANS:
  case RPC_SIMPLE_ACK:
  case RPC_CLOSE_EXT: {
    job_t job = create_async_job (client_packet_job_run, JSP_PARENT_RWE | JSC_ALLOW (JC_ENGINE, JS_RUN) | JSC_ALLOW (JC_ENGINE, JS_ABORT) | JSC_ALLOW (JC_ENGINE, JS_ALARM) | JSC_ALLOW (JC_ENGINE, JS_FINISH), -2, sizeof (struct client_packet_info), JT_HAVE_TIMER, JOB_REF_NULL);
    struct client_packet_info *D = (struct client_packet_info *)(job->j_custom);
    D->msg = *msg;
    D->type = op;
    D->conn = job_incref (C);
    schedule_job (JOB_REF_PASS (job));
    return 1;
  }
  default:
    vkprintf (1, "unknown RPC operation %08x, ignoring\n", op);
  }
  return 0;
}

static inline int get_conn_tag (connection_job_t C) {
  return 1 + (CONN_INFO(C)->generation & 0xffffff);
}

int mtfront_client_ready (connection_job_t C) {
  check_engine_class ();
  struct tcp_rpc_data *D = TCP_RPC_DATA(C);
  int fd = CONN_INFO(C)->fd;
  assert ((unsigned) fd < MAX_CONNECTIONS);
  assert (!D->extra_int);
  D->extra_int = get_conn_tag (C);
  vkprintf (1, "Connected to RPC Middle-End (fd=%d)\n", fd);
  rpcc_exists++;

  struct ext_connection *H = &ExtConnectionHead[fd];
  assert (!H->o_prev);
  H->o_prev = H->o_next = H;
  H->out_fd = fd;

  CONN_INFO(C)->last_response_time = precise_now;
  return 0;
}

int mtfront_client_close (connection_job_t C, int who) {
  check_engine_class ();
  struct tcp_rpc_data *D = TCP_RPC_DATA(C);
  int fd = CONN_INFO(C)->fd;
  assert ((unsigned) fd < MAX_CONNECTIONS);
  vkprintf (1, "Disconnected from RPC Middle-End (fd=%d)\n", fd);
  if (D->extra_int) {
    assert (D->extra_int == get_conn_tag (C));
    struct ext_connection *H = &ExtConnectionHead[fd], *Ex, *Ex_next;
    assert (H->o_next);
    for (Ex = H->o_next; Ex != H; Ex = Ex_next) {
      Ex_next = Ex->o_next;
      assert (Ex->out_fd == fd);
      remove_ext_connection (Ex, 2);
    }
    assert (H->o_next == H && H->o_prev == H);
    H->o_next = H->o_prev = 0;
    H->out_fd = 0;
  }
  D->extra_int = 0;
  return 0;
}


/* HTTP interface moved to mtproto-proxy-http.c */


int mtproto_proxy_rpc_ready (connection_job_t C) {
  check_engine_class ();
  struct tcp_rpc_data *D = TCP_RPC_DATA(C);
  int fd = CONN_INFO(C)->fd;
  assert ((unsigned) fd < MAX_CONNECTIONS);
  vkprintf (3, "proxy_rpc connection ready (%d)\n", fd);
  struct ext_connection *H = &ExtConnectionHead[fd];
  assert (!H->i_prev);
  H->i_prev = H->i_next = H;
  H->in_fd = fd;
  assert (!D->extra_int);
  D->extra_int = -get_conn_tag(C);
  lru_insert_conn (C);
  return 0;
}

int mtproto_proxy_rpc_close (connection_job_t C, int who) {
  check_engine_class ();
  struct tcp_rpc_data *D = TCP_RPC_DATA(C);
  int fd = CONN_INFO(C)->fd;
  assert ((unsigned) fd < MAX_CONNECTIONS);
  vkprintf (3, "proxy_rpc connection closing (%d) by %d\n", fd, who);
  if (D->extra_int) {
    assert (D->extra_int == -get_conn_tag (C));
    struct ext_connection *H = &ExtConnectionHead[fd], *Ex, *Ex_next;
    assert (H->i_next);
    for (Ex = H->i_next; Ex != H; Ex = Ex_next) {
      Ex_next = Ex->i_next;
      assert (Ex->in_fd == fd);
      remove_ext_connection (Ex, 1);
    }
    assert (H->i_next == H && H->i_prev == H);
    H->i_next = H->i_prev = 0;
    H->in_fd = 0;
  }
  D->extra_int = 0;
  return 0;
}


/* HTTP interface functions are in mtproto-proxy-http.c */


/* ------------- process normal (encrypted) packet ----------------- */

// connection_job_t get_target_connection (conn_target_job_t S, int rotate);

conn_target_job_t choose_proxy_target (int target_dc) {
  assert (CurConf->auth_clusters > 0);
  struct mf_cluster *MFC = mf_cluster_lookup (CurConf, target_dc, 1);
  if (!MFC) {
    return 0;
  }
  int attempts = 5;
  while (attempts --> 0) {
    assert (MFC->targets_num > 0);
    conn_target_job_t S = MFC->cluster_targets[lrand48() % MFC->targets_num];
    connection_job_t C = 0;
    rpc_target_choose_random_connections (S, 0, 1, &C);
    if (C && TCP_RPC_DATA(C)->extra_int == get_conn_tag (C)) {
      job_decref (JOB_REF_PASS (C));
      return S;
    }
  }
  return 0;
}

static int forward_mtproto_enc_packet (struct tl_in_state *tlio_in, connection_job_t C, long long auth_key_id, int len, int remote_ip_port[5], int rpc_flags) {
  if (len < offsetof (struct encrypted_message, message) /*|| (len & 15) != (offsetof (struct encrypted_message, server_salt) & 15)*/) {
    return 0;
  }
  vkprintf (2, "received mtproto encrypted packet of %d bytes from connection %p (#%d~%d), key=%016llx\n", len, C, CONN_INFO(C)->fd, CONN_INFO(C)->generation, auth_key_id);

  CONN_INFO(C)->query_start_time = get_utime_monotonic ();

  conn_target_job_t S = choose_proxy_target (TCP_RPC_DATA(C)->extra_int4);

  assert (TL_IN_REMAINING == len);
  return forward_tcp_query (tlio_in, C, S, rpc_flags, auth_key_id, remote_ip_port, 0);
}

int forward_mtproto_packet (struct tl_in_state *tlio_in, connection_job_t C, int len, int remote_ip_port[5], int rpc_flags) {
  int header[7];
  if (len < sizeof (header) || (len & 3)) {
    return 0;
  }
  assert (tl_fetch_lookup_data (header, sizeof (header)) == sizeof (header));
  long long auth_key_id = *(long long *)header;
  if (auth_key_id) {
    return forward_mtproto_enc_packet (tlio_in, C, auth_key_id, len, remote_ip_port, rpc_flags);
  }
  vkprintf (2, "received mtproto packet of %d bytes\n", len);
  int inner_len = header[4];
  if (inner_len + 20 > len) {
    vkprintf (1, "received packet with bad inner length: %d (%d expected)\n", inner_len, len - 20);
    return 0;
  }
  if (inner_len < 20) {
    //must have at least function id and nonce
    return 0;
  }
  int function = header[5];
  if (function != CODE_req_pq && function != CODE_req_pq_multi && function != CODE_req_DH_params && function != CODE_set_client_DH_params) {
    return 0;
  }
  conn_target_job_t S = choose_proxy_target (TCP_RPC_DATA(C)->extra_int4);

  assert (len == TL_IN_REMAINING);
  return forward_tcp_query (tlio_in, C, S, 2 | rpc_flags, 0, remote_ip_port, 0);
}

/*
 *
 *	QUERY FORWARDING
 *
 */

/* ----------- query rpc forwarding ------------ */
 
int forward_tcp_query (struct tl_in_state *tlio_in, connection_job_t c, conn_target_job_t S, int flags, long long auth_key_id, int remote_ip_port[5], int our_ip_port[5]) {
  connection_job_t d = 0;
  int c_fd = CONN_INFO(c)->fd;
  struct ext_connection *Ex = get_ext_connection_by_in_fd (c_fd);

  if (CONN_INFO(c)->type == &ct_tcp_rpc_ext_server_mtfront) {
    flags |= TCP_RPC_DATA(c)->flags & RPC_F_DROPPED;
    flags |= 0x1000;
  } else if (CONN_INFO(c)->type == &ct_http_server_mtfront) {
    flags |= 0x3005;
  }

  if (Ex && Ex->auth_key_id != auth_key_id) {
    Ex->auth_key_id = auth_key_id;
  }

  if (Ex) {
    assert (Ex->out_fd > 0 && Ex->out_fd < MAX_CONNECTIONS);
    d = connection_get_by_fd_generation (Ex->out_fd, Ex->out_gen);
    if (!d || !CONN_INFO(d)->target) {
      if (d) {
	job_decref (JOB_REF_PASS (d));
      }
      remove_ext_connection (Ex, 1);
      Ex = 0;
    }
  }

  if (!d) {
    int attempts = 5;
    while (S && attempts --> 0) {
      rpc_target_choose_random_connections (S, 0, 1, &d);
      if (d) {
	if (TCP_RPC_DATA(d)->extra_int == get_conn_tag (d)) {
	  break;
	} else {
	  job_decref (JOB_REF_PASS (d));
	}
      }
    }
    if (!d) {
      vkprintf (2, "nowhere to forward user query from connection %d, dropping\n", CONN_INFO(c)->fd);
      dropped_queries++;
      if (CONN_INFO(c)->type == &ct_tcp_rpc_ext_server_mtfront) {
	__sync_fetch_and_or (&TCP_RPC_DATA(c)->flags, RPC_F_DROPPED);
      }
      return 0;
    }
    if (flags & RPC_F_DROPPED) {
      // there was at least one dropped inbound packet on this connection, have to close it now instead of forwarding next queries
      fail_connection (c, -35);
      return 0;
    }
    Ex = create_ext_connection (c, 0, d, auth_key_id);
  }

  tot_forwarded_queries++;

  assert (Ex);

  vkprintf (3, "forwarding user query from connection %d~%d (ext_conn_id %llx) into connection %d~%d (ext_conn_id %llx)\n", Ex->in_fd, Ex->in_gen, Ex->in_conn_id, Ex->out_fd, Ex->out_gen, Ex->out_conn_id);

  if (proxy_tag_set) {
    flags |= 8;
  }

  TLS_START (JOB_REF_PASS (d)); // open tlio_out context

  tl_store_int (RPC_PROXY_REQ);
  tl_store_int (flags);
  tl_store_long (Ex->out_conn_id);

  if (remote_ip_port) {
    tl_store_raw_data (remote_ip_port, 20);
  } else {
    if (CONN_INFO(c)->remote_ip) {
      tl_store_long (0);
      tl_store_int (-0x10000);
      tl_store_int (htonl (CONN_INFO(c)->remote_ip));
    } else {
      tl_store_raw_data (CONN_INFO(c)->remote_ipv6, 16);
    }
    tl_store_int (CONN_INFO(c)->remote_port);
  }

  if (our_ip_port) {
    tl_store_raw_data (our_ip_port, 20);
  } else {
    if (CONN_INFO(c)->our_ip) {
      tl_store_long (0);
      tl_store_int (-0x10000);
      tl_store_int (htonl (nat_translate_ip (CONN_INFO(c)->our_ip)));
    } else {
      tl_store_raw_data (CONN_INFO(c)->our_ipv6, 16);
    }
    tl_store_int (CONN_INFO(c)->our_port);
  }

  if (flags & 12) {
    int *extra_size_ptr = tl_store_get_ptr (4);
    int pos = TL_OUT_POS;
    if (flags & 8) {
      tl_store_int (TL_PROXY_TAG);
      tl_store_string (proxy_tag, sizeof (proxy_tag));
    }
    if (flags & 4) {
      tl_store_int (TL_HTTP_QUERY_INFO);
      tl_store_string (cur_http_origin, cur_http_origin_len >= 0 ? cur_http_origin_len : 0);
      tl_store_string (cur_http_referer, cur_http_referer_len >= 0 ? cur_http_referer_len : 0);
      tl_store_string (cur_http_user_agent, cur_http_user_agent_len >= 0 ? cur_http_user_agent_len : 0);
    }
    *extra_size_ptr = TL_OUT_POS - pos;
  }

  int len = TL_IN_REMAINING;
  assert (tl_copy_through (tlio_in, tlio_out, len, 1) == len);

  TLS_END;   // close tlio_out context

  if (CONN_INFO(c)->type == &ct_http_server_mtfront) {
    assert (CONN_INFO(c)->pending_queries >= 0);
    assert (CONN_INFO(c)->pending_queries > 0);
    assert (CONN_INFO(c)->pending_queries == 1);
    set_connection_timeout (c, HTTP_MAX_WAIT_TIMEOUT);
  }

  return 1;
}

/* -------------------------- EXTERFACE ---------------------------- */

struct tl_act_extra *mtfront_parse_function (struct tl_in_state *tlio_in, long long actor_id) {
  ++api_invoke_requests;
  if (actor_id != 0) {
    tl_fetch_set_error (TL_ERROR_WRONG_ACTOR_ID, "MTProxy only supports actor_id = 0");
    return 0;
  }
  int op = tl_fetch_int ();
  if (tl_fetch_error ()) {
    return 0;
  }
  switch (op) {
  default:
    tl_fetch_set_error_format (TL_ERROR_UNKNOWN_FUNCTION_ID, "Unknown op %08x", op);
    return 0;
  }
}


/* ------------------------ FLOOD CONTROL -------------------------- */

struct ext_connection ConnLRU = { .lru_prev = &ConnLRU, .lru_next = &ConnLRU };

void lru_delete_ext_conn (struct ext_connection *Ext) {
  if (Ext->lru_next) {
    Ext->lru_next->lru_prev = Ext->lru_prev;
    Ext->lru_prev->lru_next = Ext->lru_next;
  }
  Ext->lru_next = Ext->lru_prev = 0;
}

void lru_insert_ext_conn (struct ext_connection *Ext) {
  lru_delete_ext_conn (Ext);
  Ext->lru_prev = ConnLRU.lru_prev;
  Ext->lru_next = &ConnLRU;
  Ext->lru_next->lru_prev = Ext;
  Ext->lru_prev->lru_next = Ext;
}

void lru_delete_conn (connection_job_t c) {
  struct ext_connection *Ext = get_ext_connection_by_in_fd (CONN_INFO(c)->fd);
  if (Ext && Ext->in_fd == CONN_INFO(c)->fd) {
    lru_delete_ext_conn (Ext);
  }
}

void lru_insert_conn (connection_job_t c) {
  struct ext_connection *Ext = get_ext_connection_by_in_fd (CONN_INFO(c)->fd);
  if (Ext && Ext->in_fd == CONN_INFO(c)->fd && Ext->in_gen == CONN_INFO(c)->generation) {
    lru_insert_ext_conn (Ext);
  }
}

void check_all_conn_buffers (void) {
  struct buffers_stat bufs;
  fetch_buffers_stat (&bufs);
  long long max_buffer_memory = bufs.max_buffer_chunks * (long long) MSG_BUFFERS_CHUNK_SIZE;
  long long to_free = bufs.total_used_buffers_size - max_buffer_memory * 3/4;
  while (to_free > 0 && ConnLRU.lru_next != &ConnLRU) {
    struct ext_connection *Ext = ConnLRU.lru_next;
    vkprintf (2, "check_all_conn_buffers(): closing connection %d because of %lld total used buffer vytes (%lld max, %lld bytes to free)\n", Ext->in_fd, bufs.total_used_buffers_size, max_buffer_memory, to_free);
    connection_job_t d = connection_get_by_fd_generation (Ext->in_fd, Ext->in_gen);
    if (d) {
      int tot_used_bytes = CONN_INFO(d)->in.total_bytes + CONN_INFO(d)->in_u.total_bytes + CONN_INFO(d)->out.total_bytes + CONN_INFO(d)->out_p.total_bytes;
      to_free -= tot_used_bytes * 2;
      fail_connection (d, -500);
      job_decref (JOB_REF_PASS (d));
    }
    lru_delete_ext_conn (Ext);
    ++connections_failed_lru;
  }
}

int check_conn_buffers (connection_job_t c) {
  int tot_used_bytes = CONN_INFO(c)->in.total_bytes + CONN_INFO(c)->in_u.total_bytes + CONN_INFO(c)->out.total_bytes + CONN_INFO(c)->out_p.total_bytes;
  if (tot_used_bytes > MAX_CONNECTION_BUFFER_SPACE) {
    vkprintf (2, "check_conn_buffers(): closing connection %d because of %d buffer bytes used (%d max)\n", CONN_INFO(c)->fd, tot_used_bytes, MAX_CONNECTION_BUFFER_SPACE);
    fail_connection (c, -429);
    ++connections_failed_flood;
    return -1;
  }
  return 0;
}

// invoked in NET-CPU context!
int mtfront_data_received (connection_job_t c, int bytes_received) {
  // check_conn_buffers (c);
  return 0;
}

// invoked in NET-CPU context!
int mtfront_data_sent (connection_job_t c, int bytes_sent) {
  // lru_insert_conn (c);
  return 0;
}

void init_ct_server_mtfront (void) {
  assert (check_conn_functions (&ct_http_server, 1) >= 0);
  memcpy (&ct_http_server_mtfront, &ct_http_server, sizeof (conn_type_t));
  memcpy (&ct_tcp_rpc_ext_server_mtfront, &ct_tcp_rpc_ext_server, sizeof (conn_type_t));
  memcpy (&ct_tcp_rpc_server_mtfront, &ct_tcp_rpc_server, sizeof (conn_type_t));
  memcpy (&ct_tcp_rpc_client_mtfront, &ct_tcp_rpc_client, sizeof (conn_type_t));
  ct_http_server_mtfront.data_received = &mtfront_data_received;
  ct_tcp_rpc_ext_server_mtfront.data_received = &mtfront_data_received;
  ct_tcp_rpc_server_mtfront.data_received = &mtfront_data_received;
  ct_http_server_mtfront.data_sent = &mtfront_data_sent;
  ct_tcp_rpc_ext_server_mtfront.data_sent = &mtfront_data_sent;
  ct_tcp_rpc_server_mtfront.data_sent = &mtfront_data_sent;
}

/*
 *
 *	PARSE ARGS & INITIALIZATION
 *
 */

static void check_children_dead (void) {
  int i, j;
  for (j = 0; j < 11; j++) {
    for (i = 0; i < workers; i++) {
      if (pids[i]) {
        int status = 0;
        int res = waitpid (pids[i], &status, WNOHANG);
        if (res == pids[i]) {
          if (WIFEXITED (status) || WIFSIGNALED (status)) {
            pids[i] = 0;
          } else {
            break;
          }
        } else if (res == 0) {
          break;
        } else if (res != -1 || errno != EINTR) {
          pids[i] = 0;
        } else {
          break;
        }
      }
    }
    if (i == workers) {
      break;
    }
    if (j < 10) {
      usleep (100000);
    }
  }
  if (j == 11) {
    int cnt = 0;
    for (i = 0; i < workers; i++) {
      if (pids[i]) {
        ++cnt;
        kill (pids[i], SIGKILL);
      }
    }
    kprintf ("WARNING: %d children unfinished --> they are now killed\n", cnt);
  }
}

static void kill_children (int signal) {
  int i;
  assert (workers);
  for (i = 0; i < workers; i++) {
    if (pids[i]) {
      kill (pids[i], signal);
    }
  }
}

// SIGCHLD
void on_child_termination (void) {
}

void check_children_status (void) {
  if (workers) {
    int i;
    for (i = 0; i < workers; i++) {
      int status = 0;
      int res = waitpid (pids[i], &status, WNOHANG);
      if (res == pids[i]) {
        if (WIFEXITED (status) || WIFSIGNALED (status)) {
          kprintf ("Child %d terminated, aborting\n", pids[i]);
          pids[i] = 0;
          kill_children (SIGTERM);
          check_children_dead ();
          exit (EXIT_FAILURE);
        }
      } else if (res == 0) {
      } else if (res != -1 || errno != EINTR) {
        kprintf ("Child %d: unknown result during wait (%d, %m), aborting\n", pids[i], res);
        pids[i] = 0;
        kill_children (SIGTERM);
        check_children_dead ();
        exit (EXIT_FAILURE);
      }
    }
  } else if (slave_mode) {
    if (getppid () != parent_pid) {
      kprintf ("Parent %d is changed to %d, aborting\n", parent_pid, getppid ());
      exit (EXIT_FAILURE);
    }
  }
}

void check_special_connections_overflow (void) {
  if (max_special_connections && !slave_mode) {
    int max_user_conn = workers ? SumStats.conn.max_special_connections : max_special_connections;
    int cur_user_conn = workers ? SumStats.conn.active_special_connections : active_special_connections;
    if (cur_user_conn * 10 > max_user_conn * 9) {
      vkprintf (0, "CRITICAL: used %d user connections out of %d\n", cur_user_conn, max_user_conn);
    }
  }
}

void cron (void) {
  check_children_status ();
  compute_stats_sum ();
  check_special_connections_overflow ();
  check_all_conn_buffers ();
}

int sfd;
int http_ports_num;
int http_sfd[MAX_HTTP_LISTEN_PORTS], http_port[MAX_HTTP_LISTEN_PORTS];
int domain_count;
int secret_count;
static char *toml_config_path;
struct toml_config toml_cfg;

// static double next_create_outbound;
// int outbound_connections_per_second = DEFAULT_OUTBOUND_CONNECTION_CREATION_RATE;


/* Link page generation is in mtproto-proxy-stats.c */


/* Periodic sweeper that finishes draining secret slots — releases ones with
   no remaining connections, or force-closes stragglers past the timeout. */
static double drain_sweep_gw (void *unused) {
  int pinned = tcp_rpcs_get_ext_secret_pinned ();
  int cnt = tcp_rpcs_get_ext_secret_count ();
  double timeout = tcp_rpcs_drain_get_timeout ();
  for (int s = pinned; s < cnt; s++) {
    if (tcp_rpcs_get_ext_secret_state (s) != SLOT_DRAINING) { continue; }
    if (per_secret_connections[s] == 0) {
      tcp_rpcs_drain_release_slot_if_empty (s);
      continue;
    }
    if (timeout > 0 &&
        precise_now - tcp_rpcs_get_ext_secret_drain_started (s) >= timeout) {
      tcp_rpcs_drain_force_close_for_slot (s);
    }
  }
  return precise_now + 1.0;
}

void mtfront_pre_loop (void) {
  int i, enable_ipv6 = (ipv6_enabled && !engine_state->settings_addr.s_addr) ? SM_IPV6 : 0;
  if (domain_count == 0) {
    tcp_maximize_buffers = 1;
    if (window_clamp == 0) {
      window_clamp = DEFAULT_WINDOW_CLAMP;
    }
  }
  if (!workers) {
    for (i = 0; i < http_ports_num; i++) {
      init_listening_tcpv6_connection (http_sfd[i], &ct_tcp_rpc_ext_server_mtfront, &ext_rpc_methods, enable_ipv6 | SM_LOWPRIO | (domain_count == 0 ? SM_NOQACK : 0) | (max_special_connections ? SM_SPECIAL : 0));
      // assert (setsockopt (http_sfd[i], IPPROTO_TCP, TCP_MAXSEG, (int[]){1410}, sizeof (int)) >= 0);
      // assert (setsockopt (http_sfd[i], IPPROTO_TCP, TCP_NODELAY, (int[]){1}, sizeof (int)) >= 0);
      if (window_clamp) {
        listening_connection_job_t LC = Events[http_sfd[i]].data;
        assert (LC);
        LISTEN_CONN_INFO(LC)->window_clamp = window_clamp;
        if (setsockopt (http_sfd[i], IPPROTO_TCP, TCP_WINDOW_CLAMP, &window_clamp, 4) < 0) {
          vkprintf (0, "error while setting window size for socket #%d to %d: %m\n", http_sfd[i], window_clamp);
        }
      }
    }
    // create_all_outbound_connections ();
  }

  if (!slave_mode) {
    int probe_iv = 0;
    if (dc_probe_interval_from_cli >= 0) {
      probe_iv = dc_probe_interval_from_cli;
    } else if (toml_config_path && toml_cfg.dc_probe_interval >= 0) {
      probe_iv = toml_cfg.dc_probe_interval;
    }
    dc_probes_init (probe_iv);
    if (probe_iv > 0) {
      vkprintf (0, "DC probes: interval %d seconds\n", probe_iv);
    }
  }

  /* Drain sweeper — runs at 1 Hz on the engine thread, finishes releasing
     slots that lost their last connection and force-closes stragglers past
     drain_timeout_secs.  Each worker has its own sweeper since secret state
     is per-worker. */
  job_t drain_job = job_timer_alloc (JC_MAIN, drain_sweep_gw, NULL);
  job_timer_insert (drain_job, 1.0);
}

void precise_cron (void) {
  update_local_stats ();
}

static int mtfront_has_active_connections (void) {
  if (workers > 0 && !slave_mode) {
    return 1;
  }
  return active_special_connections > 0;
}

void mtfront_sigusr1_handler (void) {
  reopen_logs_ext (slave_mode);
  if (workers) {
    kill_children (SIGUSR1);
  }
}

static void apply_toml_secrets (struct toml_config *cfg) {
  unsigned char keys[TOML_CONFIG_MAX_SECRETS][16];
  char labels[TOML_CONFIG_MAX_SECRETS][EXT_SECRET_LABEL_MAX + 1];
  int limits[TOML_CONFIG_MAX_SECRETS];
  long long quotas[TOML_CONFIG_MAX_SECRETS];
  long long rate_limits[TOML_CONFIG_MAX_SECRETS];
  int max_ips[TOML_CONFIG_MAX_SECRETS];
  int64_t expires[TOML_CONFIG_MAX_SECRETS];

  for (int i = 0; i < cfg->secret_count; i++) {
    memcpy (keys[i], cfg->secrets[i].key, 16);
    snprintf (labels[i], sizeof (labels[i]), "%s", cfg->secrets[i].label);
    limits[i] = cfg->secrets[i].limit;
    quotas[i] = cfg->secrets[i].quota;
    rate_limits[i] = cfg->secrets[i].rate_limit;
    max_ips[i] = cfg->secrets[i].max_ips;
    expires[i] = cfg->secrets[i].expires;
  }

  tcp_rpcs_reload_ext_secrets (keys, labels, limits, quotas, rate_limits, max_ips, expires, cfg->secret_count);
  tcp_rpcs_drain_set_timeout ((double) cfg->drain_timeout_secs);
}

static void mtfront_sighup_handler (void) {
  if (!direct_mode) {
    int res = do_reload_config (0x4);
    if (res < 0) {
      fprintf (stderr, "config check failed! (code %d)\n", res);
    }
  }

  ip_acl_reload ();

  if (toml_config_path) {
    if (toml_config_reload (toml_config_path, &toml_cfg) == 0) {
      apply_toml_secrets (&toml_cfg);
    }
  }

  if (workers) {
    kill_children (SIGHUP);
  }
}

/*
 *
 *		MAIN
 *
 */

void usage (void) {
  printf ("usage: %s [options] [relay-config]\n", progname);
  printf ("       %s check [--config FILE] [--direct] [-S SECRET] [-D DOMAIN]\n", progname);
  printf ("       %s generate-secret [domain]\n", progname);
  printf ("%s\n", FullVersionStr);
  printf ("\tMTProto proxy for Telegram\n");
  printf ("\n");
  printf ("\tWith --config, all settings come from the TOML file.\n");
  printf ("\tThe [relay-config] positional arg is only needed in non-direct relay mode\n");
  printf ("\t(the binary config downloaded from Telegram, e.g. proxy-multi.conf).\n");
  printf ("\n");
  parse_usage ();
  exit (2);
}

server_functions_t mtproto_front_functions;
int f_parse_option (int val) {
  char *colon, *ptr;
  switch (val) {
  case 'C':
    max_special_connections = atoi (optarg);
    if (max_special_connections < 0) {
      max_special_connections = 0;
    }
    break;
  case 'W':
    window_clamp = atoi (optarg);
    break;
  case 'H':
    ptr = optarg;
    if (!*ptr) {
      usage ();
      return 2;
    }
    while (*ptr >= '1' && *ptr <= '9' && http_ports_num < MAX_HTTP_LISTEN_PORTS) {
      int i = http_port[http_ports_num++] = strtol (ptr, &colon, 10);
      assert (colon > ptr && i > 0 && i < 65536);
      ptr = colon;
      if (*ptr != ',') {
	break;
      } else {
	ptr++;
      }
    }
    if (*ptr) {
      usage ();
      return 2;
    }
    break;
    /*
  case 'o':
    outbound_connections_per_second = atoi (optarg);
    if (outbound_connections_per_second <= 0) {
      outbound_connections_per_second = 1;
    }
    break;
    */
  case 'M':
    workers = atoi (optarg);
    assert (workers >= 0 && workers <= MAX_WORKERS);
    break;
  case 'T':
    ping_interval = atof (optarg);
    if (ping_interval <= 0) {
      ping_interval = PING_INTERVAL;
    }
    break;
  case 2000:
    engine_set_http_fallback (&ct_http_server, &http_methods_stats);
    mtproto_front_functions.flags &= ~ENGINE_NO_PORT;
    break;
  case 'D':
    tcp_rpc_add_proxy_domain (optarg, NULL);
    domain_count++;
    break;
  case 'S':
  case 'P':
    {
      char *label = NULL;
      int hex_len;
      int conn_limit = 0;

      if (val == 'S') {
        char *colon = strchr (optarg, ':');
        if (colon) {
          hex_len = colon - optarg;
          label = colon + 1;

          /* Look for optional :LIMIT after label */
          char *colon2 = strchr (label, ':');
          if (colon2) {
            *colon2 = '\0';
            char *limit_str = colon2 + 1;
            if (*limit_str) {
              char *endp;
              long lv = strtol (limit_str, &endp, 10);
              if (*endp || lv < 1) {
                kprintf ("Invalid connection limit '%s' (must be a positive integer)\n", limit_str);
                usage ();
              }
              conn_limit = (int)lv;
            }
          }

          if (strlen (label) == 0) {
            label = NULL;
          } else if (strlen (label) > EXT_SECRET_LABEL_MAX) {
            kprintf ("Secret label too long (max %d chars)\n", EXT_SECRET_LABEL_MAX);
            usage ();
          } else {
            const char *p;
            for (p = label; *p; p++) {
              if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') || *p == '_' || *p == '-')) {
                kprintf ("Secret label contains invalid character '%c' (allowed: a-z, A-Z, 0-9, _, -)\n", *p);
                usage ();
              }
            }
          }
        } else {
          hex_len = strlen (optarg);
        }
      } else {
        hex_len = strlen (optarg);
      }

      if (hex_len != 32) {
        kprintf ("'%c' option requires exactly 32 hex digits\n", val);
        usage ();
      }

      unsigned char secret[16];
      int i;
      unsigned char b = 0;
      for (i = 0; i < 32; i++) {
        if (optarg[i] >= '0' && optarg[i] <= '9')  {
          b = b * 16 + optarg[i] - '0';
        } else if (optarg[i] >= 'a' && optarg[i] <= 'f') {
          b = b * 16 + optarg[i] - 'a' + 10;
        } else if (optarg[i] >= 'A' && optarg[i] <= 'F') {
          b = b * 16 + optarg[i] - 'A' + 10;
        } else {
          kprintf ("'S' option requires exactly 32 hex digits. '%c' is not hexdigit\n", optarg[i]);
          usage ();
        }
        if (i & 1) {
          secret[i / 2] = b;
          b = 0;
        }
      }
      if (val == 'S') {
	tcp_rpcs_set_ext_secret (secret, label, conn_limit, 0, 0, 0, 0);
	secret_count++;
      } else {
	memcpy (proxy_tag, secret, sizeof (proxy_tag));
	proxy_tag_set = 1;
      }
    }
    break;
  case 'R':
    tcp_rpcs_set_ext_rand_pad_only(1);
    break;
  case 2001:
    ip_acl_set_blocklist_file (optarg);
    break;
  case 2002:
    ip_acl_set_allowlist_file (optarg);
    break;
  case 2003:
    direct_mode = 1;
    break;
  case 2004:
    if (ip_acl_add_stats_net (optarg) < 0) {
      kprintf ("invalid CIDR for --stats-allow-net: %s\n", optarg);
      return 2;
    }
    break;
  case 2005:
    {
      /* Parse dc_id:host:port or dc_id:[ipv6]:port */
      char buf[256];
      int len = strlen (optarg);
      if (len >= (int)sizeof (buf)) {
        kprintf ("--dc-override argument too long: %s\n", optarg);
        return 2;
      }
      memcpy (buf, optarg, len + 1);

      char *colon1 = strchr (buf, ':');
      if (!colon1) {
        kprintf ("--dc-override: expected dc_id:host:port, got %s\n", optarg);
        return 2;
      }
      *colon1 = 0;
      int dc_id = atoi (buf);
      if (dc_id <= 0 || dc_id > 5) {
        kprintf ("--dc-override: dc_id must be 1-5, got %s\n", buf);
        return 2;
      }

      char *host_start = colon1 + 1;
      char *port_str;
      if (*host_start == '[') {
        /* IPv6: [addr]:port */
        char *bracket = strchr (host_start, ']');
        if (!bracket || bracket[1] != ':') {
          kprintf ("--dc-override: bad IPv6 format in %s\n", optarg);
          return 2;
        }
        *bracket = 0;
        host_start++;
        port_str = bracket + 2;
      } else {
        /* IPv4: host:port */
        char *last_colon = strrchr (host_start, ':');
        if (!last_colon) {
          kprintf ("--dc-override: expected host:port after dc_id in %s\n", optarg);
          return 2;
        }
        *last_colon = 0;
        port_str = last_colon + 1;
      }
      int port = atoi (port_str);
      if (port <= 0 || port > 65535) {
        kprintf ("--dc-override: bad port %s in %s\n", port_str, optarg);
        return 2;
      }
      if (direct_dc_override (dc_id, host_start, port) < 0) {
        kprintf ("--dc-override: failed to add %s (bad address or table full)\n", optarg);
        return 2;
      }
    }
    break;
  case 2006:
    toml_config_path = strdup (optarg);
    break;
  case 2007:
    if (socks5_set_proxy (optarg) < 0) {
      kprintf ("invalid SOCKS5 URL: %s\n", optarg);
      kprintf ("expected: socks5://[user:pass@]host:port\n");
      usage ();
    }
    break;
  case 2008:
    proxy_protocol_enabled = 1;
    break;
  case 2009:
    dc_probe_interval_from_cli = atoi (optarg);
    if (dc_probe_interval_from_cli < 0) {
      dc_probe_interval_from_cli = 0;
    }
    break;
  default:
    return -1;
  }
  return 0;
}

void mtfront_prepare_parse_options (void) {
  parse_option ("http-stats", no_argument, 0, 2000, "allow http server to answer on stats queries");
  parse_option ("mtproto-secret", required_argument, 0, 'S', "16-byte secret in hex, optionally :LABEL:LIMIT (e.g. -S abcdef01234567890abcdef012345678:myapp:1000)");
  parse_option ("proxy-tag", required_argument, 0, 'P', "16-byte proxy tag in hex mode to be passed along with all forwarded queries");
  parse_option ("domain", required_argument, 0, 'D', "adds allowed domain or host:port for TLS-transport mode, disables other transports; can be specified more than once");
  parse_option ("max-special-connections", required_argument, 0, 'C', "sets maximal number of accepted client connections per worker");
  parse_option ("window-clamp", required_argument, 0, 'W', "sets window clamp for client TCP connections");
  parse_option ("http-ports", required_argument, 0, 'H', "comma-separated list of client (HTTP) ports to listen");
  // parse_option ("outbound-connections-ps", required_argument, 0, 'o', "limits creation rate of outbound connections to mtproto-servers (default %d)", DEFAULT_OUTBOUND_CONNECTION_CREATION_RATE);
  parse_option ("slaves", required_argument, 0, 'M', "spawn several slave workers; not recommended for TLS-transport mode for better replay protection");
  parse_option ("ping-interval", required_argument, 0, 'T', "sets ping interval in second for local TCP connections (default %.3lf)", PING_INTERVAL);
  parse_option ("random-padding-only", no_argument, 0, 'R', "allow only clients with random padding option enabled");
  parse_option ("ip-blocklist", required_argument, 0, 2001, "path to file with CIDR ranges to reject");
  parse_option ("ip-allowlist", required_argument, 0, 2002, "path to file with CIDR ranges to exclusively allow");
  parse_option ("direct", no_argument, 0, 2003, "connect directly to Telegram DCs instead of through ME relays (incompatible with -P)");
  parse_option ("stats-allow-net", required_argument, 0, 2004, "CIDR range to allow stats access from, e.g. 100.64.0.0/10 (repeatable)");
  parse_option ("dc-override", required_argument, 0, 2005, "override DC address: dc_id:host:port or dc_id:[ipv6]:port (repeatable, direct mode)");
  parse_option ("config", required_argument, 0, 2006, "path to TOML config file (reloaded on SIGHUP for secrets/ACLs)");
  parse_option ("socks5", required_argument, 0, 2007, "route upstream DC connections through SOCKS5 proxy (socks5://[user:pass@]host:port)");
  parse_option ("proxy-protocol", no_argument, 0, 2008, "enable PROXY protocol v1/v2 on client listeners (for use behind HAProxy/nginx/NLB)");
  parse_option ("dc-probe-interval", required_argument, 0, 2009, "seconds between DC health probes (0=disabled, default 0)");
}

void mtfront_parse_extra_args (int argc, char *argv[]) /* {{{ */ {
  if (argc > 1) {
    usage ();
    exit (2);
  }
  if (argc == 1) {
    config_filename = argv[0];
    vkprintf (0, "config_filename = '%s'\n", config_filename);
  }
  if (!config_filename && !direct_mode && !toml_config_path) {
    kprintf ("error: relay mode requires a config file.\n"
             "  Use --config for TOML configuration, or --direct for direct mode.\n"
             "  Legacy: pass the binary relay config (proxy-multi.conf) as a positional argument.\n");
    exit (2);
  }
}

// executed BEFORE dropping privileges
void mtfront_pre_init (void) {
  /* Load TOML config early — sets direct_mode and other options */
  if (toml_config_path) {
    char errbuf[512];
    if (toml_config_load (toml_config_path, &toml_cfg, errbuf, sizeof (errbuf)) < 0) {
      kprintf ("config file error: %s\n", errbuf);
      exit (1);
    }
    vkprintf (0, "loaded config from %s\n", toml_config_path);

    /* Apply non-reloadable options (only if not already set via CLI) */
    if (!direct_mode && toml_cfg.direct == 1) {
      direct_mode = 1;
    }
    if (toml_cfg.proxy_tag[0] && !proxy_tag_set) {
      unsigned char tag[16];
      if (toml_config_parse_hex_secret (toml_cfg.proxy_tag, tag) == 0) {
        memcpy (proxy_tag, tag, 16);
        proxy_tag_set = 1;
      }
    }
    if (toml_cfg.http_stats == 1) {
      engine_set_http_fallback (&ct_http_server, &http_methods_stats);
      mtproto_front_functions.flags &= ~ENGINE_NO_PORT;
      engine_state->do_not_open_port = 0;
    }
    if (toml_cfg.random_padding_only == 1) {
      tcp_rpcs_set_ext_rand_pad_only (1);
    }
    if (toml_cfg.ip_blocklist[0]) {
      ip_acl_set_blocklist_file (toml_cfg.ip_blocklist);
    }
    if (toml_cfg.ip_allowlist[0]) {
      ip_acl_set_allowlist_file (toml_cfg.ip_allowlist);
    }
    for (int i = 0; i < toml_cfg.stats_allow_net_count; i++) {
      ip_acl_add_stats_net (toml_cfg.stats_allow_nets[i]);
    }
    for (int i = 0; i < toml_cfg.domain_count; i++) {
      tcp_rpc_add_proxy_domain (toml_cfg.domains[i].name,
                                toml_cfg.domains[i].backend[0] ? toml_cfg.domains[i].backend : NULL);
      domain_count++;
    }
    for (int i = 0; i < toml_cfg.dc_override_count; i++) {
      direct_dc_override (toml_cfg.dc_overrides[i].dc_id,
                          toml_cfg.dc_overrides[i].host,
                          toml_cfg.dc_overrides[i].port);
    }
    if (toml_cfg.port > 0 && http_ports_num == 0) {
      http_port[0] = toml_cfg.port;
      http_ports_num = 1;
    }
    if (toml_cfg.workers >= 0 && workers <= 0) {
      workers = toml_cfg.workers;
    }
    if (toml_cfg.max_connections > 0 && max_special_connections == 0) {
      max_special_connections = toml_cfg.max_connections;
    }
    if (toml_cfg.stats_port > 0 && engine_state->port <= 0) {
      engine_state->port = toml_cfg.stats_port;
    }
    if (toml_cfg.bind[0] && !engine_state->settings_addr.s_addr) {
      if (inet_pton (AF_INET, toml_cfg.bind, &engine_state->settings_addr) != 1) {
        kprintf ("config error: invalid bind address '%s'\n", toml_cfg.bind);
        exit (1);
      }
    }
    if (toml_cfg.socks5[0] && !socks5_is_enabled ()) {
      if (socks5_set_proxy (toml_cfg.socks5) < 0) {
        kprintf ("config error: invalid socks5 URL '%s'\n", toml_cfg.socks5);
        exit (1);
      }
    }
    if (toml_cfg.proxy_protocol == 1 && !proxy_protocol_enabled) {
      proxy_protocol_enabled = 1;
    }
    if (toml_cfg.ipv6 == 1) {
      engine_enable_ipv6 ();
    }
    if (toml_cfg.user[0] && !username) {
      username = toml_cfg.user;
    }
    if (toml_cfg.maxconn > 0 && !engine_state->maxconn_from_cli) {
      set_maxconn (toml_cfg.maxconn);
    }
  }

  if (engine_state->port > 0 && engine_state->do_not_open_port) {
    kprintf ("warning: stats_port is set but http_stats is not enabled — stats port will not open\n");
  }

  if (direct_mode && proxy_tag_set) {
    kprintf ("--direct and -P (proxy tag) are mutually exclusive\n");
    exit (2);
  }

  if (socks5_is_enabled () && !direct_mode) {
    kprintf ("--socks5 requires --direct mode\n");
    exit (2);
  }

  init_ct_server_mtfront ();

  if (!direct_mode) {
    int res = do_reload_config (0x26);

    if (res < 0) {
      fprintf (stderr, "config check failed! (code %d)\n", res);
      exit (-res);
    }

    vkprintf (1, "config loaded!\n");
  } else {
    vkprintf (0, "direct mode: connecting directly to Telegram DCs (no ME relay)\n");
  }

  if (ip_acl_reload () < 0) {
    kprintf ("failed to load IP ACL files\n");
    exit (1);
  }

  /* Pin CLI -S secrets, then load TOML secrets on top */
  tcp_rpcs_pin_ext_secrets ();
  if (toml_config_path && toml_cfg.secret_count > 0) {
    apply_toml_secrets (&toml_cfg);
    secret_count = tcp_rpcs_get_ext_secret_count ();
  }

  if (toml_config_path) {
    tcp_rpcs_set_top_ips_per_secret (toml_cfg.top_ips_per_secret);
    tcp_rpcs_drain_set_timeout ((double) toml_cfg.drain_timeout_secs);
  }

  if (domain_count) {
    tcp_rpc_init_proxy_domains();
    drs_delays_enabled = 1;

    if (workers) {
      kprintf ("It is recommended to not use workers with TLS-transport");
    }
    if (secret_count == 0) {
      kprintf ("You must specify at least one mtproto-secret to use when using TLS-transport");
      exit (2);
    }
  }

  ipv6_enabled = engine_check_ipv6_enabled ();
  if (direct_mode && !ipv6_enabled) {
    if (direct_dc_probe_ipv6 ()) {
      vkprintf (0, "direct mode: IPv6 connectivity detected, enabling automatically\n");
      ipv6_enabled = 1;
    }
  }
  int i, enable_ipv6 = (ipv6_enabled && !engine_state->settings_addr.s_addr) ? SM_IPV6 : 0;
  if (ipv6_enabled && !enable_ipv6) {
    vkprintf (0, "--address specifies an IPv4 bind address; keeping IPv4 listener (outbound IPv6 still active)\n");
  }

  for (i = 0; i < http_ports_num; i++) {
    http_sfd[i] = server_socket (http_port[i], engine_state->settings_addr, engine_get_backlog (), enable_ipv6);
    if (http_sfd[i] < 0) {
      kprintf ("cannot open http/tcp server socket at port %d: %m\n", http_port[i]);
      exit (1);
    }
  }

  if (workers) {
    if (!kdb_hosts_loaded) {
      kdb_load_hosts ();
    }
    WStats = mmap (0, 2 * workers * sizeof (struct worker_stats), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    assert (WStats);
    // kprintf_multiprocessing_mode_enable ();
    int real_parent_pid = getpid();
    vkprintf (0, "creating %d workers\n", workers);
    for (i = 0; i < workers; i++) {
      int pid = fork ();
      assert (pid >= 0);
      if (!pid) {
        worker_id = i;
        workers = 0;
        slave_mode = 1;
        parent_pid = getppid ();
        assert (parent_pid == real_parent_pid);
	engine_enable_slave_mode ();
	engine_state->do_not_open_port = 1;
        break;
      } else {
        pids[i] = pid;
      }
    }
  }

}

void mtfront_pre_start (void) {
  if (direct_mode) {
    return;
  }

  int res = do_reload_config (0x17);

  if (res < 0) {
    fprintf (stderr, "config check failed! (code %d)\n", res);
    exit (-res);
  }

  assert (CurConf->have_proxy);

  proxy_mode |= PROXY_MODE_OUT;
  mtfront_rpc_client.mode_flags |= TCP_RPC_IGNORE_PID;
  ct_tcp_rpc_client_mtfront.flags |= C_EXTERNAL;

  assert (proxy_mode == PROXY_MODE_OUT);
}

void mtfront_on_exit (void) {
  if (workers) {
    if (signal_check_pending (SIGTERM)) {
      kill_children (SIGTERM);
    }
    check_children_dead ();
  }
}

server_functions_t mtproto_front_functions = {
  .default_modules_disabled = 0,
  .cron = cron,
  .precise_cron = precise_cron,
  .has_active_connections = mtfront_has_active_connections,
  .pre_init = mtfront_pre_init,
  .pre_start = mtfront_pre_start,
  .pre_loop = mtfront_pre_loop,
  .on_exit = mtfront_on_exit,
  .prepare_stats = mtfront_prepare_stats,
  .parse_option = f_parse_option,
  .prepare_parse_options = mtfront_prepare_parse_options,
  .parse_extra_args = mtfront_parse_extra_args,
  .epoll_timeout = 1000,
  .FullVersionStr = FullVersionStr,
  .ShortVersionStr = "teleproxy",
  .parse_function = mtfront_parse_function,
  .flags = ENGINE_NO_PORT
  //.http_functions = &http_methods_stats
};

static int cmd_generate_secret (int argc, char *argv[]) {
  const char *domain = (argc > 0) ? argv[0] : NULL;

  unsigned char key[16];
  if (RAND_bytes (key, 16) != 1) {
    fprintf (stderr, "RAND_bytes failed\n");
    return 1;
  }

  char raw[33];
  int i;
  for (i = 0; i < 16; i++) {
    snprintf (raw + i * 2, 3, "%02x", key[i]);
  }
  raw[32] = '\0';

  if (domain) {
    char hex[1024];
    int pos = 0;
    pos += snprintf (hex + pos, sizeof (hex) - pos, "ee%s", raw);
    const unsigned char *d = (const unsigned char *)domain;
    while (*d) {
      int rem = (int)sizeof (hex) - pos;
      if (rem <= 0) break;
      int w = snprintf (hex + pos, rem, "%02x", *d);
      if (w < 0 || w >= rem) break;
      pos += w;
      d++;
    }
    printf ("%s\n", hex);
    fprintf (stderr, "Secret for -S:  %s\n", raw);
    fprintf (stderr, "Domain:         %s\n", domain);
  } else {
    printf ("%s\n", raw);
  }

  return 0;
}

int main (int argc, char *argv[]) {
  /* Subcommand dispatch — checked before engine init */
  if (argc >= 2 && !strcmp (argv[1], "check")) {
    return cmd_check (argc - 1, argv + 1);
  }
  if (argc >= 2 && !strcmp (argv[1], "link")) {
    return cmd_link (argc - 1, argv + 1);
  }
  if (argc >= 2 && !strcmp (argv[1], "generate-secret")) {
    return cmd_generate_secret (argc - 2, argv + 2);
  }

  /* Default: start the proxy server */
  mtproto_front_functions.allowed_signals |= SIG2INT (SIGCHLD);
  mtproto_front_functions.signal_handlers[SIGCHLD] = on_child_termination;
  mtproto_front_functions.signal_handlers[SIGUSR1] = mtfront_sigusr1_handler;
  mtproto_front_functions.signal_handlers[SIGHUP] = mtfront_sighup_handler;
  return default_main (&mtproto_front_functions, argc, argv);
}
