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
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "net/net-events.h"
#include "net/net-connections.h"
#include "net/net-tcp-connections.h"
#include "net/net-http-server.h"
#include "net/net-tcp-rpc-server.h"
#include "net/net-tcp-rpc-ext-server.h"
#include "net/net-ip-acl.h"
#include "net/net-msg.h"
#include "net/net-msg-buffers.h"
#include "kprintf.h"
#include "precise-time.h"
#include "server-functions.h"
#include "common/tl-parse.h"
#include "jobs/jobs.h"
#include "mtproto-common.h"
#include "mtproto-proxy-stats.h"
#include "mtproto-proxy-http.h"

#define	MAX_POST_SIZE	(262144 * 4 - 4096)

/* ext_connection struct is opaque to us; we only use pointers via helpers */
struct ext_connection;
extern struct ext_connection *get_ext_connection_by_in_fd (int in_fd);
extern void remove_ext_connection (struct ext_connection *Ex, int send_notifications);

extern conn_type_t ct_http_server_mtfront, ct_tcp_rpc_ext_server_mtfront;

extern char cur_http_origin[1024], cur_http_referer[1024], cur_http_user_agent[1024];
extern int cur_http_origin_len, cur_http_referer_len, cur_http_user_agent_len;

extern long long per_secret_connections[];

int check_conn_buffers (connection_job_t c);
void lru_insert_conn (connection_job_t c);

typedef int (*job_callback_func_t)(void *data, int len);
void schedule_job_callback (int context, job_callback_func_t func, void *data, int len);

int forward_mtproto_packet (struct tl_in_state *tlio_in, connection_job_t C, int len, int remote_ip_port[5], int rpc_flags);

/*
 *
 *	HTTP INTERFACE
 *
 */

int hts_execute (connection_job_t C, struct raw_message *msg, int op);
int mtproto_http_alarm (connection_job_t C);
int mtproto_http_close (connection_job_t C, int who);

int hts_stats_execute (connection_job_t C, struct raw_message *msg, int op);

struct http_server_functions http_methods = {
  .execute = hts_execute,
  .ht_alarm = mtproto_http_alarm,
  .ht_close = mtproto_http_close
};

struct http_server_functions http_methods_stats = {
  .execute = hts_stats_execute
};

int ext_rpcs_execute (connection_job_t C, int op, struct raw_message *msg);

int mtproto_ext_rpc_ready (connection_job_t C);
int mtproto_ext_rpc_close (connection_job_t C, int who);

struct tcp_rpc_server_functions ext_rpc_methods = {
  .execute = ext_rpcs_execute,
  .check_ready = server_check_ready,
  .flush_packet = tcp_rpc_flush_packet,
  .rpc_ready = mtproto_ext_rpc_ready,
  .rpc_close = mtproto_ext_rpc_close,
  //.http_fallback_type = &ct_http_server_mtfront,
  //.http_fallback_extra = &http_methods,
  .max_packet_len = MAX_POST_SIZE,
};

// ENGINE context
int do_close_in_ext_conn (void *_data, int s_len) {
  assert (s_len == 4);
  int fd = *(int *)_data;
  struct ext_connection *Ex = get_ext_connection_by_in_fd (fd);
  if (Ex) {
    remove_ext_connection (Ex, 1);
  }
  return JOB_COMPLETED;
}

// NET_CPU context
int mtproto_http_close (connection_job_t C, int who) {
  assert ((unsigned) CONN_INFO(C)->fd < MAX_CONNECTIONS);
  vkprintf (3, "http connection closing (%d) by %d, %d queries pending\n", CONN_INFO(C)->fd, who, CONN_INFO(C)->pending_queries);
  if (CONN_INFO(C)->pending_queries) {
    assert (CONN_INFO(C)->pending_queries == 1);
    pending_http_queries--;
    CONN_INFO(C)->pending_queries = 0;
  }
  schedule_job_callback (JC_ENGINE, do_close_in_ext_conn, &CONN_INFO(C)->fd, 4);
  return 0;
}

int mtproto_ext_rpc_ready (connection_job_t C) {
  assert ((unsigned) CONN_INFO(C)->fd < MAX_CONNECTIONS);
  vkprintf (3, "ext_rpc connection ready (%d)\n", CONN_INFO(C)->fd);
  /* Per-secret increment is NOT done here — this callback fires at connection
     acceptance, before the handshake identifies the secret (extra_int2 = 0).
     The increment happens in tcp_rpcs_compact_parse_execute after handshake. */
  lru_insert_conn (C);
  return 0;
}

int mtproto_ext_rpc_close (connection_job_t C, int who) {
  assert ((unsigned) CONN_INFO(C)->fd < MAX_CONNECTIONS);
  vkprintf (3, "ext_rpc connection closing (%d) by %d\n", CONN_INFO(C)->fd, who);
  int sid = TCP_RPC_DATA(C)->extra_int2;
  if (sid > 0 && sid <= EXT_SECRET_MAX_SLOTS) {
    per_secret_connections[sid - 1]--;
    tcp_rpcs_ip_track_disconnect (sid - 1, CONN_INFO(C)->remote_ip, CONN_INFO(C)->remote_ipv6);
    tcp_rpcs_account_disconnect (sid - 1, CONN_INFO(C)->remote_ip, CONN_INFO(C)->remote_ipv6);
  }
  struct ext_connection *Ex = get_ext_connection_by_in_fd (CONN_INFO(C)->fd);
  if (Ex) {
    remove_ext_connection (Ex, 1);
  }
  return 0;
}

char mtproto_cors_http_headers[] =
	"Access-Control-Allow-Origin: *\r\n"
	"Access-Control-Allow-Methods: POST, OPTIONS\r\n"
	"Access-Control-Allow-Headers: origin, content-type\r\n"
	"Access-Control-Max-Age: 1728000\r\n";

int forward_tcp_query (struct tl_in_state *tlio_in, connection_job_t C, conn_target_job_t S, int flags, long long auth_key_id, int remote_ip_port[5], int our_ip_port[5]);

unsigned parse_text_ipv4 (char *str) {
  int a, b, c, d;
  if (sscanf (str, "%d.%d.%d.%d", &a, &b, &c, &d) != 4) {
    return 0;
  }
  if ((a | b | c | d) & -0x100) {
    return 0;
  }
  return (a << 24) | (b << 16) | (c << 8) | d;
}

int parse_text_ipv6 (unsigned char ip[16], const char *str) {
  const char *ptr = str;
  int i, k = -1;
  if (*ptr == ':' && ptr[1] == ':') {
    k = 0;
    ptr += 2;
  }
  for (i = 0; i < 8; i++) {
    int c = *ptr;
    if (i > 0) {
      if (c == ':') {
	c = *++ptr;
      } else if (k >= 0) {
	break;
      } else {
	return -1; // ':' expected
      }
      if (c == ':') {
	if (k >= 0) {
	  return -1; // second '::'
	}
	k = i;
	c = *++ptr;
      }
    }
    int j = 0, v = 0;
    while ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')) {
      c |= 0x20;
      v = (v << 4) + (c <= '9' ? c - '0' : c - 'a' + 10);
      if (++j > 4) {
	return -1; // more than 4 hex digits in component
      }
      c = *++ptr;
    }
    if (!j) {
      if (k == i) {
	break;
      }
      return -1; // hex digit or ':' expected
    }
    ip[2*i] = (v >> 8);
    ip[2*i+1] = (v & 0xff);
  }
  if (*ptr) {
    return -1;
  }
  /*
  if (*ptr && *ptr != '/' && *ptr != ' ' && *ptr != '\n' && *ptr != '\r' && *ptr != '\t') {
    return -1; // extra characters
  }
  */
  if (i < 8) {
    assert (k >= 0 && k <= i);
    int gap = 2 * (8 - i);
    memmove (ip + 2*k + gap, ip + 2*k, 2 * (i - k));
    memset (ip + 2*k, 0, gap);
  }
  return ptr - str;
}

struct http_query_info {
  struct event_timer ev;
  connection_job_t conn;
  struct raw_message msg;
  int conn_fd;
  int conn_generation;
  int flags;
  int query_type;
  int header_size;
  int data_size;
  int first_line_size;
  int host_offset;
  int host_size;
  int uri_offset;
  int uri_size;
  char header[0];
};

int process_http_query (struct tl_in_state *tlio_in, job_t HQJ) {
  struct http_query_info *D = (struct http_query_info *) HQJ->j_custom;
  connection_job_t c = D->conn;
  char *qHeaders = D->header + D->first_line_size;
  int qHeadersLen = D->header_size - D->first_line_size;

  assert (D->first_line_size > 0 && D->first_line_size <= D->header_size);

  if (verbosity > 1) {
    fprintf (stderr, "===============\n%.*s\n==============\n", D->header_size, D->header);
    fprintf (stderr, "%d,%d,%d,%d\n", D->host_offset, D->host_size, D->uri_offset, D->uri_size);

    fprintf (stderr, "hostname: '%.*s'\n", D->host_size, D->header + D->host_offset);
    fprintf (stderr, "URI: '%.*s'\n", D->uri_size, D->header + D->uri_offset);
  }

  if (verbosity >= 2) {
    char PostPreview[81];
    int preview_len = (D->data_size < sizeof (PostPreview) ? D->data_size : sizeof(PostPreview) - 1);
    tl_fetch_lookup_data (PostPreview, preview_len);
    PostPreview[preview_len] = 0;
    kprintf ("have %d POST bytes: `%.80s`\n", D->data_size, PostPreview);
  }

  char *qUri = D->header + D->uri_offset;
  int qUriLen = D->uri_size;

  char *get_qm_ptr = memchr (qUri, '?', D->uri_size);
  if (get_qm_ptr) {
    // qGet = get_qm_ptr + 1;
    // qGetLen = qUri + qUriLen - qGet;
    qUriLen = get_qm_ptr - qUri;
  } else {
    // qGet = 0;
    // qGetLen = 0;
  }

  if (qUriLen >= 20) {
    return -414;
  }

  if (qUriLen >= 4 && !memcmp (qUri, "/api", 4)) {
    if (qUriLen >= 5 && qUri[4] == 'w') {
      HTS_DATA(c)->query_flags |= QF_EXTRA_HEADERS;
      extra_http_response_headers = mtproto_cors_http_headers;
    } else {
      HTS_DATA(c)->query_flags &= ~QF_EXTRA_HEADERS;
    }
    if (D->query_type == htqt_options) {
      char response_buffer[512];
      int len = snprintf (response_buffer, 511, "HTTP/1.1 200 OK\r\nConnection: %s\r\nContent-type: text/plain\r\nPragma: no-cache\r\nCache-control: no-store\r\n%sContent-length: 0\r\n\r\n", (HTS_DATA(c)->query_flags & QF_KEEPALIVE) ? "keep-alive" : "close", HTS_DATA(c)->query_flags & QF_EXTRA_HEADERS ? mtproto_cors_http_headers : "");
      assert (len < 511);
      struct raw_message *m = calloc (sizeof (struct raw_message), 1);
      rwm_create (m, response_buffer, len);
      http_flush (c, m);
      return 0;
    }
    if (D->data_size & 3) {
      return -404;
    }
    cur_http_origin_len = get_http_header (qHeaders, qHeadersLen, cur_http_origin, sizeof (cur_http_origin) - 1, "Origin", 6);
    cur_http_referer_len = get_http_header (qHeaders, qHeadersLen, cur_http_referer, sizeof (cur_http_referer) - 1, "Referer", 7);
    cur_http_user_agent_len = get_http_header (qHeaders, qHeadersLen, cur_http_user_agent, sizeof (cur_http_user_agent) - 1, "User-Agent", 10);

    int tmp_ip_port[5], *remote_ip_port = 0;
    if ((CONN_INFO(c)->remote_ip & 0xff000000) == 0x0a000000 || (CONN_INFO(c)->remote_ip & 0xff000000) == 0x7f000000) {
      char x_real_ip[64], x_real_port[16];
      int x_real_ip_len = get_http_header (qHeaders, qHeadersLen, x_real_ip, sizeof (x_real_ip) - 1, "X-Real-IP", 9);
      int x_real_port_len = get_http_header (qHeaders, qHeadersLen, x_real_port, sizeof (x_real_port) - 1, "X-Real-Port", 11);
      if (x_real_ip_len > 0) {
	unsigned real_ip = parse_text_ipv4 (x_real_ip);
	if (real_ip >= (1 << 24) || parse_text_ipv6 ((unsigned char *)tmp_ip_port, x_real_ip) > 0) {
	  if (real_ip >= (1 << 24)) {
	    tmp_ip_port[0] = 0;
	    tmp_ip_port[1] = 0;
	    tmp_ip_port[2] = 0xffff0000;
	    tmp_ip_port[3] = htonl (real_ip);
	  }
	  int port = (x_real_port_len > 0 ? atoi (x_real_port) : 0);
	  tmp_ip_port[4] = (port > 0 && port < 65536 ? port : 0);
	  remote_ip_port = tmp_ip_port;
	  vkprintf (3, "set remote IPv6:port to %08x:%08x:%08x:%08x:%08x according to X-Real-Ip '%s', X-Real-Port '%s'\n", tmp_ip_port[0], tmp_ip_port[1], tmp_ip_port[2], tmp_ip_port[3], tmp_ip_port[4], x_real_ip, x_real_port_len > 0 ? x_real_port : "");
	}
      }
    }

    int res = forward_mtproto_packet (tlio_in, c, D->data_size, remote_ip_port, 0);
    return res ? 1 : -404;
  }

  return -404;
}

int http_query_job_run (job_t job, int op, struct job_thread *JT) {
  struct http_query_info *HQ = (struct http_query_info *)(job->j_custom);

  switch (op) {
  case JS_RUN: { // ENGINE context
    lru_insert_conn (HQ->conn);
    struct tl_in_state *tlio_in = tl_in_state_alloc ();
    tlf_init_raw_message (tlio_in, &HQ->msg, HQ->msg.total_bytes, 0);
    int res = process_http_query (tlio_in, job);
    tl_in_state_free (tlio_in);
    assert (!HQ->msg.magic);
    //rwm_free (&HQ->msg);
    if (res < 0) {
      write_http_error (HQ->conn, -res);
    } else if (res > 0) {
      assert (HQ->flags & 1);
      HQ->flags &= ~1;
    }
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
  case JS_FINISH: // NET-CPU
    if (HQ->flags & 1) {
      connection_job_t c = HQ->conn ? job_incref (HQ->conn): connection_get_by_fd_generation (HQ->conn_fd, HQ->conn_generation);
      if (c) {
	assert (CONN_INFO(c)->pending_queries == 1);
	CONN_INFO(c)->pending_queries--;
	if (!(HTS_DATA(c)->query_flags & QF_KEEPALIVE) && CONN_INFO(c)->status == conn_working) {
	  connection_write_close (c);
	}
	job_decref (JOB_REF_PASS (c));
      }
      --pending_http_queries;
      HQ->flags &= ~1;
    }
    if (HQ->conn) {
      job_decref (JOB_REF_PASS (HQ->conn));
    }
    if (HQ->msg.magic) {
      rwm_free (&HQ->msg);
    }
    return job_free (JOB_REF_PASS (job));
  default:
    return JOB_ERROR;
  }
}

static inline int is_private_ip (unsigned ip) {
  return (ip >> 24) == 127       // 127.0.0.0/8
      || (ip >> 24) == 10        // 10.0.0.0/8
      || (ip >> 20) == 0xAC1     // 172.16.0.0/12
      || (ip >> 16) == 0xC0A8;   // 192.168.0.0/16
}

int hts_stats_execute (connection_job_t c, struct raw_message *msg, int op) {
  struct hts_data *D = HTS_DATA(c);

  // lru_insert_conn (c); // dangerous in net-cpu context
  if (check_conn_buffers (c) < 0) {
    return -429;
  }

  if (op != htqt_get || D->data_size != -1) {
    D->query_flags &= ~QF_KEEPALIVE;
    return -501;
  }
  if (!is_private_ip(CONN_INFO(c)->remote_ip) && !ip_acl_check_stats_v4(CONN_INFO(c)->remote_ip)) {
    return -404;
  }

  char ReqHdr[MAX_HTTP_HEADER_SIZE];
  assert (rwm_fetch_data (msg, &ReqHdr, D->header_size) == D->header_size);

  int is_stats = (D->uri_size == 6 && !memcmp (ReqHdr + D->uri_offset, "/stats", 6));
  int is_metrics = (D->uri_size == 8 && !memcmp (ReqHdr + D->uri_offset, "/metrics", 8));
  int is_link = (D->uri_size == 5 && !memcmp (ReqHdr + D->uri_offset, "/link", 5));

  if (!is_stats && !is_metrics && !is_link) {
    return -404;
  }

  stats_buffer_t sb;
  sb_alloc(&sb, 1 << 20);

  const char *content_type;
  if (is_link) {
    mtfront_prepare_link_page (&sb, ReqHdr + D->host_offset, D->host_size);
    content_type = "text/html; charset=utf-8";
  } else if (is_metrics) {
    mtfront_prepare_prometheus_stats(&sb);
    content_type = "text/plain; version=0.0.4; charset=utf-8";
  } else {
    mtfront_prepare_stats(&sb);
    content_type = "text/plain";
  }

  struct raw_message *raw = calloc (sizeof (*raw), 1);
  rwm_init (raw, 0);
  write_basic_http_header_raw (c, raw, 200, 0, sb.pos, 0, content_type);
  if (rwm_push_data (raw, sb.buff, sb.pos) != sb.pos) {
    rwm_free (raw);
    free (raw);
    sb_release (&sb);
    return -1;
  }
  mpq_push_w (CONN_INFO(c)->out_queue, raw, 0);
  job_signal (JOB_REF_CREATE_PASS (c), JS_RUN);

  sb_release (&sb);

  return 0;
}

// NET-CPU context
int hts_execute (connection_job_t c, struct raw_message *msg, int op) {
  struct hts_data *D = HTS_DATA(c);
  vkprintf (2, "in hts_execute: connection #%d, op=%d, header_size=%d, data_size=%d, http_version=%d\n",
	    CONN_INFO(c)->fd, op, D->header_size, D->data_size, D->http_ver);
  rwm_dump(msg);

  fail_connection(c, -1);
  return 0;
  // lru_insert_conn (c); // dangerous in net-cpu context
  if (check_conn_buffers (c) < 0) {
    return -429;
  }

  if (D->data_size >= MAX_POST_SIZE) {
    return -413;
  }

  if (!((D->query_type == htqt_post && D->data_size > 0) || (D->query_type == htqt_options && D->data_size < 0))) {
    D->query_flags &= ~QF_KEEPALIVE;
    return -501;
  }

  if (D->data_size < 0) {
    D->data_size = 0;
  }

  if (D->uri_size > 14 || D->header_size > MAX_HTTP_HEADER_SIZE) {
    return -414;
  }

  if (D->data_size > 0) {
    int need_bytes = D->data_size + D->header_size - msg->total_bytes;
    if (need_bytes > 0) {
      vkprintf (2, "-- need %d more bytes, waiting\n", need_bytes);
      return need_bytes;
    }
  }

  assert (msg->total_bytes == D->header_size + D->data_size);

  // create http query job here
  job_t job = create_async_job (http_query_job_run, JSP_PARENT_RWE | JSC_ALLOW (JC_ENGINE, JS_RUN) | JSC_ALLOW (JC_ENGINE, JS_ABORT) | JSC_ALLOW (JC_ENGINE, JS_ALARM) | JSC_ALLOW (JC_CONNECTION, JS_FINISH), -2, sizeof (struct http_query_info) + D->header_size + 1, JT_HAVE_TIMER, JOB_REF_NULL);
  assert (job);
  struct http_query_info *HQ = (struct http_query_info *)(job->j_custom);

  rwm_clone (&HQ->msg, msg);
  HQ->conn = job_incref (c);
  HQ->conn_fd = CONN_INFO(c)->fd;
  HQ->conn_generation = CONN_INFO(c)->generation;
  HQ->flags = 1;  // pending_queries
  assert (!CONN_INFO(c)->pending_queries);
  CONN_INFO(c)->pending_queries++;
  ++pending_http_queries;
  HQ->query_type = D->query_type;
  HQ->header_size = D->header_size;
  HQ->data_size = D->data_size;
  HQ->first_line_size = D->first_line_size;
  HQ->host_offset = D->host_offset;
  HQ->host_size = D->host_size;
  HQ->uri_offset = D->uri_offset;
  HQ->uri_size = D->uri_size;
  assert (rwm_fetch_data (&HQ->msg, HQ->header, HQ->header_size) == HQ->header_size);
  HQ->header[HQ->header_size] = 0;
  assert (HQ->msg.total_bytes == HQ->data_size);

  schedule_job (JOB_REF_PASS (job));
  return 0;
}

struct rpcs_exec_data {
  struct raw_message msg;
  connection_job_t conn;
  int op;
  int rpc_flags;
};

int do_rpcs_execute (void *_data, int s_len) {
  struct rpcs_exec_data *data = _data;
  assert (s_len == sizeof (struct rpcs_exec_data));
  assert (data);

  lru_insert_conn (data->conn);

  int len = data->msg.total_bytes;
  struct tl_in_state *tlio_in = tl_in_state_alloc ();
  tlf_init_raw_message (tlio_in, &data->msg, len, 0);

  int res = forward_mtproto_packet (tlio_in, data->conn, len, 0, data->rpc_flags);
  tl_in_state_free (tlio_in);
  job_decref (JOB_REF_PASS (data->conn));

  if (!res) {
    vkprintf (1, "ext_rpcs_execute: cannot forward mtproto packet\n");
  }
  return JOB_COMPLETED;
}


int ext_rpcs_execute (connection_job_t c, int op, struct raw_message *msg) {
  int len = msg->total_bytes;

  vkprintf (2, "ext_rpcs_execute: fd=%d, op=%08x, len=%d\n", CONN_INFO(c)->fd, op, len);

  if (len > MAX_POST_SIZE) {
    vkprintf (1, "ext_rpcs_execute: packet too long (%d bytes), skipping\n", len);
    return SKIP_ALL_BYTES;
  }

  // lru_insert_conn (c); // dangerous in net-cpu context
  if (check_conn_buffers (c) < 0) {
    return SKIP_ALL_BYTES;
  }

  struct rpcs_exec_data data;
  rwm_move (&data.msg, msg);
  data.conn = job_incref (c);
  data.rpc_flags = TCP_RPC_DATA(c)->flags & (RPC_F_QUICKACK | RPC_F_DROPPED | RPC_F_COMPACT_MEDIUM | RPC_F_EXTMODE3);

  schedule_job_callback (JC_ENGINE, do_rpcs_execute, &data, sizeof (struct rpcs_exec_data));

  return 1;
}

// NET-CPU context
int mtproto_http_alarm (connection_job_t C) {
  vkprintf (2, "http_alarm() for connection %d\n", CONN_INFO(C)->fd);

  assert (CONN_INFO(C)->status == conn_working);
  HTS_DATA(C)->query_flags &= ~QF_KEEPALIVE;

  write_http_error (C, 500);

  if (CONN_INFO(C)->pending_queries) {
    assert (CONN_INFO(C)->pending_queries == 1);
    --pending_http_queries;
    CONN_INFO(C)->pending_queries = 0;
  }

  HTS_DATA(C)->parse_state = -1;
  connection_write_close (C);

  return 0;
}

// NET-CPU context
int finish_postponed_http_response (void *_data, int len) {
  assert (len == sizeof (connection_job_t));
  connection_job_t C = *(connection_job_t *)_data;
  if (!check_job_completion (C)) {
    assert (CONN_INFO(C)->pending_queries >= 0);
    assert (CONN_INFO(C)->pending_queries > 0);
    assert (CONN_INFO(C)->pending_queries == 1);
    CONN_INFO(C)->pending_queries = 0;
    --pending_http_queries;
    // check_conn_buffers (C);
    http_flush (C, 0);
  } else {
    assert (!CONN_INFO(C)->pending_queries);
  }
  job_decref (JOB_REF_PASS (C));
  return JOB_COMPLETED;
}

// ENGINE context
// problem: mtproto_http_alarm() may be invoked in parallel in NET-CPU context
int http_send_message (JOB_REF_ARG (C), struct tl_in_state *tlio_in, int flags) {
  clear_connection_timeout (C);
  struct hts_data *D = HTS_DATA(C);

  if ((flags & 0x10) && TL_IN_REMAINING == 4) {
    int error_code = tl_fetch_int ();
    D->query_flags &= ~QF_KEEPALIVE;
    write_http_error (C, -error_code);
  } else {
    char response_buffer[512];
    TLS_START_UNALIGN (JOB_REF_CREATE_PASS (C)) {
      int len = TL_IN_REMAINING;
      tl_store_raw_data (response_buffer, snprintf (response_buffer, sizeof (response_buffer) - 1, "HTTP/1.1 200 OK\r\nConnection: %s\r\nContent-type: application/octet-stream\r\nPragma: no-cache\r\nCache-control: no-store\r\n%sContent-length: %d\r\n\r\n", (D->query_flags & QF_KEEPALIVE) ? "keep-alive" : "close", D->query_flags & QF_EXTRA_HEADERS ? mtproto_cors_http_headers : "", len));
      assert (tl_copy_through (tlio_in, tlio_out, len, 1) == len);
    } TLS_END;
  }

  assert (CONN_INFO(C)->status == conn_working && CONN_INFO(C)->pending_queries == 1);

  assert ((unsigned) CONN_INFO(C)->fd < MAX_CONNECTIONS);
  vkprintf (3, "detaching http connection (%d)\n", CONN_INFO(C)->fd);

  struct ext_connection *Ex = get_ext_connection_by_in_fd (CONN_INFO(C)->fd);
  if (Ex) {
    remove_ext_connection (Ex, 1);
  }

  // reference to C is passed to the new job
  schedule_job_callback (JC_CONNECTION, finish_postponed_http_response, &C, sizeof (connection_job_t));

  return 1;
}

int client_send_message (JOB_REF_ARG(C), long long in_conn_id, struct tl_in_state *tlio_in, int flags) {
  if (check_conn_buffers (C) < 0) {
    job_decref (JOB_REF_PASS (C));
    return -1;
  }
  if (in_conn_id) {
    assert (0);
    return 1;
  }

  if (CONN_INFO(C)->type == &ct_http_server_mtfront) {
    return http_send_message (JOB_REF_PASS(C), tlio_in, flags);
  }
  TLS_START (JOB_REF_CREATE_PASS (C)) {
    assert (tl_copy_through (tlio_in, tlio_out, TL_IN_REMAINING, 1) >= 0);
  } TLS_END;

  if (check_conn_buffers (C) < 0) {
    job_decref (JOB_REF_PASS (C));
    return -1;
  } else {
    job_decref (JOB_REF_PASS (C));
    return 1;
  }
}
