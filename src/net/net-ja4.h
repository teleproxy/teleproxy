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

#pragma once

#include <stdint.h>

#include "common/common-stats.h"

/* JA4 string is always exactly 36 chars: "t13d1516h2_xxxxxxxxxxxx_xxxxxxxxxxxx". */
#define JA4_HASH_BUF       37
#define WORKER_TOP_JA4_MAX 32

struct worker_top_ja4 {
  char hash[JA4_HASH_BUF];
  uint64_t count;
};

/*
 *  Compute the JA4 fingerprint for a TLS 1.3 ClientHello buffer.  On
 *  success returns 0 and writes a NUL-terminated 36-char string into out;
 *  returns -1 if the ClientHello is malformed.
 */
int ja4_compute (const unsigned char *client_hello, int len, char out[JA4_HASH_BUF]);

/*
 *  Parse the ClientHello, record its JA4 in the worker-local top-N table,
 *  and (if toml_cfg.ja4_log is set) print one ja4=... sni=... line at
 *  vkprintf level 2.  Safe to call on malformed buffers.
 */
void ja4_observe (const unsigned char *client_hello, int len);

/*
 *  Copy the worker-local top-N table into the caller's buffer.  Used by
 *  update_local_stats_copy to publish into shared worker_stats memory.
 *  Empty slots have count == 0 and an empty hash string.
 */
void ja4_snapshot (struct worker_top_ja4 *out, int *count_out, int max);

/*
 *  Master-side helpers, called from mtproto-proxy-stats.c.  reset() clears
 *  the master accumulator, merge() folds one worker's snapshot into it,
 *  dump_stats / dump_prometheus emit the sorted result.
 */
void ja4_master_reset      (void);
void ja4_master_merge      (const struct worker_top_ja4 *slots, int count);

/*  Single-process convenience: reset the master accumulator and merge in
 *  the local worker table.  Used by mtfront_prepare_stats when workers=0
 *  (mirrors prepare_master_top_ips_local). */
void ja4_master_prepare_local (void);

void ja4_dump_stats        (stats_buffer_t *sb);
void ja4_dump_prometheus   (stats_buffer_t *sb);
