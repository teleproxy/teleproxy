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
 *  JA4 ClientHello fingerprint counter (issue #102).
 *
 *  Per-worker top-N table populated from net-tcp-rpc-ext-server.c on
 *  every well-formed ClientHello — including HMAC failures, which is
 *  the whole point: the operationally interesting traffic is the TSPU
 *  probe that fails secret validation, not the legit client.
 *
 *  Snapshot semantics mirror the top-IPs sidecar in
 *  net-tcp-rpc-ext-top-ips.c: each worker owns ja4_table[]; master
 *  copies a snapshot into shared worker_stats once per refresh and
 *  merges across workers before rendering /stats or /metrics.
 */

#include "net/net-ja4.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/common-stats.h"
#include "common/kprintf.h"
#include "common/sha256.h"
#include "common/toml-config.h"
#include "net/net-tls-parse.h"

extern struct toml_config toml_cfg;

/* -------- TLS ClientHello walker (JA4 spec) -------- */

static inline int is_grease_u16 (unsigned int v) {
  /* RFC 8701: GREASE values are 0x0A0A, 0x1A1A, ..., 0xFAFA. */
  return (v & 0x0F0F) == 0x0A0A && ((v >> 8) & 0xFF) == (v & 0xFF);
}

static inline unsigned int u16_be (const unsigned char *p) {
  return ((unsigned)p[0] << 8) | p[1];
}

/* Walk a ClientHello and populate JA4 inputs.  Returns 0 on success.
   On success:
     *tls_ver_out  — two ASCII digits ("13", "12", "11", "10")
     *has_sni_out  — 1 if SNI extension present, 0 otherwise
     ciphers_out[] — non-GREASE cipher hex strings (each "xxxx"), in sorted order
     *cipher_n_out — count of ciphers (after GREASE filter, capped to cipher_max)
     exts_out[]    — non-GREASE extension hex strings (excluding 0x0000 SNI and
                     0x0010 ALPN), in sorted order; cap exts_max
     *ext_count_total_out — TOTAL extension count BEFORE the SNI/ALPN filter
                            but after GREASE filter (for JA4_a "16" digit)
     *ext_n_sorted_out    — count of entries in exts_out[] (after SNI/ALPN filter)
     sigalgs_out[] — signature algorithm hex strings in ORIGINAL order
     *sigalgs_n_out — count
     alpn0_first / alpn0_last — first and last byte of the first ALPN protocol,
                                 or both NUL if no ALPN.
*/
static int ja4_parse (const unsigned char *ch, int len,
                      char *tls_ver_out,
                      int *has_sni_out,
                      char (*ciphers_out)[5], int cipher_max, int *cipher_n_out,
                      char (*exts_out)[5], int exts_max,
                      int *ext_count_total_out, int *ext_n_sorted_out,
                      char (*sigalgs_out)[5], int sigalgs_max, int *sigalgs_n_out,
                      unsigned char *alpn0_first, unsigned char *alpn0_last) {
  /* Buffer layout: TLS record (5) + handshake header (4) + ClientHello body.
     ClientHello body starts at offset 9:
       [9..10]    legacy_version (TLS 1.2 = 0x0303)
       [11..42]   random (32 bytes)
       [43]       session_id_length
       [44..]     session_id (length given by [43])
       ...        cipher_suites_length (u16), cipher_suites
       ...        compression_methods_length (u8), compression_methods
       ...        extensions_length (u16), extensions
  */
  if (len < 44) {
    return -1;
  }
  int pos = 43;
  int sid_len = ch[pos++];
  if (sid_len < 0 || pos + sid_len > len) {
    return -1;
  }
  pos += sid_len;

  /* Default version from legacy_version; supported_versions extension wins. */
  int tls_minor = (ch[9] == 0x03) ? ch[10] : -1;
  /* Map TLS 1.0 (0x0301) → "10", 1.1 → "11", 1.2 → "12", 1.3 → "13". */
  if (tls_minor >= 1 && tls_minor <= 4) {
    tls_ver_out[0] = '1';
    tls_ver_out[1] = '0' + (tls_minor - 1);
  } else {
    tls_ver_out[0] = '0';
    tls_ver_out[1] = '0';
  }

  /* Cipher suites. */
  if (pos + 2 > len) { return -1; }
  int cs_len = u16_be (ch + pos);
  pos += 2;
  if (cs_len < 0 || (cs_len & 1) || pos + cs_len > len) { return -1; }
  int cs_end = pos + cs_len;
  int cipher_n = 0;
  while (pos + 2 <= cs_end) {
    unsigned int v = u16_be (ch + pos);
    pos += 2;
    if (is_grease_u16 (v)) { continue; }
    if (cipher_n < cipher_max) {
      snprintf (ciphers_out[cipher_n], 5, "%04x", v);
    }
    cipher_n++;
  }
  pos = cs_end;
  if (cipher_n > cipher_max) { cipher_n = cipher_max; }
  *cipher_n_out = cipher_n;

  /* Compression methods. */
  if (pos + 1 > len) { return -1; }
  int comp_len = ch[pos++];
  if (comp_len < 0 || pos + comp_len > len) { return -1; }
  pos += comp_len;

  /* Extensions. */
  if (pos + 2 > len) {
    /* No extensions block at all — still a valid ClientHello. */
    *has_sni_out = 0;
    *ext_count_total_out = 0;
    *ext_n_sorted_out = 0;
    *sigalgs_n_out = 0;
    *alpn0_first = 0;
    *alpn0_last = 0;
    return 0;
  }
  int ext_total_len = u16_be (ch + pos);
  pos += 2;
  if (ext_total_len < 0 || pos + ext_total_len > len) { return -1; }
  int ext_end = pos + ext_total_len;

  int has_sni = 0;
  int ext_count_total = 0;
  int ext_n = 0;
  int sigalgs_n = 0;
  unsigned char alpn_first = 0, alpn_last = 0;

  while (pos + 4 <= ext_end) {
    unsigned int ext_type = u16_be (ch + pos);
    pos += 2;
    int ext_len = u16_be (ch + pos);
    pos += 2;
    if (ext_len < 0 || pos + ext_len > ext_end) { return -1; }

    if (!is_grease_u16 (ext_type)) {
      ext_count_total++;

      if (ext_type == 0x0000) {
        has_sni = 1;
      } else if (ext_type == 0x002b /* supported_versions */ && ext_len >= 1) {
        /* List of u16 versions, first byte is u8 list length.  Highest
           non-GREASE entry wins. */
        int sv_list_len = ch[pos];
        if (sv_list_len > 0 && sv_list_len + 1 <= ext_len &&
            (sv_list_len & 1) == 0) {
          int best_minor = -1;
          for (int k = 0; k + 1 < sv_list_len; k += 2) {
            unsigned int v = u16_be (ch + pos + 1 + k);
            if (is_grease_u16 (v)) { continue; }
            if ((v >> 8) == 0x03 && (v & 0xFF) >= 1 && (v & 0xFF) <= 4) {
              if ((int)(v & 0xFF) > best_minor) {
                best_minor = v & 0xFF;
              }
            }
          }
          if (best_minor >= 1) {
            tls_ver_out[0] = '1';
            tls_ver_out[1] = '0' + (best_minor - 1);
          }
        }
      } else if (ext_type == 0x000d /* signature_algorithms */ && ext_len >= 2) {
        int sa_list_len = u16_be (ch + pos);
        if (sa_list_len > 0 && sa_list_len + 2 <= ext_len &&
            (sa_list_len & 1) == 0) {
          for (int k = 0; k + 1 < sa_list_len; k += 2) {
            unsigned int v = u16_be (ch + pos + 2 + k);
            if (sigalgs_n < sigalgs_max) {
              snprintf (sigalgs_out[sigalgs_n], 5, "%04x", v);
            }
            sigalgs_n++;
          }
        }
      } else if (ext_type == 0x0010 /* ALPN */ && ext_len >= 3) {
        int alpn_list_len = u16_be (ch + pos);
        if (alpn_list_len > 0 && alpn_list_len + 2 <= ext_len) {
          int first_len = ch[pos + 2];
          if (first_len > 0 && pos + 3 + first_len <= ext_end) {
            alpn_first = ch[pos + 3];
            alpn_last  = ch[pos + 3 + first_len - 1];
          }
        }
      }

      /* SNI (0x0000) and ALPN (0x0010) are excluded from JA4_c per spec. */
      if (ext_type != 0x0000 && ext_type != 0x0010) {
        if (ext_n < exts_max) {
          snprintf (exts_out[ext_n], 5, "%04x", ext_type);
        }
        ext_n++;
      }
    }

    pos += ext_len;
  }

  if (ext_n > exts_max) { ext_n = exts_max; }
  if (sigalgs_n > sigalgs_max) { sigalgs_n = sigalgs_max; }
  *has_sni_out         = has_sni;
  *ext_count_total_out = ext_count_total;
  *ext_n_sorted_out    = ext_n;
  *sigalgs_n_out       = sigalgs_n;
  *alpn0_first         = alpn_first;
  *alpn0_last          = alpn_last;
  return 0;
}

static int hex4_cmp (const void *a, const void *b) {
  return memcmp (a, b, 4);
}

/* SHA256 first 12 hex chars of the given input string. */
static void sha256_hex12 (const char *in, int in_len, char out[13]) {
  unsigned char digest[32];
  sha256 ((const unsigned char *) in, in_len, digest);
  static const char hex[] = "0123456789abcdef";
  for (int i = 0; i < 6; i++) {
    out[2 * i]     = hex[digest[i] >> 4];
    out[2 * i + 1] = hex[digest[i] & 0x0F];
  }
  out[12] = '\0';
}

int ja4_compute (const unsigned char *ch, int len, char out[JA4_HASH_BUF]) {
  /* Hard caps — well above anything seen in the wild. */
  enum { MAX_CIPHERS = 64, MAX_EXTS = 64, MAX_SIGALGS = 64 };
  char ciphers[MAX_CIPHERS][5];
  char exts[MAX_EXTS][5];
  char sigalgs[MAX_SIGALGS][5];
  char tls_ver[2];
  int has_sni = 0;
  int cipher_n = 0, ext_count_total = 0, ext_n_sorted = 0, sigalgs_n = 0;
  unsigned char alpn0_first = 0, alpn0_last = 0;

  if (ja4_parse (ch, len, tls_ver, &has_sni,
                 ciphers, MAX_CIPHERS, &cipher_n,
                 exts, MAX_EXTS, &ext_count_total, &ext_n_sorted,
                 sigalgs, MAX_SIGALGS, &sigalgs_n,
                 &alpn0_first, &alpn0_last) < 0) {
    return -1;
  }

  qsort (ciphers, cipher_n, 5, hex4_cmp);
  qsort (exts,    ext_n_sorted, 5, hex4_cmp);

  /* JA4_b: SHA256 of comma-joined sorted ciphers, first 12 hex chars.
     All-zero string if no ciphers. */
  char ja4_b[13];
  if (cipher_n == 0) {
    memcpy (ja4_b, "000000000000", 13);
  } else {
    char buf[MAX_CIPHERS * 5 + 1] = {0};
    int bp = 0;
    for (int i = 0; i < cipher_n; i++) {
      if (i) { buf[bp++] = ','; }
      memcpy (buf + bp, ciphers[i], 4);
      bp += 4;
    }
    sha256_hex12 (buf, bp, ja4_b);
  }

  /* JA4_c: SHA256 of comma-joined sorted exts, optionally "_" + sigalgs
     in original order, first 12 hex chars.  All-zero if both empty. */
  char ja4_c[13];
  if (ext_n_sorted == 0 && sigalgs_n == 0) {
    memcpy (ja4_c, "000000000000", 13);
  } else {
    char buf[(MAX_EXTS + MAX_SIGALGS) * 5 + 2] = {0};
    int bp = 0;
    for (int i = 0; i < ext_n_sorted; i++) {
      if (i) { buf[bp++] = ','; }
      memcpy (buf + bp, exts[i], 4);
      bp += 4;
    }
    if (sigalgs_n > 0) {
      buf[bp++] = '_';
      for (int i = 0; i < sigalgs_n; i++) {
        if (i) { buf[bp++] = ','; }
        memcpy (buf + bp, sigalgs[i], 4);
        bp += 4;
      }
    }
    sha256_hex12 (buf, bp, ja4_c);
  }

  /* JA4_a: protocol(1) + tls_ver(2) + sni(1) + ciphers(2) + exts(2) + alpn(2)
     = 10 chars.  Cap counts at 99 → "99" per spec. */
  int cipher_disp = cipher_n > 99 ? 99 : cipher_n;
  int ext_disp    = ext_count_total > 99 ? 99 : ext_count_total;
  char alpn_a, alpn_b;
  if (alpn0_first == 0 && alpn0_last == 0) {
    alpn_a = '0'; alpn_b = '0';
  } else {
    /* Spec: if either byte is non-alphanumeric, use first/last hex nibble
       of first byte.  Common case (h2, http/1.1) yields h2 / h1. */
    int ok = (alpn0_first >= 0x20 && alpn0_first < 0x7f &&
              alpn0_last  >= 0x20 && alpn0_last  < 0x7f);
    if (ok) {
      alpn_a = (char) alpn0_first;
      alpn_b = (char) alpn0_last;
    } else {
      static const char hex[] = "0123456789abcdef";
      alpn_a = hex[(alpn0_first >> 4) & 0x0F];
      alpn_b = hex[alpn0_first & 0x0F];
    }
  }

  snprintf (out, JA4_HASH_BUF,
            "t%c%c%c%02d%02d%c%c_%s_%s",
            tls_ver[0], tls_ver[1],
            has_sni ? 'd' : 'i',
            cipher_disp, ext_disp,
            alpn_a, alpn_b,
            ja4_b, ja4_c);
  return 0;
}

/* -------- Worker-local top-N table -------- */

static struct worker_top_ja4 ja4_table[WORKER_TOP_JA4_MAX];

static void ja4_record (const char *hash) {
  /* Per-worker single-threaded — no locking needed within the hot path.
     Race tolerance for cross-process snapshots is handled by the
     __sync_synchronize() barriers in mtproto-proxy-stats.c. */
  for (int i = 0; i < WORKER_TOP_JA4_MAX; i++) {
    if (ja4_table[i].count == 0) { continue; }
    if (strcmp (ja4_table[i].hash, hash) == 0) {
      ja4_table[i].count++;
      return;
    }
  }
  /* Not found — claim an empty slot. */
  for (int i = 0; i < WORKER_TOP_JA4_MAX; i++) {
    if (ja4_table[i].count == 0) {
      snprintf (ja4_table[i].hash, JA4_HASH_BUF, "%s", hash);
      ja4_table[i].count = 1;
      return;
    }
  }
  /* Table full — evict the smallest-count entry only if our incoming hit
     would benefit observability (count == 1 always loses, so drop). */
}

void ja4_observe (const unsigned char *client_hello, int len) {
  char hash[JA4_HASH_BUF];
  if (ja4_compute (client_hello, len, hash) < 0) {
    return;
  }
  ja4_record (hash);
  if (toml_cfg.ja4_log) {
    char sni[256] = "";
    int sni_len = tls_parse_sni (client_hello, len, sni, sizeof (sni));
    if (sni_len > 0) {
      vkprintf (2, "ja4=%s sni=%s\n", hash, sni);
    } else {
      vkprintf (2, "ja4=%s sni=-\n", hash);
    }
  }
}

void ja4_snapshot (struct worker_top_ja4 *out, int *count_out, int max) {
  int n = 0;
  for (int i = 0; i < WORKER_TOP_JA4_MAX && n < max; i++) {
    if (ja4_table[i].count == 0) { continue; }
    memcpy (&out[n], &ja4_table[i], sizeof (struct worker_top_ja4));
    n++;
  }
  *count_out = n;
}

/* -------- Master-side aggregation -------- */

#define MASTER_TOP_JA4_MAX  256

static struct worker_top_ja4 master_table[MASTER_TOP_JA4_MAX];
static int master_count;

void ja4_master_reset (void) {
  master_count = 0;
  memset (master_table, 0, sizeof (master_table));
}

void ja4_master_prepare_local (void) {
  ja4_master_reset ();
  struct worker_top_ja4 buf[WORKER_TOP_JA4_MAX];
  int count = 0;
  ja4_snapshot (buf, &count, WORKER_TOP_JA4_MAX);
  ja4_master_merge (buf, count);
}

void ja4_master_merge (const struct worker_top_ja4 *slots, int count) {
  for (int i = 0; i < count; i++) {
    if (slots[i].count == 0 || slots[i].hash[0] == '\0') { continue; }
    int found = 0;
    for (int j = 0; j < master_count; j++) {
      if (strcmp (master_table[j].hash, slots[i].hash) == 0) {
        master_table[j].count += slots[i].count;
        found = 1;
        break;
      }
    }
    if (!found && master_count < MASTER_TOP_JA4_MAX) {
      master_table[master_count] = slots[i];
      master_count++;
    }
  }
}

static int master_cmp_desc (const void *a, const void *b) {
  const struct worker_top_ja4 *x = a, *y = b;
  if (x->count > y->count) { return -1; }
  if (x->count < y->count) { return  1; }
  return 0;
}

void ja4_dump_stats (stats_buffer_t *sb) {
  if (master_count == 0) { return; }
  qsort (master_table, master_count, sizeof (master_table[0]), master_cmp_desc);
  int n = master_count > WORKER_TOP_JA4_MAX ? WORKER_TOP_JA4_MAX : master_count;
  for (int i = 0; i < n; i++) {
    sb_printf (sb, "ja4_seen\t%s\t%llu\n",
               master_table[i].hash,
               (unsigned long long) master_table[i].count);
  }
}

void ja4_dump_prometheus (stats_buffer_t *sb) {
  if (master_count == 0) { return; }
  qsort (master_table, master_count, sizeof (master_table[0]), master_cmp_desc);
  int n = master_count > WORKER_TOP_JA4_MAX ? WORKER_TOP_JA4_MAX : master_count;
  sb_printf (sb,
             "# HELP teleproxy_ja4_seen ClientHello JA4 fingerprints observed (top 32 by count, aggregated across workers).\n"
             "# TYPE teleproxy_ja4_seen counter\n");
  for (int i = 0; i < n; i++) {
    sb_printf (sb, "teleproxy_ja4_seen{hash=\"%s\"} %llu\n",
               master_table[i].hash,
               (unsigned long long) master_table[i].count);
  }
}
