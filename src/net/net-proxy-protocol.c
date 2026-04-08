/*
    PROXY protocol v1/v2 parser for teleproxy.

    Teleproxy is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.
*/

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "net/net-proxy-protocol.h"
#include "common/kprintf.h"

int proxy_protocol_enabled;
long long proxy_protocol_connections_total;
long long proxy_protocol_errors_total;

/* PROXY protocol v2 12-byte signature */
static const unsigned char pp2_signature[12] = {
  0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51,
  0x55, 0x49, 0x54, 0x0a
};

/* Parse PROXY protocol v1 (text) header.
   Format: "PROXY TCP4|TCP6|UNKNOWN <src> <dst> <sport> <dport>\r\n"
   Max length per spec: 107 bytes including CRLF. */
static int parse_v1 (struct raw_message *in, struct proxy_protocol_result *out) {
  int len = in->total_bytes;
  /* Minimum meaningful v1: "PROXY UNKNOWN\r\n" = 15 bytes.
     We already verified 6+ bytes and "PROXY " prefix in the caller. */
  if (len < 15) {
    return 0;
  }

  int peek_len = len < 108 ? len : 108;
  unsigned char buf[108];
  int got = rwm_fetch_lookup (in, buf, peek_len);
  if (got < peek_len) {
    peek_len = got;
  }

  /* Scan for \r\n terminator */
  int crlf_pos = -1;
  for (int i = 6; i < peek_len - 1; i++) {
    if (buf[i] == '\r' && buf[i + 1] == '\n') {
      crlf_pos = i;
      break;
    }
  }
  if (crlf_pos < 0) {
    if (peek_len >= 108) {
      return -1;  /* header too long */
    }
    return 0;  /* need more data */
  }

  int header_len = crlf_pos + 2;

  /* Null-terminate for string parsing (replacing \r) */
  buf[crlf_pos] = '\0';
  char *p = (char *)buf + 6;  /* skip "PROXY " */

  memset (out, 0, sizeof (*out));

  if (strncmp (p, "UNKNOWN", 7) == 0) {
    if (rwm_skip_data (in, header_len) != header_len) { return -1; }
    return header_len;
  }

  int family;
  if (strncmp (p, "TCP4 ", 5) == 0) {
    family = AF_INET;
    p += 5;
  } else if (strncmp (p, "TCP6 ", 5) == 0) {
    family = AF_INET6;
    p += 5;
  } else {
    return -1;
  }

  /* Parse source IP */
  char *sp = strchr (p, ' ');
  if (!sp) return -1;
  *sp = '\0';

  out->family = family;
  if (family == AF_INET) {
    struct in_addr addr;
    if (inet_pton (AF_INET, p, &addr) != 1) return -1;
    out->src_ip = ntohl (addr.s_addr);
  } else {
    if (inet_pton (AF_INET6, p, out->src_ipv6) != 1) return -1;
  }

  /* Skip destination IP */
  p = sp + 1;
  sp = strchr (p, ' ');
  if (!sp) return -1;

  /* Parse source port */
  p = sp + 1;
  sp = strchr (p, ' ');
  if (!sp) return -1;
  *sp = '\0';
  out->src_port = (unsigned short)atoi (p);

  /* Destination port is the remainder — we don't need it */

  if (rwm_skip_data (in, header_len) != header_len) { return -1; }
  return header_len;
}

/* Parse PROXY protocol v2 (binary) header.
   Layout: 12-byte signature | ver_cmd | fam_proto | addr_len (2, big-endian) | addresses | TLVs */
static int parse_v2 (struct raw_message *in, struct proxy_protocol_result *out) {
  int len = in->total_bytes;
  if (len < 16) {
    return 0;
  }

  unsigned char hdr[16];
  if (rwm_fetch_lookup (in, hdr, 16) != 16) { return -1; }

  int ver_cmd = hdr[12];
  int version = (ver_cmd >> 4) & 0x0f;
  int command = ver_cmd & 0x0f;

  if (version != 2) return -1;
  if (command > 1) return -1;  /* only LOCAL(0) and PROXY(1) */

  int fam = (hdr[13] >> 4) & 0x0f;
  int addr_len = ((int)hdr[14] << 8) | hdr[15];
  int total_len = 16 + addr_len;

  if (len < total_len) {
    return 0;
  }

  memset (out, 0, sizeof (*out));

  if (command == 0) {
    /* LOCAL: no address info (health check / internal) */
    if (rwm_skip_data (in, total_len) != total_len) { return -1; }
    return total_len;
  }

  /* PROXY command: extract addresses */
  if (fam == 1 && addr_len >= 12) {
    /* AF_INET: src_addr(4) + dst_addr(4) + src_port(2) + dst_port(2) */
    unsigned char addrs[12];
    /* Peek past the 16-byte header to get addresses */
    unsigned char full[28]; /* 16 header + 12 addrs */
    if (rwm_fetch_lookup (in, full, 28) != 28) { return -1; }

    memcpy (addrs, full + 16, 12);
    out->family = AF_INET;
    out->src_ip = ntohl (*(unsigned *)(addrs));
    out->src_port = ntohs (*(unsigned short *)(addrs + 8));
  } else if (fam == 2 && addr_len >= 36) {
    /* AF_INET6: src_addr(16) + dst_addr(16) + src_port(2) + dst_port(2) */
    unsigned char full[52]; /* 16 header + 36 addrs */
    if (rwm_fetch_lookup (in, full, 52) != 52) { return -1; }

    out->family = AF_INET6;
    memcpy (out->src_ipv6, full + 16, 16);
    out->src_port = ntohs (*(unsigned short *)(full + 48));
  }
  /* fam == 0 (AF_UNSPEC) or unknown: family stays 0 */

  /* Skip entire header including any TLV extensions */
  if (rwm_skip_data (in, total_len) != total_len) { return -1; }
  return total_len;
}

int proxy_protocol_parse (struct raw_message *in, struct proxy_protocol_result *out) {
  int len = in->total_bytes;
  if (len < 6) {
    return 0;
  }

  unsigned char peek[12];
  int peek_len = len < 12 ? len : 12;
  int got = rwm_fetch_lookup (in, peek, peek_len);
  if (got < peek_len) {
    peek_len = got;
  }

  /* Check v1 signature: "PROXY " */
  if (memcmp (peek, "PROXY ", 6) == 0) {
    return parse_v1 (in, out);
  }

  /* Check v2 signature (need 12 bytes) */
  if (peek_len >= 12 && memcmp (peek, pp2_signature, 12) == 0) {
    return parse_v2 (in, out);
  }

  /* Not enough data to rule out v2 */
  if (peek_len < 12) {
    return 0;
  }

  return -1;  /* not a PROXY protocol header */
}
