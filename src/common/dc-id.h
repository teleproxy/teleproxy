/*
    Telegram DC identifiers addressable by direct-mode address overrides.

    Production DCs are numbered 1-5.  CDN DCs are numbered 200 + N; Telegram
    currently uses 201-205, and the whole 201-299 block is accepted so that
    new CDN DCs can be routed with --dc-override without a rebuild.  Without
    an override, direct_dc_lookup() maps a CDN DC to its origin DC N, which
    only exists for N = 1-5.  Negative media ids are normalized by
    direct_dc_lookup() before the override table is consulted, so they are
    not listed separately here.
*/
#pragma once

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define DC_ID_PROD_MIN 1
#define DC_ID_PROD_MAX 5
#define DC_ID_CDN_BASE 200
#define DC_ID_CDN_MIN  (DC_ID_CDN_BASE + 1)
#define DC_ID_CDN_MAX  (DC_ID_CDN_BASE + 99)

/* Addresses per DC entry, and distinct DCs in the override table */
#define DC_MAX_ADDRS        4
#define DC_OVERRIDE_MAX_DCS 16

static inline int dc_override_id_is_valid (long long dc_id) {
  return (dc_id >= DC_ID_PROD_MIN && dc_id <= DC_ID_PROD_MAX) ||
         (dc_id >= DC_ID_CDN_MIN && dc_id <= DC_ID_CDN_MAX);
}

/* Overrides take address literals only: IPv6, or IPv4 in any form that
   inet_addr() accepts.  Hostnames are not resolved. */
static inline int dc_override_host_is_valid (const char *host) {
  unsigned char ipv6[16];
  return inet_pton (AF_INET6, host, ipv6) == 1 || inet_addr (host) != INADDR_NONE;
}
