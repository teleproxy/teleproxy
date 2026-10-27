/*
    This file is part of MTProto-Server

    MTProto-Server is free software: you can redistribute it and/or modify
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
*/
#pragma once

#include <netinet/in.h>
#include "common/dc-id.h"

struct dc_addr {
  in_addr_t ipv4;             /* network byte order, 0 if unavailable */
  unsigned char ipv6[16];     /* network byte order, all-zero if unavailable */
  int port;
};

struct dc_entry {
  int dc_id;
  int addr_count;
  struct dc_addr addrs[DC_MAX_ADDRS];
};

/* Look up a Telegram DC by its identifier.
   Handles negative dc_id (media DCs), dc_id >= 10000 (test DCs),
   and dc_id 201-299 (CDN DCs, mapped to the base production DC).
   Override table (--dc-override) is checked first.
   Returns NULL if the DC is unknown. */
const struct dc_entry *direct_dc_lookup (int dc_id);

/* Add or replace a DC address via --dc-override.
   Overrides for a dc_id replace the built-in addresses entirely.
   Returns 0 on success, DC_OVERRIDE_EBADHOST if host is not an address
   literal, DC_OVERRIDE_EFULL if the DC already has DC_MAX_ADDRS addresses
   or the table already holds DC_OVERRIDE_MAX_DCS DCs. */
#define DC_OVERRIDE_EBADHOST (-1)
#define DC_OVERRIDE_EFULL    (-2)
int direct_dc_override (int dc_id, const char *host, int port);

/* Human-readable reason for a negative direct_dc_override() result. */
const char *direct_dc_override_strerror (int rc);

/* Return the --dc-override entry for exactly this dc_id, or NULL.
   Unlike direct_dc_lookup(), no media/test/CDN normalization is applied
   and the built-in table is never consulted. */
const struct dc_entry *direct_dc_override_lookup (int dc_id);

/* Probe IPv6 connectivity by attempting a non-blocking connect to a known DC.
   Returns 1 if IPv6 appears to work, 0 otherwise. */
int direct_dc_probe_ipv6 (void);
