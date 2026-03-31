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

#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include "mtproto/mtproto-dc-table.h"

/*
 * Well-known Telegram production DC addresses.
 * Media DCs (negative dc_id) share the same IPs as their positive counterparts.
 * Test DCs use dc_id + 10000 and have their own addresses.
 */

static int dc_table_initialized;

static struct dc_entry prod_table[5];
static struct dc_entry test_table[3];

#define MAX_OVERRIDES 16
static struct dc_entry override_table[MAX_OVERRIDES];
static int override_count;

static void dc_table_init (void) {
  if (dc_table_initialized) {
    return;
  }
  dc_table_initialized = 1;

  /* Production DCs */
  prod_table[0].dc_id = 1;
  prod_table[0].addr_count = 1;
  prod_table[0].addrs[0].ipv4 = inet_addr ("149.154.175.50");
  prod_table[0].addrs[0].port = 443;
  assert (inet_pton (AF_INET6, "2001:0b28:f23d:f001::a", prod_table[0].addrs[0].ipv6) == 1);

  prod_table[1].dc_id = 2;
  prod_table[1].addr_count = 1;
  prod_table[1].addrs[0].ipv4 = inet_addr ("149.154.167.51");
  prod_table[1].addrs[0].port = 443;
  assert (inet_pton (AF_INET6, "2001:067c:04e8:f002::a", prod_table[1].addrs[0].ipv6) == 1);

  prod_table[2].dc_id = 3;
  prod_table[2].addr_count = 1;
  prod_table[2].addrs[0].ipv4 = inet_addr ("149.154.175.100");
  prod_table[2].addrs[0].port = 443;
  assert (inet_pton (AF_INET6, "2001:0b28:f23d:f003::a", prod_table[2].addrs[0].ipv6) == 1);

  prod_table[3].dc_id = 4;
  prod_table[3].addr_count = 1;
  prod_table[3].addrs[0].ipv4 = inet_addr ("149.154.167.91");
  prod_table[3].addrs[0].port = 443;
  assert (inet_pton (AF_INET6, "2001:067c:04e8:f004::a", prod_table[3].addrs[0].ipv6) == 1);

  prod_table[4].dc_id = 5;
  prod_table[4].addr_count = 1;
  prod_table[4].addrs[0].ipv4 = inet_addr ("91.108.56.100");
  prod_table[4].addrs[0].port = 443;
  assert (inet_pton (AF_INET6, "2001:0b28:f23f:f005::a", prod_table[4].addrs[0].ipv6) == 1);

  /* Test DCs */
  test_table[0].dc_id = 1;
  test_table[0].addr_count = 1;
  test_table[0].addrs[0].ipv4 = inet_addr ("149.154.175.10");
  test_table[0].addrs[0].port = 443;
  assert (inet_pton (AF_INET6, "2001:0b28:f23d:f001::e", test_table[0].addrs[0].ipv6) == 1);

  test_table[1].dc_id = 2;
  test_table[1].addr_count = 1;
  test_table[1].addrs[0].ipv4 = inet_addr ("149.154.167.40");
  test_table[1].addrs[0].port = 443;
  assert (inet_pton (AF_INET6, "2001:067c:04e8:f002::e", test_table[1].addrs[0].ipv6) == 1);

  test_table[2].dc_id = 3;
  test_table[2].addr_count = 1;
  test_table[2].addrs[0].ipv4 = inet_addr ("149.154.175.117");
  test_table[2].addrs[0].port = 443;
  assert (inet_pton (AF_INET6, "2001:0b28:f23d:f003::e", test_table[2].addrs[0].ipv6) == 1);
}

const struct dc_entry *direct_dc_lookup (int dc_id) {
  dc_table_init ();

  int is_test = 0;

  if (dc_id < 0) {
    dc_id = -dc_id;
  }

  if (dc_id >= 10000) {
    dc_id -= 10000;
    is_test = 1;
  }

  /* Check override table before CDN stripping.
     This allows --dc-override 203:cdn-ip:443 to route CDN DCs
     to actual CDN IPs instead of falling back to the origin DC. */
  for (int i = 0; i < override_count; i++) {
    if (override_table[i].dc_id == dc_id) {
      return &override_table[i];
    }
  }

  /* CDN DCs use 200 + base_dc_id.  Fall back to the origin DC
     when no --dc-override is configured for the CDN DC. */
  if (dc_id > 200 && dc_id < 300) {
    dc_id -= 200;
  }

  if (is_test) {
    for (int i = 0; i < 3; i++) {
      if (test_table[i].dc_id == dc_id) {
        return &test_table[i];
      }
    }
    return 0;
  }

  for (int i = 0; i < 5; i++) {
    if (prod_table[i].dc_id == dc_id) {
      return &prod_table[i];
    }
  }
  return 0;
}

int direct_dc_override (int dc_id, const char *host, int port) {
  dc_table_init ();

  /* Find existing override entry for this dc_id */
  struct dc_entry *entry = NULL;
  for (int i = 0; i < override_count; i++) {
    if (override_table[i].dc_id == dc_id) {
      entry = &override_table[i];
      break;
    }
  }

  if (!entry) {
    if (override_count >= MAX_OVERRIDES) {
      return -1;
    }
    entry = &override_table[override_count++];
    memset (entry, 0, sizeof (*entry));
    entry->dc_id = dc_id;
  }

  if (entry->addr_count >= DC_MAX_ADDRS) {
    return -1;
  }

  struct dc_addr *addr = &entry->addrs[entry->addr_count];
  memset (addr, 0, sizeof (*addr));
  addr->port = port;

  if (inet_pton (AF_INET6, host, addr->ipv6) == 1) {
    /* IPv6 address — leave ipv4 as 0 */
  } else {
    addr->ipv4 = inet_addr (host);
    if (addr->ipv4 == (in_addr_t) -1) {
      return -1;
    }
  }

  entry->addr_count++;
  return 0;
}

int direct_dc_probe_ipv6 (void) {
  dc_table_init ();

  static const unsigned char zero_ipv6[16] = {};
  if (memcmp (prod_table[1].addrs[0].ipv6, zero_ipv6, 16) == 0) {
    return 0;
  }

  int fd = socket (AF_INET6, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    return 0;
  }

  struct sockaddr_in6 addr;
  memset (&addr, 0, sizeof (addr));
  addr.sin6_family = AF_INET6;
  addr.sin6_port = htons (prod_table[1].addrs[0].port);
  memcpy (&addr.sin6_addr, prod_table[1].addrs[0].ipv6, 16);

  int ret = connect (fd, (struct sockaddr *)&addr, sizeof (addr));
  int ok = (ret == 0 || errno == EINPROGRESS);
  close (fd);
  return ok;
}
