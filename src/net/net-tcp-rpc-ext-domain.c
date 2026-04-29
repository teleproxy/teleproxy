/*
    This file is part of Teleproxy.

    Teleproxy is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.
*/

/*
 * Fake-TLS domain registration.  Owns tcp_rpc_add_proxy_domain — the entry
 * point used by both the CLI flag (-D) and the TOML [[domain]] loop.  The
 * heavy lifting (TLS fingerprinting, SNI matching, server hello mimicry)
 * lives in net-tcp-rpc-ext-server.c; this file just parses the user spec
 * and inserts a struct domain_info into the shared hash table.
 */

#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "common/kprintf.h"
#include "jobs/jobs.h"
#include "net/net-connections.h"
#include "net/net-tcp-rpc-common.h"
#include "net/net-tcp-rpc-ext-server.h"
#include "net/net-tcp-rpc-ext-domain.h"

/* Split host[:port] or [IPv6]:port. Returns malloc'd host or NULL on error. */
static char *parse_host_port (const char *spec, int *port_out) {
  *port_out = 443;
  if (spec[0] == '[') {
    const char *e = strchr (spec, ']');
    if (!e) { return NULL; }
    if (e[1] == ':') { *port_out = atoi (e + 2); }
    return strndup (spec + 1, e - spec - 1);
  }
  const char *c = strrchr (spec, ':');
  if (c && strchr (spec, ':') == c) { *port_out = atoi (c + 1); return strndup (spec, c - spec); }
  return strdup (spec);
}

void tcp_rpc_add_proxy_domain (const char *name, const char *backend) {
  assert (name != NULL);
  struct domain_info *info = calloc (1, sizeof (struct domain_info));
  assert (info != NULL);
  info->port = 443;

  const char *bspec = (backend && backend[0]) ? backend : NULL;
  if (bspec == NULL) {
    char *parsed = parse_host_port (name, &info->port);
    if (!parsed) { kprintf ("Invalid IPv6 address: %s\n", name); free (info); return; }
    info->domain = parsed;
  } else {
    info->domain = strdup (name);
    if (strncmp (bspec, "unix:", 5) == 0 || bspec[0] == '/') {
      info->unix_path = strdup (bspec[0] == '/' ? bspec : bspec + 5);
    } else {
      char *host = parse_host_port (bspec, &info->port);
      if (!host) {
        kprintf ("Invalid backend spec: %s\n", bspec);
        free ((void *)info->domain); free (info); return;
      }
      info->backend_host = host;
    }
  }

  if (info->port <= 0 || info->port > 65535) {
    kprintf ("Invalid port: %s\n", bspec ? bspec : name);
    free ((void *)info->domain); free ((void *)info->backend_host); free ((void *)info->unix_path);
    free (info); return;
  }

  if (info->unix_path) { kprintf ("Proxy domain: %s -> unix:%s\n", info->domain, info->unix_path); }
  else if (info->backend_host) { kprintf ("Proxy domain: %s -> %s:%d\n", info->domain, info->backend_host, info->port); }
  else { kprintf ("Proxy domain: %s:%d\n", info->domain, info->port); }

  struct domain_info **bucket = get_domain_info_bucket (info->domain, strlen (info->domain));
  info->next = *bucket;
  *bucket = info;
  if (!allow_only_tls) { allow_only_tls = 1; default_domain_info = info; }
}
