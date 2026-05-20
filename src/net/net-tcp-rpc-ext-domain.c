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

int wildcard_match (const char *pattern, const char *sni, size_t sni_len) {
  const char *suffix = pattern + 1;             /* ".suffix" */
  size_t suffix_len = strlen (suffix);
  if (sni_len <= suffix_len) { return 0; }      /* need at least 1 label byte */
  size_t label_len = sni_len - suffix_len;
  if (memchr (sni, '.', label_len) != NULL) { return 0; }  /* exactly one label */
  if (memchr (sni, '*', label_len) != NULL) { return 0; }  /* no literal wildcard in SNI */
  return memcmp (sni + label_len, suffix, suffix_len) == 0;
}

int is_wildcard_domain (const char *pattern) {
  /* Must start with "*." and have at least one suffix character. */
  if (pattern[0] != '*' || pattern[1] != '.' || pattern[2] == '\0') {
    return 0;
  }
  const char *p = pattern + 2;
  /* No further '*' anywhere; no empty labels (".." or trailing "."); must
     contain a dot to give a real suffix like ".example.com". */
  int saw_dot = 0;
  int label_len = 0;
  for (; *p; p++) {
    if (*p == '*') { return 0; }
    if (*p == '.') {
      if (label_len == 0) { return 0; }
      label_len = 0;
      saw_dot = 1;
    } else {
      label_len++;
    }
  }
  /* Trailing dot rejected, and we need at least one label after the '*.'. */
  return saw_dot && label_len > 0;
}

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

  int is_wildcard = info->domain[0] == '*';
  if (is_wildcard) {
    if (!is_wildcard_domain (info->domain)) {
      kprintf ("Invalid wildcard pattern: %s (expected '*.label.label...' with no embedded or trailing wildcards)\n", info->domain);
      free ((void *)info->domain); free ((void *)info->backend_host); free ((void *)info->unix_path);
      free (info); return;
    }
    if (!info->backend_host && !info->unix_path) {
      kprintf ("Wildcard domain %s requires an explicit backend (e.g. -D %s:host:port) — nothing to fingerprint or forward to\n",
               info->domain, info->domain);
      free ((void *)info->domain); free (info); return;
    }
  }

  if (info->unix_path) { kprintf ("Proxy domain: %s -> unix:%s\n", info->domain, info->unix_path); }
  else if (info->backend_host) { kprintf ("Proxy domain: %s -> %s:%d\n", info->domain, info->backend_host, info->port); }
  else { kprintf ("Proxy domain: %s:%d\n", info->domain, info->port); }

  if (is_wildcard) {
    info->next = wildcard_domains;
    wildcard_domains = info;
  } else {
    struct domain_info **bucket = get_domain_info_bucket (info->domain, strlen (info->domain));
    info->next = *bucket;
    *bucket = info;
  }
  if (!allow_only_tls) { allow_only_tls = 1; default_domain_info = info; }
}
