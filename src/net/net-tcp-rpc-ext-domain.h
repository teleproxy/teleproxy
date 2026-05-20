/*
    This file is part of Teleproxy.

    Teleproxy is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.
*/

#pragma once

#include <netinet/in.h>

/* Internal interface between net-tcp-rpc-ext-server.c and
   net-tcp-rpc-ext-domain.c.  Not part of the public API. */

#define DOMAIN_HASH_MOD 257

struct domain_info {
  const char *domain;       /* SNI hostname matched in ClientHello */
  const char *backend_host; /* host for connect; NULL = use domain */
  const char *unix_path;    /* set => AF_UNIX backend; backend_host/port unused */
  int port;
  struct in_addr target;
  unsigned char target_ipv6[16];
  short server_hello_encrypted_size;
  char use_random_encrypted_size;
  char is_reversed_extension_order;
  struct domain_info *next;
};

extern int allow_only_tls;
extern struct domain_info *default_domain_info;
extern struct domain_info *domains[DOMAIN_HASH_MOD];

/* Singly linked list of wildcard SNI entries (patterns of the form
   "*.suffix").  Kept separate from the hash table so exact-match lookup
   stays O(1); wildcards are scanned only on a miss.  Chain via the
   existing struct domain_info::next field. */
extern struct domain_info *wildcard_domains;

struct domain_info **get_domain_info_bucket (const char *domain, size_t len);

/* Returns non-zero iff `pattern` is a syntactically valid wildcard ("*.label.label...")
   per RFC 6125 (one leading "*." label only, no embedded or trailing wildcards,
   at least one suffix label). */
int is_wildcard_domain (const char *pattern);

/* RFC 6125 §6.4.3 single-label match.  Returns non-zero iff `sni[0..sni_len]`
   has exactly one non-empty label (no '.' and no '*') followed by `pattern + 1`.
   `pattern` must already be a valid wildcard pattern (see is_wildcard_domain).
   Byte-wise compare; SNI is canonically lowercase per RFC 6066. */
int wildcard_match (const char *pattern, const char *sni, size_t sni_len);
