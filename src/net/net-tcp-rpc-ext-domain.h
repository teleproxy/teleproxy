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

struct domain_info **get_domain_info_bucket (const char *domain, size_t len);
