/*
    TOML configuration file support for Teleproxy.

    Teleproxy is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.
*/

#pragma once

#include <stdint.h>

#define TOML_SECRET_LABEL_MAX 32
#define TOML_CONFIG_MAX_SECRETS  16
#define TOML_CONFIG_MAX_DOMAINS  16
#define TOML_CONFIG_MAX_DC_OVERRIDES 5
#define TOML_CONFIG_MAX_STATS_NETS 16

struct toml_secret {
  unsigned char key[16];
  char label[TOML_SECRET_LABEL_MAX + 1];
  int limit;
  long long quota;      /* byte quota, rx+tx combined (0 = unlimited) */
  long long rate_limit; /* bytes/sec per IP, rx+tx combined (0 = unlimited) */
  int max_ips;          /* unique IP limit (0 = unlimited) */
  int64_t expires;      /* Unix timestamp (0 = never expires) */
};

struct toml_dc_override {
  int dc_id;
  char host[256];
  int port;
};

struct toml_config {
  /* Network (not reloadable) */
  int port;                /* -H; 0 = not set */
  int stats_port;          /* -p; 0 = not set */
  int external_port;       /* port advertised in /link URLs; 0 = use port */
  int workers;             /* -M; -1 = not set */
  int max_connections;     /* -C; 0 = not set */
  char bind[64];           /* --address; empty = not set */
  int ipv6;                /* -6; -1 = not set */
  int maxconn;             /* -c (engine fd limit); 0 = not set */
  char user[64];           /* -u; empty = not set */

  /* Mode (not reloadable) */
  int direct;              /* --direct; -1 = not set */
  char proxy_tag[33];      /* -P; empty = not set (32 hex + NUL) */

  /* TLS (not reloadable) */
  struct toml_domain {
    char name[256];     /* SNI hostname advertised in fake-TLS ClientHello */
    char backend[256];  /* host:port or unix:/path; empty = forward to name itself */
  } domains[TOML_CONFIG_MAX_DOMAINS];
  int domain_count;

  /* Stats (reloadable) */
  int http_stats;          /* --http-stats; -1 = not set */
  char stats_allow_nets[TOML_CONFIG_MAX_STATS_NETS][64];
  int stats_allow_net_count;

  /* Per-IP top-N metrics in /metrics output (0 = disabled, default).
     Operator-side cardinality cap; clamped to WORKER_TOP_IPS_MAX. */
  int top_ips_per_secret;

  /* IP filtering (reloadable — paths only; actual reload via ip_acl_reload) */
  char ip_blocklist[256];
  char ip_allowlist[256];

  /* Secrets (reloadable) */
  struct toml_secret secrets[TOML_CONFIG_MAX_SECRETS];
  int secret_count;

  /* DC overrides (not reloadable) */
  struct toml_dc_override dc_overrides[TOML_CONFIG_MAX_DC_OVERRIDES];
  int dc_override_count;

  /* Misc (not reloadable) */
  int random_padding_only; /* -R; -1 = not set */
  int proxy_protocol;      /* --proxy-protocol; -1 = not set */

  /* Drain timeout (reloadable).  Seconds an old secret keeps serving
     in-flight connections after SIGHUP removes it; 0 = infinite (never
     force-close), default 300. */
  int drain_timeout_secs;

  /* DC probes (not reloadable) */
  int dc_probe_interval;   /* seconds between probe rounds; 0 = disabled; -1 = not set */

  /* SOCKS5 upstream proxy (not reloadable) */
  char socks5[256];        /* socks5://[user:pass@]host:port; empty = not set */
};

/*
 * Parse a TOML config file. Returns 0 on success, -1 on error.
 * On error, errbuf is filled with a description.
 */
int toml_config_load (const char *path, struct toml_config *cfg,
                      char *errbuf, int errlen);

/*
 * Reload only the reloadable fields from the TOML config file.
 * Returns 0 on success, -1 on error (old config kept).
 */
int toml_config_reload (const char *path, struct toml_config *cfg);

/*
 * Parse a hex secret string into a 16-byte binary secret.
 * hex must be exactly 32 hex characters.
 * Returns 0 on success, -1 on error.
 */
int toml_config_parse_hex_secret (const char *hex, unsigned char out[16]);
