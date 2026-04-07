/*
    TOML configuration file support for Teleproxy.

    Teleproxy is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.
*/

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#include "toml-config.h"
#include "tomlc17.h"
#include "kprintf.h"

int toml_config_parse_hex_secret (const char *hex, unsigned char out[16]) {
  if (!hex || strlen (hex) != 32) {
    return -1;
  }
  unsigned char b = 0;
  for (int i = 0; i < 32; i++) {
    char c = hex[i];
    if (c >= '0' && c <= '9') {
      b = b * 16 + (c - '0');
    } else if (c >= 'a' && c <= 'f') {
      b = b * 16 + (c - 'a' + 10);
    } else if (c >= 'A' && c <= 'F') {
      b = b * 16 + (c - 'A' + 10);
    } else {
      return -1;
    }
    if (i & 1) {
      out[i / 2] = b;
      b = 0;
    }
  }
  return 0;
}

static int validate_label (const char *label) {
  for (const char *p = label; *p; p++) {
    char c = *p;
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
          (c >= '0' && c <= '9') || c == '_' || c == '-')) {
      return -1;
    }
  }
  return 0;
}

/* Parse a human-readable byte size: "10G", "500M", "1T", "1024".
   Case-insensitive, optional trailing 'B'. Returns -1 on error. */
static long long parse_byte_size (const char *s, char *errbuf, int errlen) {
  char *endp;
  long long val = strtoll (s, &endp, 10);
  if (endp == s || val < 0) {
    snprintf (errbuf, errlen, "invalid byte size '%s'", s);
    return -1;
  }
  char suffix = toupper ((unsigned char) *endp);
  if (suffix == 'K') { val *= 1024LL; endp++; }
  else if (suffix == 'M') { val *= 1024LL * 1024; endp++; }
  else if (suffix == 'G') { val *= 1024LL * 1024 * 1024; endp++; }
  else if (suffix == 'T') { val *= 1024LL * 1024 * 1024 * 1024; endp++; }
  /* skip optional trailing 'B' */
  if (toupper ((unsigned char) *endp) == 'B') { endp++; }
  if (*endp != '\0') {
    snprintf (errbuf, errlen, "invalid byte size '%s'", s);
    return -1;
  }
  return val;
}

/* Convert a TOML datetime datum to a Unix epoch timestamp.
   Accepts TOML_DATETIME (assumed UTC) and TOML_DATETIMETZ. */
static int64_t toml_ts_to_epoch (toml_datum_t d) {
  struct tm tm;
  memset (&tm, 0, sizeof (tm));
  tm.tm_year = d.u.ts.year - 1900;
  tm.tm_mon = d.u.ts.month - 1;
  tm.tm_mday = d.u.ts.day;
  tm.tm_hour = d.u.ts.hour;
  tm.tm_min = d.u.ts.minute;
  tm.tm_sec = d.u.ts.second;
#ifdef __APPLE__
  time_t t = timegm (&tm);
#else
  /* timegm is available on Linux (glibc, musl) */
  time_t t = timegm (&tm);
#endif
  if (d.type == TOML_DATETIMETZ) {
    t -= d.u.ts.tz * 60;  /* tz is offset in minutes east of UTC */
  }
  return (int64_t) t;
}

static int parse_secrets (toml_datum_t toptab, struct toml_config *cfg,
                          char *errbuf, int errlen) {
  cfg->secret_count = 0;
  toml_datum_t secret_arr = toml_get (toptab, "secret");
  if (secret_arr.type == TOML_UNKNOWN) {
    return 0;  /* no secrets section — valid */
  }
  if (secret_arr.type != TOML_ARRAY) {
    snprintf (errbuf, errlen, "'secret' must be an array of tables");
    return -1;
  }

  int n = secret_arr.u.arr.size;
  if (n > TOML_CONFIG_MAX_SECRETS) {
    snprintf (errbuf, errlen, "too many secrets (%d, max %d)", n, TOML_CONFIG_MAX_SECRETS);
    return -1;
  }

  for (int i = 0; i < n; i++) {
    toml_datum_t entry = secret_arr.u.arr.elem[i];
    if (entry.type != TOML_TABLE) {
      snprintf (errbuf, errlen, "secret[%d]: expected table", i);
      return -1;
    }

    /* key (required) */
    toml_datum_t key = toml_get (entry, "key");
    if (key.type != TOML_STRING) {
      snprintf (errbuf, errlen, "secret[%d]: 'key' must be a string", i);
      return -1;
    }
    if (toml_config_parse_hex_secret (key.u.s, cfg->secrets[i].key) < 0) {
      snprintf (errbuf, errlen, "secret[%d]: 'key' must be exactly 32 hex digits", i);
      return -1;
    }

    /* label (optional) */
    cfg->secrets[i].label[0] = '\0';
    toml_datum_t label = toml_get (entry, "label");
    if (label.type == TOML_STRING) {
      if (strlen (label.u.s) > TOML_SECRET_LABEL_MAX) {
        snprintf (errbuf, errlen, "secret[%d]: label too long (max %d chars)", i, TOML_SECRET_LABEL_MAX);
        return -1;
      }
      if (label.u.s[0] && validate_label (label.u.s) < 0) {
        snprintf (errbuf, errlen, "secret[%d]: label contains invalid characters", i);
        return -1;
      }
      snprintf (cfg->secrets[i].label, sizeof (cfg->secrets[i].label), "%s", label.u.s);
    }

    /* limit (optional, default 0 = unlimited) */
    cfg->secrets[i].limit = 0;
    toml_datum_t limit = toml_get (entry, "limit");
    if (limit.type == TOML_INT64) {
      if (limit.u.int64 < 0) {
        snprintf (errbuf, errlen, "secret[%d]: limit must be non-negative", i);
        return -1;
      }
      cfg->secrets[i].limit = (int) limit.u.int64;
    }

    /* quota (optional, default 0 = unlimited) — bytes or "10G" style */
    cfg->secrets[i].quota = 0;
    toml_datum_t quota = toml_get (entry, "quota");
    if (quota.type == TOML_INT64) {
      if (quota.u.int64 < 0) {
        snprintf (errbuf, errlen, "secret[%d]: quota must be non-negative", i);
        return -1;
      }
      cfg->secrets[i].quota = quota.u.int64;
    } else if (quota.type == TOML_STRING) {
      long long qv = parse_byte_size (quota.u.s, errbuf, errlen);
      if (qv < 0) {
        snprintf (errbuf, errlen, "secret[%d]: invalid quota '%s'", i, quota.u.s);
        return -1;
      }
      cfg->secrets[i].quota = qv;
    }

    /* rate_limit (optional, default 0 = unlimited) — bytes/sec per IP */
    cfg->secrets[i].rate_limit = 0;
    toml_datum_t rate_limit = toml_get (entry, "rate_limit");
    if (rate_limit.type == TOML_INT64) {
      if (rate_limit.u.int64 < 0) {
        snprintf (errbuf, errlen, "secret[%d]: rate_limit must be non-negative", i);
        return -1;
      }
      cfg->secrets[i].rate_limit = rate_limit.u.int64;
    } else if (rate_limit.type == TOML_STRING) {
      long long rv = parse_byte_size (rate_limit.u.s, errbuf, errlen);
      if (rv < 0) {
        snprintf (errbuf, errlen, "secret[%d]: invalid rate_limit '%s'", i, rate_limit.u.s);
        return -1;
      }
      cfg->secrets[i].rate_limit = rv;
    }

    /* max_ips (optional, default 0 = unlimited) */
    cfg->secrets[i].max_ips = 0;
    toml_datum_t max_ips = toml_get (entry, "max_ips");
    if (max_ips.type == TOML_INT64) {
      if (max_ips.u.int64 < 0) {
        snprintf (errbuf, errlen, "secret[%d]: max_ips must be non-negative", i);
        return -1;
      }
      cfg->secrets[i].max_ips = (int) max_ips.u.int64;
    }

    /* expires (optional, default 0 = never) — TOML datetime or integer epoch */
    cfg->secrets[i].expires = 0;
    toml_datum_t expires = toml_get (entry, "expires");
    if (expires.type == TOML_DATETIME || expires.type == TOML_DATETIMETZ) {
      cfg->secrets[i].expires = toml_ts_to_epoch (expires);
    } else if (expires.type == TOML_INT64) {
      if (expires.u.int64 < 0) {
        snprintf (errbuf, errlen, "secret[%d]: expires must be non-negative", i);
        return -1;
      }
      cfg->secrets[i].expires = expires.u.int64;
    }

    cfg->secret_count++;
  }
  return 0;
}

static int parse_dc_overrides (toml_datum_t toptab, struct toml_config *cfg,
                               char *errbuf, int errlen) {
  cfg->dc_override_count = 0;
  toml_datum_t arr = toml_get (toptab, "dc_override");
  if (arr.type == TOML_UNKNOWN) {
    return 0;
  }
  if (arr.type != TOML_ARRAY) {
    snprintf (errbuf, errlen, "'dc_override' must be an array of tables");
    return -1;
  }

  int n = arr.u.arr.size;
  if (n > TOML_CONFIG_MAX_DC_OVERRIDES) {
    snprintf (errbuf, errlen, "too many dc_override entries (%d, max %d)", n, TOML_CONFIG_MAX_DC_OVERRIDES);
    return -1;
  }

  for (int i = 0; i < n; i++) {
    toml_datum_t entry = arr.u.arr.elem[i];
    if (entry.type != TOML_TABLE) {
      snprintf (errbuf, errlen, "dc_override[%d]: expected table", i);
      return -1;
    }

    toml_datum_t dc = toml_get (entry, "dc");
    if (dc.type != TOML_INT64 || dc.u.int64 < 1 || dc.u.int64 > 5) {
      snprintf (errbuf, errlen, "dc_override[%d]: 'dc' must be 1-5", i);
      return -1;
    }
    cfg->dc_overrides[i].dc_id = (int) dc.u.int64;

    toml_datum_t host = toml_get (entry, "host");
    if (host.type != TOML_STRING || !host.u.s[0]) {
      snprintf (errbuf, errlen, "dc_override[%d]: 'host' must be a non-empty string", i);
      return -1;
    }
    snprintf (cfg->dc_overrides[i].host, sizeof (cfg->dc_overrides[i].host), "%s", host.u.s);

    toml_datum_t port = toml_get (entry, "port");
    if (port.type != TOML_INT64 || port.u.int64 < 1 || port.u.int64 > 65535) {
      snprintf (errbuf, errlen, "dc_override[%d]: 'port' must be 1-65535", i);
      return -1;
    }
    cfg->dc_overrides[i].port = (int) port.u.int64;

    cfg->dc_override_count++;
  }
  return 0;
}

static int parse_string_array (toml_datum_t toptab, const char *key,
                               char out[][64], int max, int *count,
                               char *errbuf, int errlen) {
  *count = 0;
  toml_datum_t arr = toml_get (toptab, key);
  if (arr.type == TOML_UNKNOWN) {
    return 0;
  }
  if (arr.type != TOML_ARRAY) {
    snprintf (errbuf, errlen, "'%s' must be an array of strings", key);
    return -1;
  }

  int n = arr.u.arr.size;
  if (n > max) {
    snprintf (errbuf, errlen, "'%s' has too many entries (%d, max %d)", key, n, max);
    return -1;
  }

  for (int i = 0; i < n; i++) {
    toml_datum_t elem = arr.u.arr.elem[i];
    if (elem.type != TOML_STRING) {
      snprintf (errbuf, errlen, "%s[%d]: expected string", key, i);
      return -1;
    }
    snprintf (out[i], 64, "%s", elem.u.s);
    (*count)++;
  }
  return 0;
}

static void get_optional_string (toml_datum_t toptab, const char *key,
                                 char *out, int outlen) {
  toml_datum_t v = toml_get (toptab, key);
  if (v.type == TOML_STRING) {
    snprintf (out, outlen, "%s", v.u.s);
  }
}

static int get_optional_int (toml_datum_t toptab, const char *key, int fallback) {
  toml_datum_t v = toml_get (toptab, key);
  if (v.type == TOML_INT64) {
    return (int) v.u.int64;
  }
  return fallback;
}

static int get_optional_bool (toml_datum_t toptab, const char *key, int fallback) {
  toml_datum_t v = toml_get (toptab, key);
  if (v.type == TOML_BOOLEAN) {
    return v.u.boolean ? 1 : 0;
  }
  return fallback;
}

int toml_config_load (const char *path, struct toml_config *cfg,
                      char *errbuf, int errlen) {
  memset (cfg, 0, sizeof (*cfg));
  cfg->port = 0;
  cfg->stats_port = 0;
  cfg->workers = -1;
  cfg->direct = -1;
  cfg->http_stats = -1;
  cfg->random_padding_only = -1;
  cfg->ipv6 = -1;

  toml_result_t res = toml_parse_file_ex (path);
  if (!res.ok) {
    snprintf (errbuf, errlen, "%s: %s", path, res.errmsg);
    return -1;
  }

  toml_datum_t top = res.toptab;

  /* Network */
  cfg->port = get_optional_int (top, "port", 0);
  cfg->stats_port = get_optional_int (top, "stats_port", 0);
  cfg->workers = get_optional_int (top, "workers", -1);
  cfg->max_connections = get_optional_int (top, "max_connections", 0);
  get_optional_string (top, "bind", cfg->bind, sizeof (cfg->bind));
  cfg->ipv6 = get_optional_bool (top, "ipv6", -1);
  cfg->maxconn = get_optional_int (top, "maxconn", 0);
  get_optional_string (top, "user", cfg->user, sizeof (cfg->user));

  /* Mode */
  cfg->direct = get_optional_bool (top, "direct", -1);
  get_optional_string (top, "proxy_tag", cfg->proxy_tag, sizeof (cfg->proxy_tag));

  /* TLS domains */
  {
    cfg->domain_count = 0;
    toml_datum_t d = toml_get (top, "domain");
    if (d.type == TOML_STRING) {
      /* single domain as string */
      snprintf (cfg->domains[0], sizeof (cfg->domains[0]), "%s", d.u.s);
      cfg->domain_count = 1;
    } else if (d.type == TOML_ARRAY) {
      int n = d.u.arr.size;
      if (n > TOML_CONFIG_MAX_DOMAINS) {
        snprintf (errbuf, errlen, "too many domains (%d, max %d)", n, TOML_CONFIG_MAX_DOMAINS);
        toml_free (res);
        return -1;
      }
      for (int i = 0; i < n; i++) {
        toml_datum_t elem = d.u.arr.elem[i];
        if (elem.type != TOML_STRING) {
          snprintf (errbuf, errlen, "domain[%d]: expected string", i);
          toml_free (res);
          return -1;
        }
        snprintf (cfg->domains[i], sizeof (cfg->domains[i]), "%s", elem.u.s);
      }
      cfg->domain_count = n;
    }
  }

  /* Stats */
  cfg->http_stats = get_optional_bool (top, "http_stats", -1);
  if (parse_string_array (top, "stats_allow_net", cfg->stats_allow_nets,
                          TOML_CONFIG_MAX_STATS_NETS, &cfg->stats_allow_net_count,
                          errbuf, errlen) < 0) {
    toml_free (res);
    return -1;
  }
  cfg->top_ips_per_secret = get_optional_int (top, "top_ips_per_secret", 0);
  if (cfg->top_ips_per_secret < 0) {
    snprintf (errbuf, errlen, "top_ips_per_secret must be non-negative");
    toml_free (res);
    return -1;
  }

  /* IP filtering */
  get_optional_string (top, "ip_blocklist", cfg->ip_blocklist, sizeof (cfg->ip_blocklist));
  get_optional_string (top, "ip_allowlist", cfg->ip_allowlist, sizeof (cfg->ip_allowlist));

  /* Misc */
  cfg->random_padding_only = get_optional_bool (top, "random_padding_only", -1);
  cfg->proxy_protocol = get_optional_bool (top, "proxy_protocol", -1);

  /* DC probes */
  cfg->dc_probe_interval = get_optional_int (top, "dc_probe_interval", -1);

  /* Graceful secret draining */
  cfg->drain_timeout_secs = get_optional_int (top, "drain_timeout_secs", 300);
  if (cfg->drain_timeout_secs < 0) {
    snprintf (errbuf, errlen, "drain_timeout_secs must be >= 0 (0 = infinite)");
    toml_free (res);
    return -1;
  }

  /* SOCKS5 upstream proxy */
  get_optional_string (top, "socks5", cfg->socks5, sizeof (cfg->socks5));

  /* Secrets */
  if (parse_secrets (top, cfg, errbuf, errlen) < 0) {
    toml_free (res);
    return -1;
  }

  /* DC overrides */
  if (parse_dc_overrides (top, cfg, errbuf, errlen) < 0) {
    toml_free (res);
    return -1;
  }

  toml_free (res);
  return 0;
}

int toml_config_reload (const char *path, struct toml_config *cfg) {
  struct toml_config new_cfg;
  char errbuf[512];

  if (toml_config_load (path, &new_cfg, errbuf, sizeof (errbuf)) < 0) {
    kprintf ("config reload failed: %s\n", errbuf);
    return -1;
  }

  /* Warn about non-reloadable fields that changed */
  if (new_cfg.port && cfg->port && new_cfg.port != cfg->port) {
    kprintf ("config reload: 'port' changed (%d -> %d) — restart required\n", cfg->port, new_cfg.port);
  }
  if (new_cfg.stats_port && cfg->stats_port && new_cfg.stats_port != cfg->stats_port) {
    kprintf ("config reload: 'stats_port' changed — restart required\n");
  }
  if (new_cfg.workers >= 0 && cfg->workers >= 0 && new_cfg.workers != cfg->workers) {
    kprintf ("config reload: 'workers' changed — restart required\n");
  }
  if (new_cfg.direct >= 0 && cfg->direct >= 0 && new_cfg.direct != cfg->direct) {
    kprintf ("config reload: 'direct' changed — restart required\n");
  }
  if (new_cfg.domain_count != cfg->domain_count) {
    kprintf ("config reload: 'domain' changed — restart required\n");
  }
  if (new_cfg.maxconn && cfg->maxconn && new_cfg.maxconn != cfg->maxconn) {
    kprintf ("config reload: 'maxconn' changed — restart required\n");
  }
  if (new_cfg.bind[0] && cfg->bind[0] && strcmp (new_cfg.bind, cfg->bind) != 0) {
    kprintf ("config reload: 'bind' changed — restart required\n");
  }
  if (new_cfg.ipv6 >= 0 && cfg->ipv6 >= 0 && new_cfg.ipv6 != cfg->ipv6) {
    kprintf ("config reload: 'ipv6' changed — restart required\n");
  }
  if (new_cfg.user[0] && cfg->user[0] && strcmp (new_cfg.user, cfg->user) != 0) {
    kprintf ("config reload: 'user' changed — restart required\n");
  }
  if (new_cfg.socks5[0] && cfg->socks5[0] && strcmp (new_cfg.socks5, cfg->socks5) != 0) {
    kprintf ("config reload: 'socks5' changed — restart required\n");
  }
  if (new_cfg.proxy_protocol >= 0 && cfg->proxy_protocol >= 0 &&
      new_cfg.proxy_protocol != cfg->proxy_protocol) {
    kprintf ("config reload: 'proxy_protocol' changed — restart required\n");
  }
  if (new_cfg.dc_probe_interval >= 0 && cfg->dc_probe_interval >= 0 &&
      new_cfg.dc_probe_interval != cfg->dc_probe_interval) {
    kprintf ("config reload: 'dc_probe_interval' changed — restart required\n");
  }

  /* Apply reloadable fields */
  memcpy (cfg->secrets, new_cfg.secrets, sizeof (cfg->secrets));
  cfg->secret_count = new_cfg.secret_count;

  memcpy (cfg->stats_allow_nets, new_cfg.stats_allow_nets, sizeof (cfg->stats_allow_nets));
  cfg->stats_allow_net_count = new_cfg.stats_allow_net_count;

  snprintf (cfg->ip_blocklist, sizeof (cfg->ip_blocklist), "%s", new_cfg.ip_blocklist);
  snprintf (cfg->ip_allowlist, sizeof (cfg->ip_allowlist), "%s", new_cfg.ip_allowlist);

  cfg->drain_timeout_secs = new_cfg.drain_timeout_secs;

  kprintf ("config reloaded: %d secret(s)\n", cfg->secret_count);
  return 0;
}
