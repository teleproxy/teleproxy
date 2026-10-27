---
description: "Complete reference for Teleproxy's native TOML configuration, including network, fake-TLS, secrets, monitoring, ACLs, and direct-mode settings."
---

# TOML Configuration

Pass a TOML file with `--config`:

```bash
teleproxy --config /etc/teleproxy/config.toml
```

This page documents native Teleproxy options. Docker environment variables are
documented separately under [Docker Configuration](../docker/configuration.md).

## Complete example

```toml
# Listeners
port = 443
stats_port = 8888
external_port = 443
bind = "0.0.0.0"
ipv6 = true
workers = 1
max_connections = 10000
maxconn = 65536
user = "teleproxy"

# Upstream mode
direct = true

# Fake-TLS. A string is enough when the SNI name is also the backend.
domain = "cover.example.com"

# Monitoring
http_stats = true
stats_allow_net = ["100.64.0.0/10", "fd00::/8"]
top_ips_per_secret = 20
ja4_log = false
dc_probe_interval = 30

# Access and transport
ip_blocklist = "/etc/teleproxy/blocklist.txt"
ip_allowlist = "/etc/teleproxy/allowlist.txt"
random_padding_only = false
proxy_protocol = false
mss_clamp = true
socks5 = "socks5://127.0.0.1:1080"

# Removed secrets keep existing sessions for this many seconds.
drain_timeout_secs = 300

[[secret]]
key = "0123456789abcdef0123456789abcdef"
label = "default"
limit = 1000
quota = "100G"
rate_limit = "10M"
max_ips = 20
expires = 2026-12-31T23:59:59Z
```

Only `key` is required inside each `[[secret]]` block. Remove options you do not
need.

## Network

| Key | Type | Default | Meaning |
|---|---|---:|---|
| `port` | integer | unset | Client-facing MTProto listener port. |
| `stats_port` | integer | unset | HTTP `/stats`, `/metrics`, and `/link` listener port. |
| `external_port` | integer | `port` | Port advertised by `/link`; useful behind port mapping or NAT. |
| `bind` | string | all IPv4 interfaces | Listener bind address. |
| `ipv6` | boolean | `false` | Enable IPv6 listeners and direct-DC addresses. |
| `workers` | integer | `0` | Number of worker processes. |
| `max_connections` | integer | engine default | Accepted client connections per worker. |
| `maxconn` | integer | engine default | Process file-descriptor/connection table limit. |
| `user` | string | current user | Drop privileges to this user after opening listeners. |

Changing these values requires a restart.

## Upstream mode

| Key | Type | Default | Meaning |
|---|---|---:|---|
| `direct` | boolean | `false` | Connect directly to Telegram DCs instead of ME relays. |
| `proxy_tag` | string | unset | 32-hex promotion tag for ME relay mode; incompatible with `direct`. |
| `socks5` | string | unset | Route direct-mode DC connections through `socks5://` or `socks5h://`. Requires `direct = true`. |

Relay mode still needs Telegram's binary relay files because they are not TOML
settings:

```bash
teleproxy --config /etc/teleproxy/config.toml \
  --aes-pwd /etc/teleproxy/proxy-secret \
  /etc/teleproxy/proxy-multi.conf
```

Direct mode needs neither file.

## Fake-TLS domains

For one domain whose hostname is also the HTTPS backend:

```toml
domain = "cover.example.com"
```

Specify a separate backend, several domains, a fixed address, or a Unix socket
with an array:

```toml
domain = [
  { name = "one.example.com", backend = "127.0.0.1:8443" },
  { name = "two.example.com", backend = "backend.example.net:443" },
  { name = "*.example.org", backend = "origin.example.org:443" },
  { name = "local.example.com", backend = "unix:/run/nginx.sock" },
]
```

Up to 16 entries are accepted. Domain changes require a restart.

## Secrets

Repeat `[[secret]]` up to 16 times:

```toml
[[secret]]
key = "0123456789abcdef0123456789abcdef"
label = "family"
limit = 50
quota = "25G"
rate_limit = "5M"
max_ips = 10
expires = 1798761599
```

| Key | Type | Default | Meaning |
|---|---|---:|---|
| `key` | string | required | Exactly 32 hexadecimal digits. |
| `label` | string | empty | Metrics label, up to 32 safe characters. |
| `limit` | integer | `0` | Simultaneous connections; `0` is unlimited. |
| `quota` | integer or size | `0` | Total uploaded plus downloaded bytes; `0` is unlimited. |
| `rate_limit` | integer or size | `0` | Bytes per second per client IP; `0` is unlimited. |
| `max_ips` | integer | `0` | Unique client IPs; `0` is unlimited. |
| `expires` | integer or datetime | `0` | Unix timestamp or TOML datetime; `0` never expires. |

Size strings accept binary suffixes such as `"10K"`, `"50M"`, and `"100G"`.
Secrets and `drain_timeout_secs` reload on SIGHUP. The contents of configured
ACL files are reread without changing their paths.

## Monitoring

| Key | Type | Default | Meaning |
|---|---|---:|---|
| `http_stats` | boolean | `false` | Enable the HTTP listener. |
| `stats_allow_net` | string array | private networks | Additional CIDRs allowed to read HTTP endpoints. |
| `top_ips_per_secret` | integer | `0` | Export this many top client IPs per secret; `0` disables it. |
| `ja4_log` | boolean | `false` | Log each ClientHello JA4 and SNI at verbose level 2. |
| `dc_probe_interval` | integer | `0` | Seconds between direct DC health probes; `0` disables them. |

The HTTP endpoints deliberately return 404 to source addresses outside private
networks and `stats_allow_net`. See [Monitoring](../features/monitoring.md).

## Access and transport

| Key | Type | Default | Meaning |
|---|---|---:|---|
| `ip_blocklist` | string | unset | Path to rejected IPv4/IPv6 CIDRs. |
| `ip_allowlist` | string | unset | Path to the exclusive allowlist. |
| `random_padding_only` | boolean | `false` | Require clients using random-padding secrets. |
| `proxy_protocol` | boolean | `false` | Accept PROXY protocol v1/v2 on client listeners. |
| `mss_clamp` | boolean | `true` | Enable automatic ClientHello fragmentation. |
| `drain_timeout_secs` | integer | `300` | Grace period for removed secrets; `0` never force-closes. |

## Direct DC overrides

Replace built-in addresses for a DC by repeating `[[dc_override]]`:

```toml
[[dc_override]]
dc = 2
host = "149.154.167.51"
port = 443

[[dc_override]]
dc = 2
host = "2001:67c:4e8:f002::a"
port = 443
```

`dc` must be a production DC (1-5) or a CDN DC (201-299). `host` must be an IPv4 or IPv6 address written without brackets; hostnames are not resolved. At most 16 override rows are accepted, with up to four addresses per DC. A row that breaks any of these rules is a config error: the proxy refuses to start, and a SIGHUP reload fails and keeps the running configuration.

## Reload behavior

Reload without dropping established sessions:

```bash
systemctl reload teleproxy
# or
kill -HUP "$(pidof teleproxy)"
```

Secrets, ACL file contents, `ja4_log`, and `drain_timeout_secs` reload.
Listener, mode, domain, worker, SOCKS5, stats allow networks, ACL paths, and DC
settings require a restart; Teleproxy logs a warning for most non-reloadable
changes.
