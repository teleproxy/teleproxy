---
description: "Complete reference for Teleproxy Docker environment variables: secrets, TLS domains, access control, monitoring, and connection limits."
---

# Docker Configuration

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET` | auto-generated | Proxy secret(s) — 32 hex chars each. Single, comma-separated, or with labels |
| `SECRET_1`...`SECRET_16` | — | Numbered secrets (combined with `SECRET` if both set) |
| `SECRET_LABEL_1`...`SECRET_LABEL_16` | — | Labels for numbered secrets |
| `SECRET_LIMIT_1`...`SECRET_LIMIT_16` | — | Per-secret connection limits |
| `SECRET_QUOTA_1`...`SECRET_QUOTA_16` | — | Per-secret byte quota (e.g. `10737418240` for 10 GB) |
| `SECRET_MAX_IPS_1`...`SECRET_MAX_IPS_16` | — | Per-secret unique IP limits |
| `SECRET_EXPIRES_1`...`SECRET_EXPIRES_16` | — | Per-secret expiration (TOML datetime or Unix timestamp) |
| `PORT` | 443 | Client connection port (internal listen port) |
| `EXTERNAL_PORT` | `$PORT` | Port advertised in connection links and `/link` QR codes. Set to the host-side port when Docker maps a different external port (e.g. `-p 4443:443` → `EXTERNAL_PORT=4443`) |
| `STATS_PORT` | 8888 | Statistics endpoint port |
| `WORKERS` | 1 | Worker processes |
| `PROXY_TAG` | — | Tag from @MTProxybot (channel promotion) |
| `DIRECT_MODE` | false | Connect directly to Telegram DCs |
| `RANDOM_PADDING` | false | Enable random padding only (DD mode) |
| `EXTERNAL_IP` | auto-detected | Public IP for NAT environments |
| `EE_DOMAIN` | — | Domain for Fake-TLS (SNI hostname advertised to clients) |
| `EE_BACKEND` | — | Optional backend for fake-TLS camouflage. Splits the SNI domain (`EE_DOMAIN`) from the connect target. Accepts `host:port`, `[ipv6]:port`, or `unix:/path` for a local socket — useful when `EE_DOMAIN` is a public SNI like `cloudflare.com` but the actual backend is a local nginx |
| `IP_BLOCKLIST` | — | Path to CIDR blocklist file |
| `IP_ALLOWLIST` | — | Path to CIDR allowlist file |
| `STATS_ALLOW_NET` | — | Comma-separated CIDR ranges to allow stats access from (e.g. `100.64.0.0/10,fd00::/8`) |
| `SOCKS5_PROXY` | — | Route upstream DC connections through a SOCKS5 proxy (`socks5://[user:pass@]host:port`) |
| `CONFIG_DOWNLOAD_PROXY` | `$SOCKS5_PROXY` | Outbound proxy for fetching `proxy-multi.conf` from `core.telegram.org`. Accepts any URL `curl -x` understands (`http://`, `https://`, `socks5://`, `socks5h://`). Defaults to `SOCKS5_PROXY` if unset |
| `PROXY_PROTOCOL` | false | Enable PROXY protocol v1/v2 on client listeners (for HAProxy/nginx/NLB) |
| `DC_OVERRIDE` | — | Comma-separated DC address overrides for direct mode (e.g. `2:1.2.3.4:443,2:5.6.7.8:443`) |
| `MAX_CONNECTIONS` | 10000 | Maximum file descriptors (≈ connections) per worker. Raise on high-memory servers, lower on constrained ones. Hard limit: 65536 |
| `DC_PROBE_INTERVAL` | — | Seconds between DC health probes (e.g. `30`). Disabled when absent or `0` |

Maximum 16 secrets (binary limit). See the [tuning guide](/deployment/tuning/) for connection-limit sizing recommendations.

## Docker Compose

Simple setup:

```yaml
services:
  teleproxy:
    image: ghcr.io/teleproxy/teleproxy:latest
    ports:
      - "443:443"
      - "8888:8888"
    restart: unless-stopped
```

With `.env` file:

```bash
SECRET=your_secret_here
PROXY_TAG=your_proxy_tag_here
```

## Volume Mounting

The container stores `proxy-multi.conf` in `/opt/teleproxy/data/`. Mount a volume to persist the configuration across restarts:

```bash
docker run -d \
  --name teleproxy \
  -p 443:443 \
  -v /path/to/host/data:/opt/teleproxy/data \
  --restart unless-stopped \
  ghcr.io/teleproxy/teleproxy:latest
```

`proxy-secret` is baked into the image at build time — no volume needed for it.

If `core.telegram.org` is unreachable, the container uses the cached config from the volume.

## Automatic Config Refresh

A cron job refreshes the Telegram DC configuration every 6 hours. It downloads the latest config, validates it, compares it with the existing one, and hot-reloads the proxy via `SIGHUP` if the config changed. No configuration needed.

If direct connections to `core.telegram.org` are blocked from the host, set `CONFIG_DOWNLOAD_PROXY` to route the download through an outbound proxy:

```bash
docker run -d -e CONFIG_DOWNLOAD_PROXY=socks5://10.0.0.1:1080 ... ghcr.io/teleproxy/teleproxy:latest
```

When unset, falls back to `SOCKS5_PROXY` if that's configured for upstream DC routing.

## Health Check

The Docker image includes a built-in health check that monitors the stats endpoint:

```bash
docker ps  # Check the STATUS column for health
```

The health check runs every 30 seconds after a 60-second startup grace period.
