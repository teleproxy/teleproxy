---
description: "Route Teleproxy outbound connections through a SOCKS5 proxy when the server IP is blocked by Telegram or for origin hiding."
---

# SOCKS5 Upstream Proxy

Route all outbound connections to Telegram DCs through a SOCKS5 proxy:

```
Client -> Teleproxy -> SOCKS5 proxy -> Telegram DC
```

This is useful when the server's IP is blocked by Telegram or when you want to hide the server's origin from Telegram's network.

## Configuration

### Docker

```bash
docker run -d \
  --name teleproxy \
  -p 443:443 \
  -e SOCKS5_PROXY=socks5://proxy.example.com:1080 \
  -e DIRECT_MODE=true \
  --restart unless-stopped \
  ghcr.io/teleproxy/teleproxy:latest
```

With authentication:

```bash
-e SOCKS5_PROXY=socks5://user:pass@proxy.example.com:1080
```

### TOML config

```toml
socks5 = "socks5://proxy.example.com:1080"
```

### CLI flag

```bash
./teleproxy --direct --socks5 socks5://user:pass@proxy.example.com:1080 -H 443 -S <secret> ...
```

## Connecting to a SOCKS5 proxy on the Docker host

Two pieces have to line up when the SOCKS5 proxy runs on the same machine as the
container:

**1. Resolve the host from inside the container.**

`127.0.0.1` inside a bridge-network container points at the container itself,
not the host. Use `host.docker.internal`:

| Platform | Setup |
|----------|-------|
| Docker Desktop (macOS, Windows) | Wired up automatically, no flags needed |
| Linux | Pass `--add-host=host.docker.internal:host-gateway` |

**2. Bind the SOCKS5 daemon to a non-loopback address.**

A daemon bound only to `127.0.0.1` is unreachable from any container on a
bridge network, regardless of `host.docker.internal`. Bind it to `0.0.0.0`
(or to the docker bridge IP, e.g. `172.17.0.1`):

```bash
# Won't work — only listens on host loopback
ssh -D 127.0.0.1:1080 user@hop.example.com

# Works — reachable from containers
ssh -D 0.0.0.0:1080 user@hop.example.com
```

The same applies to dante, gost, 3proxy, sing-box, and any other SOCKS5 server.
Check the listen address with `ss -ltnp | grep 1080`.

**Verify before launching teleproxy:**

```bash
docker run --rm --add-host=host.docker.internal:host-gateway alpine \
  sh -c 'apk add -q curl && curl -sS --socks5 host.docker.internal:1080 https://api.telegram.org'
```

If that prints the Telegram API banner, teleproxy will work too:

```bash
docker run -d \
  --name teleproxy \
  -p 443:443 \
  --add-host=host.docker.internal:host-gateway \
  -e SOCKS5_PROXY=socks5://host.docker.internal:1080 \
  -e DIRECT_MODE=true \
  ghcr.io/teleproxy/teleproxy:latest
```

`--network host` is the simplest fallback when the host port is free, but it is
not required.

## URL format

Two schemes are supported:

| Scheme | DNS resolution | Use case |
|--------|---------------|----------|
| `socks5://` | Local (teleproxy resolves DC addresses) | Default — works with most SOCKS5 proxies |
| `socks5h://` | Remote (SOCKS5 proxy resolves hostnames) | Privacy-sensitive setups where DNS should not leak |

Full format: `socks5[h]://[user:pass@]host:port`

## Authentication

- **Anonymous**: `socks5://host:port` — no credentials, proxy must allow unauthenticated access
- **Username/Password**: `socks5://user:pass@host:port` — RFC 1929 authentication

## Monitoring

SOCKS5 connection stats are exposed on the stats endpoints:

`/stats` (tab-separated):

```
socks5_enabled	1
socks5_connects_attempted	42
socks5_connects_succeeded	40
socks5_connects_failed	2
```

`/metrics` (Prometheus):

```
teleproxy_socks5_connects_attempted_total 42
teleproxy_socks5_connects_succeeded_total 40
teleproxy_socks5_connects_failed_total 2
```

## Notes

- Works with both direct mode and ME relay mode
- Not reloadable via SIGHUP — requires a restart to change the SOCKS5 proxy
- IPv6 target addresses are supported if the SOCKS5 proxy supports them
