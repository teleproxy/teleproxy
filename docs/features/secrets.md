---
description: "Configure up to 16 proxy secrets with labels, per-secret connection limits, and byte quotas for fine-grained access control."
---

# Secrets & Limits

## Generating Secrets

Generate a random 16-byte secret:

```bash
teleproxy generate-secret
```

For fake-TLS mode, pass the domain to get the full `ee`-prefixed secret ready for client links:

```bash
teleproxy generate-secret www.google.com
# stdout:  ee<secret><domain-hex>  (use in tg://proxy links)
# stderr:  Secret for -S: <secret>  (use with -S flag)
```

## Multiple Secrets

Up to 16 secrets, each with an optional label:

```bash
./teleproxy ... -S cafe...ab:family -S dead...ef:friends
```

## Secret Labels

Labels identify which secret a connection uses.

CLI:

```bash
./teleproxy ... -S cafe...ab:family -S dead...ef:friends
```

Installer:

```bash
curl -sSL .../install.sh | \
  SECRET_1=cafe...ab SECRET_LABEL_1=family \
  SECRET_2=dead...ef SECRET_LABEL_2=friends \
  sh
```

Docker:

```bash
# Inline labels
SECRET=cafe...ab:family,dead...ef:friends

# Or numbered
SECRET_1=cafe...ab
SECRET_LABEL_1=family
SECRET_2=dead...ef
SECRET_LABEL_2=friends
```

Labels appear in:

- **Logs:** `TLS handshake matched secret [family] from 1.2.3.4:12345`
- **Prometheus:** `teleproxy_secret_connections{secret="family"} 3`
- **Stats:** `secret_family_connections	3`

Unlabeled secrets are auto-labeled `secret_0`, `secret_1`, etc.

Label rules: max 32 chars, alphanumeric plus `_` and `-`.

## Per-Secret Connection Limits

Prevent a leaked secret from consuming all resources:

```bash
# CLI: append :LIMIT after the label
./teleproxy ... -S cafe...ab:family:1000 -S dead...ef:public:200

# Without a label
./teleproxy ... -S cafe...ab::500
```

Installer:

```bash
curl -sSL .../install.sh | \
  SECRET_1=cafe...ab SECRET_LABEL_1=family SECRET_LIMIT_1=1000 \
  SECRET_2=dead...ef SECRET_LABEL_2=public SECRET_LIMIT_2=200 \
  sh
```

Docker:

```bash
# Environment variables
SECRET_LIMIT_1=1000
SECRET_LIMIT_2=200

# Inline
SECRET=cafe...ab:family:1000,dead...ef:public:200
```

When the limit is reached:

- **Fake-TLS (EE):** rejected during TLS handshake — client sees the backend website
- **Obfuscated2 (DD):** connection silently dropped

Multi-worker note: with `-M N` workers, each enforces `limit / N` independently.

Metrics:

- **Stats:** `secret_family_limit 1000`, `secret_family_rejected 42`
- **Prometheus:** `teleproxy_secret_connection_limit{secret="family"} 1000`, `teleproxy_secret_connections_rejected_total{secret="family"} 42`

## Per-Secret Quotas

Cap total bytes transferred (received + sent) per secret. Once exhausted, active connections are closed and new connections are rejected.

TOML config:

```toml
[[secret]]
key = "cafe...ab"
label = "guest"
quota = "10G"    # accepts: bytes (int), or "500M", "10G", "1T"
```

Docker:

```bash
SECRET_QUOTA_1=10737418240   # 10 GB in bytes
```

Quota is cumulative since startup — it does not reset on SIGHUP config reload. Restart the proxy to reset usage.

Metrics:

- **Stats:** `secret_guest_quota 10737418240`, `secret_guest_bytes_total 5368709120`, `secret_guest_rejected_quota 3`
- **Prometheus:** `teleproxy_secret_quota_bytes{secret="guest"} 10737418240`, `teleproxy_secret_bytes_total{secret="guest"} 5368709120`

## Per-IP Rate Limiting

Cap real-time throughput per source IP. Uses a token bucket algorithm — each IP gets a bucket that refills at the configured rate. When the bucket is empty, reads are paused until tokens refill. Unlike quota (which closes connections), rate limiting throttles via TCP backpressure — users see slower speeds, not dropped connections.

TOML config:

```toml
[[secret]]
key = "cafe...ab"
label = "shared"
rate_limit = "10M"   # 10 MB/s per IP (accepts: bytes/sec int, or "500K", "10M")
```

Docker:

```bash
SECRET_RATE_LIMIT_1=10485760   # 10 MB/s in bytes/sec
# or human-readable:
SECRET_RATE_LIMIT_1=10M
```

The rate limit is combined (received + sent) per source IP. Burst size is 1 second of tokens — a new connection can burst up to the rate limit before throttling kicks in.

Multi-worker note: with `-M N` workers, each enforces `rate_limit / N` independently.

Reloadable: changing `rate_limit` on SIGHUP takes effect immediately for new data.

Metrics:

- **Stats:** `secret_shared_rate_limit 10485760`, `secret_shared_rate_limited 42`
- **Prometheus:** `teleproxy_secret_rate_limit_bytes{secret="shared"} 10485760`, `teleproxy_secret_rate_limited_total{secret="shared"} 42`

## Per-Secret Unique IP Limits

Cap how many distinct client IPs can use a secret simultaneously. Additional connections from an already-connected IP are allowed.

TOML config:

```toml
[[secret]]
key = "cafe...ab"
label = "guest"
max_ips = 5
```

Docker:

```bash
SECRET_MAX_IPS_1=5
```

Metrics:

- **Stats:** `secret_guest_max_ips 5`, `secret_guest_unique_ips 3`, `secret_guest_rejected_ips 0`
- **Prometheus:** `teleproxy_secret_max_ips{secret="guest"} 5`, `teleproxy_secret_unique_ips{secret="guest"} 3`

## Secret Expiration

Auto-disable a secret after a timestamp. New connections are rejected; existing connections continue until they close naturally.

TOML config:

```toml
[[secret]]
key = "cafe...ab"
label = "temp"
expires = 2025-06-30T23:59:59Z    # TOML datetime (UTC)
# or: expires = 1751327999         # Unix timestamp
```

Docker:

```bash
SECRET_EXPIRES_1=2025-06-30T23:59:59Z
# or: SECRET_EXPIRES_1=1751327999
```

Metrics:

- **Stats:** `secret_temp_expires 1751327999`, `secret_temp_rejected_expired 12`
- **Prometheus:** `teleproxy_secret_expires_timestamp{secret="temp"} 1751327999`

## Graceful Draining on Removal

When a secret is removed from the TOML and you `kill -HUP` the proxy, in-flight
connections that authenticated under that secret keep working — the slot
transitions to a draining state, new connections matching the removed secret
are rejected, and the slot is released only after all existing connections
have closed (or after `drain_timeout_secs` seconds, whichever comes first).
This enables zero-downtime secret rotation without dropping users mid-session.

TOML config:

```toml
drain_timeout_secs = 300   # 0 = infinite (never force-close), default 300
```

Workflow for rotating a secret without dropping users:

1. Add the new secret to `config.toml` alongside the old one.
2. `kill -HUP $(pidof teleproxy)` — both secrets are now active.
3. Update clients to the new secret at your own pace.
4. Remove the old secret from `config.toml`.
5. `kill -HUP` again — old secret enters draining state, new connections
   matching it are rejected, in-flight ones keep going until they close.
6. After all clients have migrated (or `drain_timeout_secs` elapses), the
   slot is released and metrics for it disappear.

Re-adding a draining secret before the timeout revives it — the same slot,
counters, and IP tracking carry over.  Pinned `-S` CLI secrets are immutable
across SIGHUP and never drain.

Metrics for a draining secret:

- **Stats:** `secret_<label>_draining 1`, `secret_<label>_drain_age_seconds`,
  `secret_<label>_rejected_draining`, `secret_<label>_drain_forced`
- **Prometheus:** `teleproxy_secret_draining{secret="..."}`,
  `teleproxy_secret_drain_age_seconds{secret="..."}`,
  `teleproxy_secret_rejected_draining_total{secret="..."}`,
  `teleproxy_secret_drain_forced_total{secret="..."}`

Capacity: at most 16 active secrets at any moment, plus up to 16 additional
draining slots.  Rotating all 16 secrets twice in quick succession before the
first batch finishes draining will fail the second reload — wait for drain to
complete or set a smaller `drain_timeout_secs` to reclaim slots faster.

## Per-IP Top-N Metrics

Surface the heaviest client IPs per secret in `/metrics` to diagnose rogue clients. Disabled by default — opt in with a top-level config knob, not a per-secret one (cardinality is an operator concern).

TOML config:

```toml
top_ips_per_secret = 10  # 0 disables; max 32
```

Docker:

```bash
TOP_IPS_PER_SECRET=10
```

When enabled, three new Prometheus metric families are emitted, each labelled `{secret="...", ip="..."}` for the top-N heaviest IPs per secret (sorted by total bytes):

- `teleproxy_secret_ip_connections` — current active connections from this IP (gauge)
- `teleproxy_secret_ip_bytes_received_total` — bytes received from this IP (counter)
- `teleproxy_secret_ip_bytes_sent_total` — bytes sent to this IP (counter)

Cardinality is bounded at `top_ips_per_secret × secret_count` labelled samples per family. Counters reset when an IP entry is recycled — Prometheus `rate()` handles this correctly.

## TOML Config Example

All per-secret features combined:

```toml
[[secret]]
key = "cafe01234567890abcafe01234567890a"
label = "family"
limit = 100
quota = "50G"
rate_limit = "10M"
max_ips = 10
expires = 2026-12-31T23:59:59Z

[[secret]]
key = "dead01234567890abcead01234567890a"
label = "guest"
limit = 50
quota = "5G"
rate_limit = "2M"
max_ips = 3
expires = 2025-06-30T00:00:00Z
```
