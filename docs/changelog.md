---
description: "Release history for Teleproxy. Version details, new features, bug fixes, and breaking changes across all releases."
---

# Changelog

## Unreleased

Graceful connection draining on secret removal ([#45](https://github.com/teleproxy/teleproxy/issues/45)).

- **Zero-downtime secret rotation** — removing a secret from `config.toml` and sending SIGHUP no longer drops the in-flight connections that were authenticated under it. The slot enters a "draining" state: new connections matching that secret are rejected, but existing ones keep working until they close on their own or `drain_timeout_secs` (default 300, `0` = infinite) elapses. Re-adding a draining secret revives the same slot — counters and IP tracking carry over.
- New TOML option `drain_timeout_secs` (reloadable). Pinned `-S` CLI secrets are immutable across SIGHUP and never drain.
- New stats: `secret_<lbl>_draining`, `secret_<lbl>_drain_age_seconds`, `secret_<lbl>_rejected_draining`, `secret_<lbl>_drain_forced`. Same fields exposed in Prometheus as `teleproxy_secret_draining`, `teleproxy_secret_drain_age_seconds`, `teleproxy_secret_rejected_draining_total`, `teleproxy_secret_drain_forced_total`.
- Slot capacity expanded internally: 16 active secrets at a time as before, plus up to 16 additional draining slots.
- Fixes a latent bug where the per-secret connection counter could go negative if a TLS connection was closed between the TLS handshake and the obfs2 init.

## 4.9.0

PROXY protocol v1/v2 listener support ([#50](https://github.com/teleproxy/teleproxy/issues/50)) and per-IP top-N Prometheus metrics ([#46](https://github.com/teleproxy/teleproxy/issues/46)).

- **PROXY protocol** — accept HAProxy PROXY protocol v1 (text) and v2 (binary) headers on client listeners. Required when running behind a load balancer (HAProxy, nginx, AWS NLB) that injects client IP. Enable with `--proxy-protocol` (CLI), `proxy_protocol = true` (TOML), or `PROXY_PROTOCOL=true` (Docker).
- Auto-detects v1 and v2 headers, extracts real client IP, re-checks IP ACLs against the real address.
- v2 LOCAL command accepted for load balancer health check probes.
- New Prometheus metrics: `teleproxy_proxy_protocol_connections_total`, `teleproxy_proxy_protocol_errors_total`.
- **Per-IP top-N metrics** — opt-in `top_ips_per_secret = N` (TOML) or `TOP_IPS_PER_SECRET=N` (Docker) exposes the top-N heaviest client IPs per secret in `/metrics`. Three new families: `teleproxy_secret_ip_connections`, `teleproxy_secret_ip_bytes_received_total`, `teleproxy_secret_ip_bytes_sent_total`. Sorted by total bytes; cap at 32 per secret to keep Prometheus cardinality bounded. Default 0 (disabled, zero overhead). Useful for diagnosing the "proxy works for 5 minutes then stops" complaint pattern alongside the Grafana dashboard.
- Fix auto-generated secret not written to TOML config — `start.sh` now correctly stores the generated secret in the TOML config.
- Documentation: complete SEO overhaul with per-page meta descriptions, OpenGraph tags, JSON-LD structured data, and robots.txt.
- Translations: Russian documentation now at 100% coverage, Farsi and Vietnamese expanded to 38%.
- TON wallet added as a donation option alongside Tribute.

## 4.8.0

DC health probes ([#47](https://github.com/teleproxy/teleproxy/issues/47)).

- **DC latency probes** - periodic TCP handshake measurement to all 5 Telegram DCs, exposed as Prometheus histograms (`teleproxy_dc_latency_seconds`), failure counters, and last-latency gauges. Helps operators diagnose slow downloads and pick optimal DC routing.
- Disabled by default. Enable with `--dc-probe-interval 30` (CLI), `dc_probe_interval = 30` (TOML), or `DC_PROBE_INTERVAL=30` (Docker env).
- Probes run in the master process only. Completion is tracked via non-blocking poll to preserve sub-millisecond accuracy.
- Text stats endpoint includes per-DC latency, average, count, and failure fields.

## 4.7.0

Per-secret quotas, unique-IP limits, and expiration ([#26](https://github.com/teleproxy/teleproxy/issues/26)).

- **Data quota** — cap total bytes transferred per secret; active connections are closed and new ones rejected when exhausted. Configurable in bytes or human-readable sizes (`quota = "10G"`)
- **Unique IP limit** — cap how many distinct client IPs can use a secret simultaneously (`max_ips = 5`). Additional connections from an already-connected IP are always allowed
- **Secret expiration** — auto-disable a secret after a timestamp (`expires = 2025-12-31T23:59:59Z`). Existing connections continue; only new ones are rejected
- Per-reason rejection counters in Prometheus and plain-text stats (`rejected_quota`, `rejected_ips`, `rejected_expired`)
- Docker env vars: `SECRET_QUOTA_N`, `SECRET_MAX_IPS_N`, `SECRET_EXPIRES_N`
- SOCKS5 upstream proxy support ([#22](https://github.com/teleproxy/teleproxy/issues/22))
- One-click cloud deploy page
- Documentation: install/upgrade instructions, SOCKS5 docs, Observatory link

## 4.6.0

DPI resistance and operational improvements.

- **ServerHello size variation** widened from ±1 to ±32 bytes, mimicking the natural variation in certificate chain and session ticket sizes seen from real TLS servers
- **ServerHello fragmentation**: ServerHello and CCS+AppData are now sent as separate TCP segments, defeating DPI that pattern-matches the full handshake response in a single packet
- Docker healthcheck respects custom `STATS_PORT` — previously hardcoded to 8888, now uses `${STATS_PORT:-8888}` ([#38](https://github.com/teleproxy/teleproxy/issues/38))
- `install.sh` supports multiple secrets via comma-separated `SECRET` or numbered `SECRET_N` variables
- `/link` endpoint serves connection links as HTML pages with scannable QR codes

New documentation: [DPI Resistance](features/dpi-resistance.md) — covers server-side mitigations, recommended setup, and client-side bypass tools.

!!! note "Client-side detection"
    The primary detection vector for MTProxy fake-TLS in Russia is the **Telegram client's TLS fingerprint**, which cannot be fixed server-side. Telegram Desktop [fixed several fingerprint artifacts](https://github.com/telegramdesktop/tdesktop/pull/30513); keep clients updated. For affected networks, client-side bypass tools like [zapret](https://github.com/bol-van/zapret) and [GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI) can help.

## 4.5.0

QR codes for connection links.

- `teleproxy link` subcommand prints a proxy URL and renders a scannable QR code in the terminal using UTF-8 half-block characters
- Docker `start.sh` and `install.sh` now display QR codes automatically at startup — point a phone camera at the screen to connect
- Vendored nayuki/QR-Code-generator (MIT) for zero-dependency QR rendering on any platform
- E2E tests decode the rendered QR output with pyzbar and verify it matches the expected URL
- Documentation: new "Connection Links" page (en + ru)

## 4.4.0

- `teleproxy check` diagnostic subcommand — validates configuration and tests connectivity before accepting clients. Checks DC reachability, NTP clock drift, fake-TLS domain probe, and SNI/DNS mismatch. Exit 0/1/2 for pass/fail/bad-args.

## 4.3.0

Direct mode connection resilience.

- IPv6 auto-detection: probe at startup, enable without `-6` if reachable
- Multiple addresses per DC with synchronous failover on connect failure
- Connection retry with exponential backoff (200ms–800ms, 3 attempts)
- `--dc-override dc_id:host:port` to add or replace DC addresses (repeatable). Docker: `DC_OVERRIDE=2:1.2.3.4:443,2:5.6.7.8:443`
- New stat: `direct_dc_retries` / `teleproxy_direct_dc_retries_total`

## 4.2.1

- Fix aarch64 build: remove unused x86-only `sys/io.h` include
- Add native ARM64 glibc build to CI (catches platform-specific issues masked by Alpine/musl)

## 4.2.0

- `--stats-allow-net CIDR` flag to extend stats endpoint access beyond RFC1918 ranges (repeatable). Docker: `STATS_ALLOW_NET=100.64.0.0/10,fd00::/8`

## 4.1.0

MTProto transport protocol compliance improvements.

- Detect and log transport error codes (-404, -429, etc.) from DCs in direct mode
- Detect transport error codes in medium mode client parse path
- Track quick ACK packets with `teleproxy_quickack_packets_total` counter
- Track transport errors with `teleproxy_transport_errors_total` counter

## 4.0.0

Rebrand to Teleproxy. Binary renamed from `mtproto-proxy` to `teleproxy`.

- Binary name: `teleproxy` (was `mtproto-proxy`)
- Prometheus metrics prefix: `teleproxy_` (was `mtproxy_`)
- Docker user/paths: `/opt/teleproxy/` (was `/opt/mtproxy/`)
- Environment variables: `TELEPROXY_*` (old `MTPROXY_*` still accepted with deprecation warning)
- Docker image includes backward-compat symlink `mtproto-proxy -> teleproxy`
- CLI flags and behavior unchanged
