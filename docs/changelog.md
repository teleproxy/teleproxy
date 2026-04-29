---
description: "Release history for Teleproxy. Version details, new features, bug fixes, and breaking changes across all releases."
---

# Changelog

## Unreleased

- **`CONFIG_DOWNLOAD_PROXY` env var for the proxy-multi.conf download** ([#61](https://github.com/teleproxy/teleproxy/issues/61)). Hosts that can't reach `core.telegram.org` directly can now route the config refresh through an outbound HTTP or SOCKS proxy. Accepts any URL `curl -x` understands (`http://`, `https://`, `socks5://`, `socks5h://`, with optional `user:pass@`). Falls back to `SOCKS5_PROXY` when unset, so users who already proxy DC traffic don't need to set anything new. Applies to the initial fetch in `start.sh` and the 6-hour cron refresh.
- **Split SNI domain from camouflage backend** ([#62](https://github.com/teleproxy/teleproxy/issues/62)). The fake-TLS feature used to require `EE_DOMAIN` to be both the SNI hostname and the backend connect target — operators worked around it by editing `/etc/hosts`. New `EE_BACKEND` env var separates the two: `EE_DOMAIN` keeps a clean public SNI name like `cloudflare.com`, while `EE_BACKEND` points at the actual backend (`127.0.0.1:8443`, `[::1]:8443`, or `unix:/run/nginx.sock`). Reality-style. Available as TOML too: `domain = [{ name = "cloudflare.com", backend = "127.0.0.1:8443" }]`. The legacy `EE_DOMAIN=host:port` and `domain = "..."` strings still work unchanged.

## 4.12.2

Build hygiene release. No runtime changes.

- **Clang x86_64 build support** ([#68](https://github.com/teleproxy/teleproxy/pull/68)). `make CC=clang` now compiles cleanly on Linux x86_64 — `src/common/crc32.c` previously relied on GCC-only `__builtin_ia32_*` names for SSE/PCLMUL ops; clang gets `_mm_*` intrinsic shims for the missing ones. The shim block is gated to `__x86_64__`/`__i386__` so Apple Silicon clang isn't affected.
- **Clang x86_64 CI job** ([#72](https://github.com/teleproxy/teleproxy/issues/72)). New `build-clang` job in the test matrix runs `make CC=clang` so future regressions in the clang build path surface in CI instead of in third-party packaging.

## 4.12.1

Hotfix for log spam introduced by the 4.12.0 unique-IPs counter rework.

- **Fix `WARNING: IP tracking table full for secret 0` flooding docker logs** ([#71](https://github.com/teleproxy/teleproxy/issues/71)). The 4.12.0 fix for [#70](https://github.com/teleproxy/teleproxy/issues/70) made every secret populate a fixed-size 256-entry per-IP table; on a busy public proxy with no `max_ips` or `rate_limit` configured, the table fills as soon as ~256 distinct source IPs have connected and every subsequent unique client logs a warning. Plain secrets now bypass the precise table entirely and feed `teleproxy_secret_unique_ips` from a per-secret Bloom filter — bounded memory, no overflow, ~0.5% FPR at 10K IPs.
- **Throttle the table-full warning** to once per minute per slot for limit-bearing secrets where `max_ips` legitimately exceeds the table size. The message now also includes the secret label and a hint to raise `max_ips` or check the configuration.
- The macro `SECRET_MAX_TRACKED_IPS` is now overridable at build time (`make EXTRA_CFLAGS="-DSECRET_MAX_TRACKED_IPS=N"`), used by the new `make test-table-full` regression test.

## 4.12.0

Bug fixes for Docker deployments and per-secret metrics.

- **Fix `teleproxy_secret_unique_ips` always reporting 0** ([#70](https://github.com/teleproxy/teleproxy/issues/70)). The counter only ever incremented for secrets that had `max_ips` or `rate_limit` configured — a stale guard inside `ip_track_connect()` that broke the metric for every plain secret. Removed the guard so the IP-tracking table populates for all secrets. Also clarified the metric type: `teleproxy_secret_unique_ips` is `counter` (cumulative count of distinct source IPs since startup), not `gauge`.
- **Clarified `teleproxy_secret_bytes_received_total` / `_sent_total` HELP text** ([#70](https://github.com/teleproxy/teleproxy/issues/70)). The labels are technically correct ("received from clients" = uploads, "sent to clients" = downloads) but easy to misread from a client perspective. The HELP lines now explicitly call out the direction. Note: these counters increment in direct mode only — relay-mode aggregation is a separate gap, tracked for a follow-up.
- **Fix Docker `SECRET=hex:label,hex:label` writing the entire string as the TOML key** ([#67](https://github.com/teleproxy/teleproxy/issues/67)). The numbered-secret path (`SECRET_LABEL_N`) was already correct; the comma-separated path now mirrors it and writes a separate `label = ...` line.
- **New `EXTERNAL_PORT` env var** ([#66](https://github.com/teleproxy/teleproxy/issues/66)) for advertising a different port in the connection link than the internal listen port — needed when Docker maps `-p 4443:443`. Also added a matching `external_port` TOML option, consumed by both the operator-printed connection URL and the `/link` HTML page (QR codes).

## 4.11.0

SOCKS5 upstream support in the check command ([#57](https://github.com/teleproxy/teleproxy/issues/57)) and a new Cloudflare Spectrum deployment guide ([#55](https://github.com/teleproxy/teleproxy/issues/55)).

- **`teleproxy check` now routes DC probes through the configured SOCKS5 proxy** — new `--socks5 URL` CLI flag, also reads from the `socks5` field in TOML config. Useful for environments where the proxy itself sits behind a SOCKS5 upstream.
- Handle buffer allocation failures gracefully instead of crashing ([#58](https://github.com/teleproxy/teleproxy/issues/58)). Under memory pressure, `rwm_alloc` and related functions could return NULL and trigger a segfault. Now they fail the connection cleanly.
- Fix PROXY protocol metrics always reporting 0 in multi-worker mode ([#53](https://github.com/teleproxy/teleproxy/issues/53)). `teleproxy_proxy_protocol_connections_total` and `teleproxy_proxy_protocol_errors_total` were not aggregated from worker processes — the master read its own zero copy. Both the text stats and Prometheus endpoints now report correct values.
- New [deployment guide](/deployment/cloudflare-spectrum/) for running behind Cloudflare Spectrum.

## 4.10.0

Graceful connection draining on secret removal ([#45](https://github.com/teleproxy/teleproxy/issues/45)) and a brand-new signed RPM repository ([#21](https://github.com/teleproxy/teleproxy/issues/21)).

- **Zero-downtime secret rotation** — removing a secret from `config.toml` and sending SIGHUP no longer drops the in-flight connections that were authenticated under it. The slot enters a "draining" state: new connections matching that secret are rejected, but existing ones keep working until they close on their own or `drain_timeout_secs` (default 300, `0` = infinite) elapses. Re-adding a draining secret revives the same slot — counters and IP tracking carry over.
- New TOML option `drain_timeout_secs` (reloadable). Pinned `-S` CLI secrets are immutable across SIGHUP and never drain.
- New stats: `secret_<lbl>_draining`, `secret_<lbl>_drain_age_seconds`, `secret_<lbl>_rejected_draining`, `secret_<lbl>_drain_forced`. Same fields exposed in Prometheus as `teleproxy_secret_draining`, `teleproxy_secret_drain_age_seconds`, `teleproxy_secret_rejected_draining_total`, `teleproxy_secret_drain_forced_total`.
- Slot capacity expanded internally: 16 active secrets at a time as before, plus up to 16 additional draining slots.
- Fixes a latent bug where the per-secret connection counter could go negative if a TLS connection was closed between the TLS handshake and the obfs2 init.
- **Signed dnf repository** at <https://teleproxy.github.io/repo/> serving RHEL 9, RHEL 10, AlmaLinux, Rocky Linux, and Fedora 41/42 on x86_64 and aarch64. Install on any of these distros with `dnf install https://teleproxy.github.io/repo/teleproxy-release-latest.noarch.rpm && dnf install teleproxy && systemctl enable --now teleproxy`. Packages are signed with an RSA 4096 / SHA-512 key (RHEL 9 rpm-sequoia compatible). The first install generates a random secret in `/etc/teleproxy/config.toml`; subsequent `dnf upgrade` runs swap the binary and never touch user-edited config; `dnf remove` leaves the config file in place. Built automatically on each tag from the existing static linux binaries via [nfpm](https://nfpm.goreleaser.com/), driven by `repository_dispatch` from the release workflow into the new [teleproxy/repo](https://github.com/teleproxy/repo) repository.

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
