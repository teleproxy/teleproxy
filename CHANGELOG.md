# Changelog

## [Unreleased]

Graceful connection draining on secret removal (#45).

- Removing a secret via SIGHUP reload no longer drops in-flight connections.
  The slot transitions to a draining state — new connections matching the
  removed secret are rejected, but existing ones keep working until they
  close naturally or `drain_timeout_secs` (default 300, `0` = infinite)
  elapses, at which point stragglers are force-closed.
- Re-adding a draining secret revives the same slot — counters, byte totals,
  and IP tracking carry over.  Pinned `-S` CLI secrets remain immutable.
- New TOML option `drain_timeout_secs` (reloadable).
- New stats: `secret_<lbl>_draining`, `secret_<lbl>_drain_age_seconds`,
  `secret_<lbl>_rejected_draining`, `secret_<lbl>_drain_forced`.
- Slot capacity expanded to 16 active + up to 16 draining at any moment.
- Fix latent bug where the per-secret connection counter could go negative
  if a TLS connection closed between handshake and obfs2 init.

## [4.9.0]

PROXY protocol v1/v2 listener support.

- `--proxy-protocol` CLI flag / `proxy_protocol = true` TOML config / `PROXY_PROTOCOL=true` Docker env
- Auto-detects v1 (text) and v2 (binary) headers, extracts real client IP from load balancer
- IP ACLs re-checked against the real client IP after header parsing
- v2 LOCAL command accepted for health check probes
- New stats: `proxy_protocol_enabled`, `proxy_protocol_connections`, `proxy_protocol_errors`
- Prometheus metrics: `teleproxy_proxy_protocol_connections_total`, `teleproxy_proxy_protocol_errors_total`

Per-IP top-N Prometheus metrics (#46).

- New `top_ips_per_secret` TOML config knob (`TOP_IPS_PER_SECRET` Docker env). Default 0 (disabled, zero overhead).
- When set, exposes `teleproxy_secret_ip_connections`, `teleproxy_secret_ip_bytes_received_total`, and `teleproxy_secret_ip_bytes_sent_total` for the top-N client IPs per secret, sorted by total bytes.
- Cardinality cap is enforced operator-side: `top_ips_per_secret * secret_count` labelled samples maximum. Capped at 32 per secret.
- Useful for diagnosing the "proxy works for 5 minutes then stops" complaint pattern when paired with the Grafana dashboard.

Other changes:

- Fix auto-generated secret not written to TOML config
- TON wallet donation option
- Per-page SEO metadata, OpenGraph tags, JSON-LD structured data, robots.txt
- Complete Russian translation (100%), expanded Farsi and Vietnamese (38%)
- Merged duplicate issue notification workflows

## [4.8.0]

DC health probes (#47).

- Periodic TCP handshake probes to all 5 Telegram DCs, exposed as Prometheus histograms (`teleproxy_dc_latency_seconds`), failure counters, and last-latency gauges
- Disabled by default. Enable with `--dc-probe-interval 30` (CLI), `dc_probe_interval = 30` (TOML), or `DC_PROBE_INTERVAL=30` (Docker env)
- Probes run in master process only with non-blocking poll for sub-millisecond accuracy
- Text stats include per-DC latency, average, count, and failure fields

## [4.5.0]

QR codes for connection links.

- `teleproxy link` subcommand prints a proxy URL and renders a scannable QR code in the terminal using UTF-8 half-block characters
- Docker `start.sh` and `install.sh` now display QR codes automatically at startup — point a phone camera at the screen to connect
- Vendored nayuki/QR-Code-generator (MIT) for zero-dependency QR rendering on any platform
- E2E tests decode the rendered QR output with pyzbar and verify it matches the expected URL
- Documentation: new "Connection Links" page (en + ru)

## [4.4.0]

TOML config file, SIGHUP secret reload, and one-liner installer.

- `--config /path/to/config.toml` for all settings: secrets, mode, ports, ACLs, DC overrides
- SIGHUP reloads secrets and IP ACLs from the config file without dropping connections
- CLI flags (`-S`, `--direct`, `-H`, etc.) override config file values; `-S` secrets are pinned and survive reload
- `install.sh` one-liner for bare-metal Linux: downloads binary, creates systemd service, generates config with secret, prints connection link
- Docker `start.sh` now generates a TOML config internally, enabling `docker exec <ctr> kill -HUP 1` for secret rotation
- Vendored tomlc17 TOML v1.1 parser (MIT, cktan/tomlc17)

## [4.3.0]

Direct mode connection resilience.

- IPv6 auto-detection: probe at startup, enable without `-6` if reachable
- Multiple addresses per DC with synchronous failover on connect failure
- Connection retry with exponential backoff (200ms–800ms, 3 attempts)
- `--dc-override dc_id:host:port` to add or replace DC addresses (repeatable). Docker: `DC_OVERRIDE=2:1.2.3.4:443,2:5.6.7.8:443`
- New stat: `direct_dc_retries` / `teleproxy_direct_dc_retries_total`

## [4.2.1]

- Fix aarch64 build: remove unused x86-only `sys/io.h` include
- Add native ARM64 glibc build to CI (catches platform-specific issues masked by Alpine/musl)

## [4.2.0]

- `--stats-allow-net CIDR` flag to extend stats endpoint access beyond RFC1918 ranges (repeatable). Docker: `STATS_ALLOW_NET=100.64.0.0/10,fd00::/8`

## [4.1.0]

MTProto transport protocol compliance improvements.

- Detect and log transport error codes (-404, -429, etc.) from DCs in direct mode
- Detect transport error codes in medium mode client parse path
- Track quick ACK packets with `teleproxy_quickack_packets_total` counter
- Track transport errors with `teleproxy_transport_errors_total` counter

## [4.0.0]

Rebrand to Teleproxy. Binary renamed from `mtproto-proxy` to `teleproxy`.

- Binary name: `teleproxy` (was `mtproto-proxy`)
- Prometheus metrics prefix: `teleproxy_` (was `mtproxy_`)
- Docker user/paths: `/opt/teleproxy/` (was `/opt/mtproxy/`)
- Environment variables: `TELEPROXY_*` (old `MTPROXY_*` still accepted with deprecation warning)
- Docker image includes backward-compat symlink `mtproto-proxy -> teleproxy`
- CLI flags and behavior unchanged
