# Changelog

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
