# Teleproxy

[![CI](https://github.com/teleproxy/teleproxy/actions/workflows/test.yml/badge.svg)](https://github.com/teleproxy/teleproxy/actions/workflows/test.yml)
[![Docker](https://img.shields.io/badge/docker-ghcr.io-blue?logo=docker)](https://github.com/teleproxy/teleproxy/pkgs/container/teleproxy)
[![License: GPLv2](https://img.shields.io/badge/license-GPLv2-blue.svg)](LICENSE)

High-performance MTProto proxy for Telegram with DPI resistance, fake-TLS camouflage, and production-grade monitoring.

<video src="https://github.com/user-attachments/assets/b96b7646-20de-427e-bad0-cb1cbc7e9379" controls width="480"></video>

**[Documentation](https://teleproxy.github.io)** | **[Docker Quick Start](https://teleproxy.github.io/docker/)** | **[Comparison](https://teleproxy.github.io/comparison/)** | **[Telegram](https://t.me/teleproxy_dev)**

## Highlights

- **Fake-TLS camouflage** — traffic indistinguishable from normal HTTPS (TLS 1.3)
- **Direct-to-DC mode** — bypass middle-end relays, zero config files needed
- **Dynamic Record Sizing** — defeats statistical traffic analysis
- **8 MB Docker image** — 7x smaller than the original
- **Prometheus metrics** — production monitoring out of the box
- **Up to 16 secrets** with labels and per-secret connection limits
- **E2E tested** — the only MTProto proxy with automated tests against real Telegram

## DPI Resistance

Teleproxy's fake-TLS produces traffic indistinguishable from a standard Chrome TLS 1.3 session. Every claim below is verified by automated tests in CI.

| Layer | Implementation | Verified by |
|-------|---------------|-------------|
| ClientHello fingerprint | 517-byte Chrome-profile hello with 15 TLS extensions, GREASE (RFC 8701), X25519 key share, padding | `test_ja3_fingerprint`, `test_tls_extension_completeness`, `test_grease_randomness` |
| ServerHello emulation | Live-probes the real backend (20 connections), mirrors extension order and encrypted record sizes | `test_emulation_matches_backend`, `test_server_hello_tls13_compliance` |
| Record sizing | Dynamic Record Sizing mimics TCP slow-start (1450→4096→16144 bytes) with ±100B noise and Weibull inter-record delays | `test_drs_e2e.py` |
| Active probing resistance | Every failed validation (wrong secret, stale timestamp, unknown SNI, replay, non-TLS) forwarded to real HTTPS backend | `test_wrong_secret_rejected`, `test_unknown_sni_falls_back`, `test_browser_tls_sees_real_backend` |
| Anti-replay | client\_random dedup cache + 120-second timestamp window + HMAC-SHA256 binding | `test_duplicate_client_random_rejected`, `test_stale_timestamp_rejected` |
| Encrypted payload entropy | Fake application data passes Shannon entropy validation (H ≥ 7.0 bits/byte) | `test_encrypted_data_entropy` |

Every parser on the attack surface is fuzz-tested on every push (60s smoke) and weekly (30min deep exploration) with ASan + UBSan + libFuzzer. CodeQL and cppcheck run static analysis on every commit. The ASan CI even [verifies itself](https://github.com/teleproxy/teleproxy/blob/main/.github/workflows/test.yml) by re-introducing a known heap overflow and confirming detection.

Other MTProto proxy implementations describe their TLS layer with adjectives. Teleproxy describes it with test names. Every anti-fingerprinting claim above links to an automated test that runs in CI on every commit — from JA3 hash computation to Shannon entropy of encrypted payloads to DRS timing distributions. No other MTProto proxy validates its DPI resistance this way.

## Quick Start

### Docker (recommended)

```bash
docker run -d \
  --name teleproxy \
  -p 443:443 \
  --restart unless-stopped \
  ghcr.io/teleproxy/teleproxy:latest
```

Check logs for connection links: `docker logs teleproxy`

### Static Binary

```bash
curl -Lo teleproxy https://github.com/teleproxy/teleproxy/releases/latest/download/teleproxy-linux-amd64
chmod +x teleproxy
SECRET=$(head -c 16 /dev/urandom | xxd -ps)
./teleproxy -S "$SECRET" -H 443 --direct -p 8888 --aes-pwd /dev/null
```

## Comparison

| Feature | [Original](https://github.com/TelegramMessenger/MTProxy) | **[Teleproxy](https://github.com/teleproxy/teleproxy)** | [mtg](https://github.com/9seconds/mtg) | [telemt](https://github.com/telemt/telemt) |
|---------|:---:|:---:|:---:|:---:|
| **Language** | C | C | Go | Rust |
| Fake-TLS (EE mode) | Yes | Yes | Yes | Yes |
| Direct-to-DC mode | No | Yes | Yes | Yes |
| Multiple secrets | Yes | Yes (up to 16) | No | Yes |
| Anti-replay protection | Weak | Yes | Yes | Partial |
| Dynamic Record Sizing | No | Yes | Yes | No |
| IP blocklist / allowlist | No | Yes | Yes | No |
| Docker image | ~57 MB | ~8 MB | ~3.5 MB | ~5 MB |
| ARM64 / Apple Silicon | No | Yes | Yes | Yes |
| Prometheus metrics | No | Yes | Yes | Yes |
| E2E tests (real Telegram) | No | Yes | No | No |
| TLS fingerprint validation (CI) | No | Yes | No | No |
| Fuzz testing (CI) | No | Yes | No | Partial |

[Full comparison →](https://teleproxy.github.io/comparison/)

## Docker Images

- `ghcr.io/teleproxy/teleproxy:latest`
- `rkline0x/teleproxy:latest` (Docker Hub)

## License

GPLv2 — see [LICENSE](LICENSE).
