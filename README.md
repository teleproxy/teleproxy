# Teleproxy

[![CI](https://github.com/teleproxy/teleproxy/actions/workflows/test.yml/badge.svg)](https://github.com/teleproxy/teleproxy/actions/workflows/test.yml)
[![Docker](https://img.shields.io/badge/docker-ghcr.io-blue?logo=docker)](https://github.com/teleproxy/teleproxy/pkgs/container/teleproxy)
[![License: GPLv2](https://img.shields.io/badge/license-GPLv2-blue.svg)](LICENSE)
[![Stars](https://img.shields.io/github/stars/teleproxy/teleproxy?style=flat&label=stars)](https://github.com/teleproxy/teleproxy)
[![Release](https://img.shields.io/github/v/release/teleproxy/teleproxy?label=release)](https://github.com/teleproxy/teleproxy/releases/latest)
[![Telegram](https://img.shields.io/badge/telegram-@teleproxy__dev-blue?logo=telegram)](https://t.me/teleproxy_dev)

High-performance MTProto proxy for Telegram with DPI resistance, fake-TLS camouflage, and production-grade monitoring.

**[Documentation](https://teleproxy.github.io)** | **[Docker Quick Start](https://teleproxy.github.io/docker/)** | **[Comparison](https://teleproxy.github.io/comparison/)** | **[Telegram](https://t.me/teleproxy_dev)**

> [!NOTE]
> Teleproxy is maintained by one person. If it's useful to you, consider [supporting development](https://teleproxy.github.io/donate/).
>
> | | |
> |---|---|
> | Telegram | **[Donate via Tribute](https://t.me/tribute/app?startapp=dIa9)** (cards, worldwide) |
> | Web | **[Donate via Tribute](https://web.tribute.tg/d/Ia9)** |
> | TON (The Open Network) | `UQCRB931D__Q2YQmAbUfcuHQ7fHsG3_3At7e6pUtNa6b9bTh` ([Tonkeeper](https://app.tonkeeper.com/transfer/UQCRB931D__Q2YQmAbUfcuHQ7fHsG3_3At7e6pUtNa6b9bTh)) |
> | USDT — TON network ONLY | same address as above (not TRC20/ERC20) |

<details>
<summary>🎵 Ghost Protocol — the unofficial anthem</summary>
<br>
<video src="https://github.com/user-attachments/assets/37919bc8-2bbb-4bea-8af6-2e15d3bc7c65" controls width="640"></video>
</details>

## Deploy (beta)

Get a proxy running in under 2 minutes:

[![Deploy](https://img.shields.io/badge/deploy-one--click-00C853?style=for-the-badge&logoColor=white)](https://teleproxy.github.io/deploy/)

The deploy page generates a unique secret, gives you a script to paste when creating a VPS, then shows your connection QR code. No terminal needed.

Supports: DigitalOcean · Vultr · Hetzner · Linode · any Ubuntu/Debian VPS

## Highlights

- **Fake-TLS camouflage** — emulates HTTPS handshakes and TLS records
- **Direct-to-DC mode** — bypass middle-end relays, zero config files needed
- **Dynamic Record Sizing** — varies record sizes and inter-record delays
- **8 MB Docker image** — 7x smaller than the original
- **Prometheus metrics** — production monitoring out of the box
- **Up to 16 secrets** with labels and per-secret connection limits
- **E2E tested** — the only MTProto proxy with automated tests against real Telegram

## DPI Resistance

Teleproxy's fake-TLS emulates HTTPS traffic. Automated tests check the framing and camouflage below; they do not prove that a deployment will pass current DPI rules. The Telegram client controls its ClientHello fingerprint, which the proxy cannot rewrite. See the [current limitations and operator playbook](https://teleproxy.github.io/features/dpi-resistance/).

| Layer | Implementation | Verified by |
|-------|---------------|-------------|
| ClientHello fingerprint | 517-byte Chrome-profile hello with 15 TLS extensions, GREASE (RFC 8701), X25519 key share, padding | `test_ja3_fingerprint`, `test_tls_extension_completeness`, `test_grease_randomness` |
| ServerHello emulation | Live-probes the real backend (20 connections), mirrors extension order and encrypted record sizes | `test_emulation_matches_backend`, `test_server_hello_tls13_compliance` |
| Record sizing | Dynamic Record Sizing mimics TCP slow-start (1450→4096→16144 bytes) with ±100B noise and Weibull inter-record delays | `test_drs_e2e.py` |
| Active probing resistance | Every failed validation (wrong secret, stale timestamp, unknown SNI, replay, non-TLS) forwarded to real HTTPS backend | `test_wrong_secret_rejected`, `test_unknown_sni_falls_back`, `test_browser_tls_sees_real_backend` |
| Anti-replay | client\_random dedup cache + 120-second timestamp window + HMAC-SHA256 binding | `test_duplicate_client_random_rejected`, `test_stale_timestamp_rejected` |
| Encrypted payload entropy | Fake application data passes Shannon entropy validation (H ≥ 7.0 bits/byte) | `test_encrypted_data_entropy` |

Every parser on the attack surface is fuzz-tested on every push (60s smoke) and weekly (30min deep exploration) with ASan + UBSan + libFuzzer. CodeQL and cppcheck run static analysis on every commit. The ASan CI even [verifies itself](https://github.com/teleproxy/teleproxy/blob/main/.github/workflows/test.yml) by re-introducing a known heap overflow and confirming detection.

These tests cover specific protocol properties, from JA3 hash computation to encrypted-payload entropy and DRS timing distributions. Connectivity under censorship still needs testing with real Telegram clients on the affected networks.

## Telegram WEB Proxy

[Telegram Desktop 7.1](https://github.com/telegramdesktop/tdesktop/releases/tag/v7.1.0) added a WEB proxy type. It carries normal MTProxy traffic through an embedded browser over real HTTPS or WebSockets. Telegram's [tproxy-server](https://github.com/telegramdesktop/tproxy-server) relay converts those streams back into TCP connections to a local MTProxy backend.

```text
Telegram WebView -> HTTPS frontend -> tproxy-server -> MTProxy backend -> Telegram
```

Teleproxy can serve as the MTProxy backend: `tproxy-server` forwards the standard obfs2 or padded MTProxy stream unchanged. The WEB transport is handled by the relay and HTTPS frontend. When using Teleproxy as the backend:

- Keep the backend listener private and use the same base 16-byte secret in the relay and Teleproxy. WEB clients accept plain or `dd`-prefixed secrets, not fake-TLS `ee` secrets.
- Use a dedicated backend without `EE_DOMAIN` / `-D`, which enables TLS-only ingress. The public HTTPS connection terminates at the frontend.
- Leave `PROXY_PROTOCOL` disabled: the reference relay sends raw MTProxy bytes without a PROXY header. Backend IP-based limits and statistics therefore see the relay address, not individual users.

The public TLS handshake comes from the browser engine rather than Telegram's fake-TLS implementation. A compatible HTTPS frontend can also negotiate [Encrypted Client Hello (ECH)](https://www.rfc-editor.org/rfc/rfc9849.html) to hide the inner hostname, and [TLS certificate compression](https://www.rfc-editor.org/rfc/rfc8879.html) to reduce full-handshake certificate bytes. These require client support; ECH also requires the client to obtain the server's ECH configuration. Neither hides the server IP or guarantees access through a blocked network.

## Quick Start

### Docker (recommended)

```bash
docker run -d \
  --name teleproxy \
  -p 443:443 \
  -p 127.0.0.1:8888:8888 \
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
| Anti-replay protection | Weak | Yes | Yes | Yes |
| Dynamic Record Sizing | No | Yes | Yes | No |
| Per-secret byte quotas | No | Yes | No | Yes |
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
