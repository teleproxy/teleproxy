# Teleproxy

[![CI](https://github.com/teleproxy/teleproxy/actions/workflows/test.yml/badge.svg)](https://github.com/teleproxy/teleproxy/actions/workflows/test.yml)
[![Docker](https://img.shields.io/badge/docker-ghcr.io-blue?logo=docker)](https://github.com/teleproxy/teleproxy/pkgs/container/teleproxy)
[![License: GPLv2](https://img.shields.io/badge/license-GPLv2-blue.svg)](LICENSE)

High-performance MTProto proxy for Telegram with DPI resistance, fake-TLS camouflage, and production-grade monitoring.

**[Documentation](https://teleproxy.github.io)** | **[Docker Quick Start](https://teleproxy.github.io/docker/)** | **[Comparison](https://teleproxy.github.io/comparison/)**

## Highlights

- **Fake-TLS camouflage** — traffic indistinguishable from normal HTTPS (TLS 1.3)
- **Direct-to-DC mode** — bypass middle-end relays, zero config files needed
- **Dynamic Record Sizing** — defeats statistical traffic analysis
- **8 MB Docker image** — 7x smaller than the original
- **Prometheus metrics** — production monitoring out of the box
- **Up to 16 secrets** with labels and per-secret connection limits
- **E2E tested** — the only MTProto proxy with automated tests against real Telegram

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
| Fuzz testing (CI) | No | Yes | No | Partial |

[Full comparison →](https://teleproxy.github.io/comparison/)

## Docker Images

- `ghcr.io/teleproxy/teleproxy:latest`
- `rkline0x/teleproxy:latest` (Docker Hub)

## License

GPLv2 — see [LICENSE](LICENSE).
