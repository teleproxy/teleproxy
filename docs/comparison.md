# Comparison

Teleproxy is a fork of the original [TelegramMessenger/MTProxy](https://github.com/TelegramMessenger/MTProxy), which has been abandoned since 2021. This page compares Teleproxy with the upstream and the main third-party alternatives: [mtg](https://github.com/9seconds/mtg) (Go) and [telemt](https://github.com/telemt/telemt) (Rust).

| Feature | [Original](https://github.com/TelegramMessenger/MTProxy) | **[Teleproxy](https://github.com/teleproxy/teleproxy)** | [mtg](https://github.com/9seconds/mtg) | [telemt](https://github.com/telemt/telemt) |
|---------|:---:|:---:|:---:|:---:|
| **Language** | C | C | Go | Rust |
| ***Protocol*** | | | | |
| Fake-TLS (EE mode) | Yes | Yes | Yes | Yes |
| Direct-to-DC mode | No | Yes | Yes | Yes |
| Ad proxy tag | Yes | Yes | No | Yes |
| Multiple secrets | Yes | Yes (up to 16, with labels) | No | Yes |
| Anti-replay protection | Weak | Yes | Yes | Yes |
| Constant-time HMAC | No | Yes | Yes | Yes |
| ***DPI resistance*** | | | | |
| Custom TLS backend (TCP splitting) | Yes | Yes | Yes | Yes |
| Dynamic Record Sizing (DRS) | No | Yes | Yes | No |
| Traffic mimicry (DRS + timing) | No | Yes | Yes | Partial |
| ServerHello fragmentation | No | Yes | No | No |
| SOCKS5 upstream proxy | No | Yes | Yes | Yes |
| DNS over HTTPS/TLS | No | No | Yes | No |
| ***Access control*** | | | | |
| IP blocklist / allowlist | No | Yes | Yes | No |
| Per-user unique IP limits | No | Yes | No | Yes |
| Per-secret byte quotas | No | Yes | No | Yes |
| Secret expiration | No | Yes | No | Yes |
| Proxy Protocol v1/v2 | No | Yes | Yes | Yes |
| ***Deployment*** | | | | |
| Docker image | ~57 MB | ~8 MB | ~3.5 MB | ~5 MB |
| ARM64 / Apple Silicon | No | Yes | Yes | Yes |
| IPv6 | Yes | Yes | Yes | Yes |
| Multi-worker processes | Yes | Yes | — | — |
| Static binary releases | No | Yes | Yes | Yes |
| RPM packages | No | Yes | No | No |
| Systemd integration | Partial | Yes | No | Yes |
| ***Monitoring & management*** | | | | |
| Prometheus metrics | No | Yes | Yes | Yes |
| HTTP stats endpoint | Yes | Yes | No | Yes |
| REST management API | No | No | No | Yes |
| Auto config refresh | No | Yes | Yes | Yes |
| Health checks | No | Yes | Yes | Yes |
| ***Testing & quality*** | | | | |
| Fuzz testing (CI) | No | Yes | No | Partial |
| E2E tests (real Telegram clients) | No | Yes | No | No |
| TLS fingerprint validation (CI) | No | Yes | No | No |
| CodeQL security scanning | No | Yes | No | No |
| AddressSanitizer CI | No | Yes | No | No |
| Static analysis (CI) | No | Yes | Yes | — |

Teleproxy is the only MTProto proxy implementation with automated end-to-end testing against real Telegram infrastructure. The E2E suite connects a Telethon client through the proxy on both obfuscated and fake-TLS transports, verifying authentication and file transfers against Telegram's test datacenter.
