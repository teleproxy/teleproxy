---
hide:
  - navigation
  - toc
---

<div class="tx-hero" markdown>

# Unblock Telegram. Invisibly.

A high-performance MTProto proxy that makes Telegram traffic indistinguishable from regular HTTPS — defeating deep packet inspection while delivering lower latency than the original.

[Get Started](getting-started/quickstart.md){ .md-button .md-button--primary }
[Docker Quick Start](docker/index.md){ .md-button }

:material-send: Follow **[@teleproxy_dev](https://t.me/teleproxy_dev)** on Telegram for updates.

</div>

<div class="feature-grid" markdown>

<div class="feature" markdown>

### :material-shield-lock-outline: Fake-TLS & DPI Resistance

Wraps MTProto in a genuine TLS handshake with Dynamic Record Sizing, making proxy traffic statistically indistinguishable from normal HTTPS browsing.

</div>

<div class="feature" markdown>

### :material-lightning-bolt: Direct-to-DC

Bypasses Telegram's middle-end relay servers, routing clients straight to the nearest datacenter for measurably lower latency and higher throughput.

</div>

<div class="feature" markdown>

### :material-chart-line: Production Monitoring

Built-in Prometheus metrics endpoint and HTTP stats page give you real-time visibility into connections, traffic, and per-secret usage.

</div>

<div class="feature" markdown>

### :material-docker: 8 MB Docker Image

A minimal, scratch-based container — 7x smaller than the original Telegram proxy image. Runs on AMD64 and ARM64 including Apple Silicon.

</div>

<div class="feature" markdown>

### :material-key-variant: Multi-Secret Access Control

Configure up to 16 secrets with human-readable labels, per-secret connection limits, and IP allowlists or blocklists for fine-grained access control.

</div>

<div class="feature" markdown>

### :material-test-tube: Battle-Tested

The only MTProto proxy with automated end-to-end tests against real Telegram — every commit verified with actual Telethon client connections through both obfs2 and fake-TLS transports.

</div>

</div>

## Quick Start

Get a proxy running in one command:

```bash
docker run -d --name teleproxy \
  -p 443:443 \
  --restart unless-stopped \
  ghcr.io/teleproxy/teleproxy:latest
```

The container generates a random secret on first launch and prints the `tg://` connection link to the logs.

<div class="callout" markdown>

:material-check-decagram: **The only MTProto proxy with automated end-to-end tests against real Telegram** — every commit is verified with actual client connections through both transport modes. No other proxy implementation does this.

</div>

## What is Teleproxy?

Teleproxy is an MTProto proxy — a specialized relay that lets Telegram clients connect even when the service is blocked by ISPs or government firewalls. Unlike VPNs and SOCKS proxies, an MTProto proxy only handles Telegram traffic, requires zero client-side configuration beyond scanning a link, and is natively supported in every official Telegram app.

Teleproxy is a drop-in replacement for the [abandoned official proxy](https://github.com/TelegramMessenger/MTProxy) from Telegram, rebuilt with modern DPI resistance, production monitoring, and a dramatically smaller footprint.

## Explore the Docs

- **[Quick Start](getting-started/quickstart.md)** — Install and run in under a minute
- **[Docker Deployment](docker/index.md)** — Container images, Compose files, configuration reference
- **[Fake-TLS & DPI Resistance](features/fake-tls.md)** — How the TLS camouflage works
- **[Direct-to-DC Mode](features/direct-mode.md)** — Lower latency, explained
- **[Monitoring](features/monitoring.md)** — Prometheus metrics and HTTP stats
- **[Secrets & Access Control](features/secrets.md)** — Multi-secret setup and connection limits
- **[Comparison](comparison.md)** — How Teleproxy stacks up against alternatives
