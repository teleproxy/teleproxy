---
description: "How Teleproxy defeats deep packet inspection. Current threat landscape, TSPU/ASBI detection methods, and server-side countermeasures."
---

# DPI Resistance

Teleproxy includes several layers of defense against Deep Packet Inspection (DPI) systems that attempt to identify and block MTProxy traffic.

## Current Threat Landscape

As of April 2026, Russian DPI systems (TSPU/ASBI) classify MTProxy fake-TLS as a distinct protocol ("TELEGRAM_TLS"). Detection relies primarily on **client-side TLS fingerprinting** — the Telegram app's ClientHello has recognizable JA3/JA4 characteristics that DPI matches against known signatures.

Key observations:

- **Mobile operators** (MTS, Megafon, Beeline, T2, Yota) are affected more than home ISPs — TSPU deployment varies by provider
- **VPN connections bypass** both DPI heuristics and IP-level blocking
- **Client-side packet fragmentation tools** (zapret, GoodbyeDPI) restore connectivity, confirming that DPI matches patterns on intact TCP segments
- Telegram Desktop [updated its TLS fingerprint](https://github.com/telegramdesktop/tdesktop/pull/30513) to fix detectable artifacts; mobile clients may lag behind

## What Teleproxy Does (Server-Side)

### Fake-TLS camouflage

All traffic is wrapped in TLS 1.3 records with a Chrome-profile ClientHello. See [Fake-TLS](fake-tls.md) for setup.

### Custom TLS backend (active probing resistance)

DPI systems actively probe suspected proxies. When running with a real TLS backend (nginx with a valid certificate), every invalid connection — wrong secret, expired timestamp, DPI probe — gets forwarded to the real website. The probe sees a legitimate HTTPS server.

This is the single most effective server-side measure. See [Fake-TLS: Custom TLS Backend](fake-tls.md#custom-tls-backend-tcp-splitting).

### Dynamic Record Sizing (DRS)

TLS record sizes follow a graduated pattern matching real web servers (Cloudflare, Caddy): MTU-sized during slow-start, ramping to maximum. Random noise is added to each record. This defeats statistical analysis that fingerprints proxy traffic by uniform record sizes.

### ServerHello response variation

The ServerHello encrypted payload size varies by up to ±32 bytes across connections, mimicking the natural variation in certificate chain and session ticket sizes seen from real TLS servers. The ServerHello and ChangeCipherSpec are sent as separate TCP segments to prevent DPI from matching the full handshake response in a single packet.

### Forced ClientHello fragmentation (automatic)

Teleproxy announces a small TCP Maximum Segment Size (128 bytes) in the SYN-ACK on its public listening port. The client kernel obeys the limit and chops the outgoing ClientHello (~500-700 bytes) into 4-5 TCP segments. Cipher list, extensions, signature algorithms, and ALPN end up straddling segment boundaries, so a DPI that JA4-fingerprints a single packet only sees a fragment of the data it needs.

This is automatic, requires no configuration, and works against unmodified Telegram clients on every platform. The HTTP `/stats` and `/metrics` listener uses the full system MSS and is unaffected.

Trade-off: Linux applies the listening-socket MSS to both directions of each accepted connection, so server→client segments are also capped at 128 bytes. Packet count rises (roughly 10× compared to MSS=1460) and per-byte TCP/IP header overhead grows from ~3% to ~25%. On modern hardware with TSO/GSO offload, CPU cost stays manageable, but bandwidth-saturated proxies will see a measurable throughput cap. Heavy operators who would rather take the JA4 detection risk than the throughput hit can rebuild without the `SM_LOWMSS` bit on their proxy listener — but the default ships with fragmentation on, because for most users a working proxy that runs slower beats a fast proxy that gets blocked.

### GREASE randomization

Each ClientHello (for upstream domain probing) uses fresh GREASE values per RFC 8701, preventing static fingerprint matching.

## What You Can Do (Server Setup)

### Use port 443

TLS traffic on non-standard ports (8443, 6443) is inherently suspicious. Always run Teleproxy on port 443:

```bash
./teleproxy -H 443 -S <secret> -D example.com ...
```

### Pick a high-traffic domain

Choose a popular, CDN-backed domain for SNI (e.g., `www.google.com`, `cloudflare.com`). The domain must support TLS 1.3. Teleproxy probes the domain at startup to learn its ServerHello characteristics and mimics them.

### Run a custom TLS backend

If you control the server's domain, set up nginx with a valid TLS certificate behind Teleproxy. This makes the server indistinguishable from a normal HTTPS website under active probing. See [Fake-TLS: Custom TLS Backend](fake-tls.md#custom-tls-backend-tcp-splitting).

### Wildcard certificates

If your TLS certificate is a wildcard (e.g. `*.example.com` served from `proxy.example.com`), configure the `-D` flag with the wildcard pattern: `-D '*.example.com:proxy.example.com:443'`. Teleproxy matches any single-label subdomain of `example.com` against the pattern (RFC 6125): `proxy.example.com` and `node-7.example.com` match; `example.com` (apex) and `a.b.example.com` (multi-label) do not. Fingerprinting at startup probes the backend host, not the literal `*.example.com`. An explicit backend is required for wildcard entries.

### Use random padding (DD mode)

For ISPs that fingerprint MTProto by packet sizes, enable random padding by prefixing `dd` to the client secret.

## What Users Can Do (Client-Side)

The primary detection vector is the Telegram client's TLS fingerprint, which **cannot be fixed server-side**. Users in affected networks should use client-side DPI bypass tools that fragment TCP segments:

| Tool | Platform | Method |
|------|----------|--------|
| [zapret](https://github.com/bol-van/zapret) | Linux, Android (root) | TCP segmentation, fake packets |
| [zapret2](https://github.com/bol-van/zapret2) | Linux, Android (root) | Updated fork |
| [GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI) | Windows | TCP fragmentation, TTL tricks |
| [NoDPI](https://github.com/nicknsy/NoDPI) | Android (no root) | Local VPN with fragmentation |
| [SpoofDPI](https://github.com/xvzc/SpoofDPI) | macOS, Linux | HTTP/TLS splitting proxy |

These tools work because Russian DPI matches patterns on **intact TCP segments**. Fragmenting the ClientHello across multiple segments defeats the pattern matcher.

!!! tip "Keep Telegram updated"
    Telegram Desktop [fixed several TLS fingerprint artifacts](https://github.com/telegramdesktop/tdesktop/pull/30513) that DPI exploited. Mobile clients (Android/iOS) typically receive these fixes in subsequent updates. Always use the latest version.

## What Cannot Be Fully Fixed Server-Side

- **Client TLS fingerprint content**: The Telegram app controls the byte-for-byte content of the ClientHello. Server-side proxy code cannot alter what the client puts on the wire. We can, however, force the *kernel* of the connecting client to spread those bytes across multiple TCP segments — see [Forced ClientHello fragmentation](#forced-clienthello-fragmentation-automatic) above. This raises the cost of single-packet JA4 matching for DPI but does not invalidate the fingerprint if the DPI fully reassembles TCP streams.
- **IP/L3 blocking**: When DPI blocks Telegram's IP ranges at the network layer, only a VPN or intermediate relay can help.
- **TSPU deployment**: Whether an ISP's DPI detects the traffic depends on their TSPU hardware/software version — this varies by operator and region.
