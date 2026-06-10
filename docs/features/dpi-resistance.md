---
description: "How Teleproxy defeats deep packet inspection. Current threat landscape, TSPU/ASBI detection methods, and server-side countermeasures."
---

# DPI Resistance

Teleproxy includes several layers of defense against Deep Packet Inspection (DPI) systems that attempt to identify and block MTProxy traffic.

## Current Threat Landscape

Russian DPI systems (TSPU/ASBI) classify MTProxy fake-TLS as a distinct protocol ("TELEGRAM_TLS"). Detection is **client-side TLS fingerprinting**: the Telegram app's ClientHello carries one fixed JA4 fingerprint that DPI matches against a signature. The proxy cannot change this — the bytes are produced by the Telegram client, not the server.

There have been two distinct blocking waves in 2026:

**April 2026 (static fingerprint).** TSPU matched the static JA4/JA3 of Telegram's fake-TLS ClientHello, keying on tells no real browser sends (a malformed `0xfe02` extension codepoint and a 20-byte random field). Telegram fixed those artifacts client-side ([tdesktop PR #30513](https://github.com/telegramdesktop/tdesktop/pull/30513), [DrKLO Android PR #1949](https://github.com/DrKLO/Telegram/pull/1949)), which restored connectivity through late May.

**Late May – June 2026 (reassembly + flow correlation).** The April fix only swapped one static fingerprint for another — the client still emits a single fixed JA4. This wave is harder:

- **TSPU now reassembles TCP streams** before fingerprinting, so splitting the ClientHello across segments no longer hides it. Field tests that clamped the server MSS aggressively (256 then 88 bytes), verified on the wire, **still got blocked** on reassembling nodes.
- **Active flow correlation.** Several ClientHellos carrying the same SNI + Telegram's JA4 to the same `ip:port` get the connection temporarily dropped. The proxy IP is also cross-checked against the cover domain's A-record — a random SNI that doesn't resolve to the proxy IP does **not** pass. Rotating SNI across real cover domains, or spreading across IPs/ports, defeats this correlation.
- **Silent drops, not RST.** The TLS handshake completes; the moment MTProto Application Data starts, packets are dropped without a reset and the client floods retransmissions (the "connects, then drops after ~30s" symptom).

Key observations:

- **Mobile vs. home is uneven, not policy.** The same proxy often works on an operator's mobile network but fails on its wired/home network (and vice versa, and iOS vs. Android can differ). This is **uneven per-node TSPU reassembly rollout** — the proxy is identical; the DPI box in the path differs — not a per-provider decision. Beeline, MTS, Megafon, Rostelecom have all been reported both ways.
- **VPN / Reality tunnels bypass** the MTProto fingerprint entirely (see the operator playbook below).
- **Client-side fragmentation tools** (zapret, GoodbyeDPI) still help on **non-reassembling** paths, but are path-dependent now that some nodes reassemble.
- Telegram client randomization (the durable fix) is [still under discussion upstream](https://github.com/telegramdesktop/tdesktop/issues/30733) and not yet shipped.

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

Teleproxy announces a small TCP Maximum Segment Size (256 bytes) in the SYN-ACK on its public listening port. The client kernel obeys the limit and chops the outgoing ClientHello (~500-700 bytes) into 2-3 TCP segments, so the required inputs to the JA4 hash (ALPN, `signature_algorithms`) land in later segments.

**Honest scope (updated June 2026).** This only defeats DPI that fingerprints from a single packet. The current TSPU wave **reassembles the TCP stream** before hashing, so on those nodes the fragmentation does nothing — field tests clamping the MSS as low as 88 bytes, verified on the wire, were still blocked. It remains useful against non-reassembling nodes (some mobile paths) and pairs with the existing ServerHello segmentation, so the default stays on. But it is **not** a fix for the June wave on its own — see the [operator playbook](#surviving-the-june-2026-wave-operator-playbook) for what actually helps now.

This is automatic, requires no configuration, and works against unmodified Telegram clients on every platform. The HTTP `/stats` and `/metrics` listener uses the full system MSS and is unaffected.

Trade-off: Linux applies the listening-socket MSS to both directions of each accepted connection, so server→client segments are also capped at 256 bytes. Packet count rises ~5× compared to MSS=1460 and per-byte TCP/IP header overhead grows from ~3% to ~15%. On modern hardware with TSO/GSO offload, CPU cost stays manageable, and a 20MB MTProto download still completes well inside any sensible timeout. Bandwidth-saturated proxies will see a measurable throughput cap.

**Turning it off.** Operators who would rather take the JA4 detection risk than the throughput overhead can disable the clamp:

- TOML: `mss_clamp = false` (top-level key)
- CLI: `--no-mss-clamp`
- Docker / `start.sh`: `MSS_CLAMP=false` (or `MSS_CLAMP=0`)

Any one of these turns the SYN-ACK MSS announcement back to system default — every accepted connection gets a normal-size MSS in both directions, and the proxy carries bulk MTProto at full speed. The default remains on, because for most users a working proxy that runs slightly slower beats a fast proxy that gets blocked.

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

For ISPs that fingerprint MTProto by packet sizes, enable random padding by prefixing `dd` to the client secret. Honest note: this helps against size-based heuristics on some ISPs, but does nothing against the JA4 detection driving the June 2026 wave — don't rely on it alone.

## Surviving the June 2026 wave (operator playbook)

The current wave keys on the client's JA4 plus `(SNI + ip:port)` correlation, and reassembles TCP. Server-side fingerprint tricks can't change the client's JA4, so the measures that are actually holding up in the field are about **diluting correlation** and **moving the outbound leg off MTProto**. In rough priority order:

### 1. Rotate SNI across several real cover domains

The correlation triggers when many connections with the same SNI + Telegram's JA4 hit the same `ip:port`. Register several cover domains and hand different users links with different SNIs:

```bash
./teleproxy -H 443 -S <secret> \
  -D www.cloudflare.com:127.0.0.1:8443 \
  -D www.microsoft.com:127.0.0.1:8443 \
  -D www.apple.com:127.0.0.1:8443
```

Each domain's [SNI is split from the backend](fake-tls.md) (`EE_DOMAIN`/`EE_BACKEND`, or the `-D sni:backend:port` form), so they can all share one local TLS backend. [Wildcard certs](#wildcard-certificates) work too.

**The cover domain's A-record must resolve to the proxy IP.** A random SNI that points elsewhere fails the June A-record cross-check. Use domains you control (or a wildcard cert host) that genuinely point at the proxy.

### 2. Spread across IPs and ports, and keep IPs clean

Multiple listening IPs/ports further dilute the per-`ip:port` correlation. Note that post-detection IP bans have been observed to hit **neighboring IPs in the same range** — keep proxy IPs spread across ranges rather than clustered, and rotate an IP that gets burned.

### 3. Cascade the outbound leg through VLESS + Reality (strongest option)

The most reliable field-confirmed survivor is to stop sending MTProto-shaped traffic out of the censored network at all: run teleproxy in [direct mode](direct-mode.md) and route its **outbound** DC connections through a local [Xray VLESS + Reality](https://github.com/XTLS/Xray-core) client over [SOCKS5](socks5.md):

```bash
# teleproxy on the in-country box, DC traffic egresses via local Xray Reality
DIRECT_MODE=true
SOCKS5_PROXY=socks5://127.0.0.1:1080   # local Xray Reality outbound
```

The Telegram client still reaches teleproxy over fake-TLS locally, but what crosses the TSPU border is Reality, which the current wave does not block. Mind the [direct-mode trade-offs](direct-mode.md) (media on non-Premium accounts, sponsored channels). This is more setup, but it is what keeps working when straight fake-TLS does not.

## What Users Can Do (Client-Side)

The primary detection vector is the Telegram client's TLS fingerprint, which **cannot be fixed server-side**. Users in affected networks should use client-side DPI bypass tools that fragment TCP segments:

| Tool | Platform | Method |
|------|----------|--------|
| [zapret](https://github.com/bol-van/zapret) | Linux, Android (root) | TCP segmentation, fake packets |
| [zapret2](https://github.com/bol-van/zapret2) | Linux, Android (root) | Updated fork |
| [GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI) | Windows | TCP fragmentation, TTL tricks |
| [NoDPI](https://github.com/nicknsy/NoDPI) | Android (no root) | Local VPN with fragmentation |
| [SpoofDPI](https://github.com/xvzc/SpoofDPI) | macOS, Linux | HTTP/TLS splitting proxy |

These tools fragment the ClientHello across multiple TCP segments. That still helps on **non-reassembling** paths, but the June wave reassembles the stream on some nodes, so results are path-dependent — try them, but they are not a guaranteed fix anymore.

!!! tip "Keep Telegram updated, and watch the randomization work"
    The durable fix is the **client** randomizing its TLS fingerprint instead of emitting one fixed JA4. That work is in progress upstream but **not yet shipped**: [tdesktop #30733](https://github.com/telegramdesktop/tdesktop/issues/30733) tracks the request to rotate/randomize the JA4, with open PRs ([#30528](https://github.com/telegramdesktop/tdesktop/pull/30528), [#30738](https://github.com/telegramdesktop/tdesktop/pull/30738)) and the more thorough [telemt/tdlib-obf](https://github.com/telemt/tdlib-obf) effort (capture-driven ClientHello masking against real browser profiles). The April fingerprint fix ([tdesktop #30513](https://github.com/telegramdesktop/tdesktop/pull/30513)) is already in current releases — always run the latest client, but understand it still emits a single fixed JA4 until randomization lands.

## What Cannot Be Fully Fixed Server-Side

- **Client TLS fingerprint content**: The Telegram app controls the byte-for-byte content of the ClientHello, and TSPU sits between the client and the proxy. Server-side code cannot alter what the client puts on the wire. The MSS clamp can spread those bytes across TCP segments, but DPI nodes that reassemble the stream — as the June 2026 wave does — recompute the correct JA4 regardless. The only real fix for the fingerprint is client-side (see above).
- **IP/L3 blocking and IP bans**: When DPI blocks an IP at the network layer — including post-detection bans that spill onto neighboring IPs in the same range — only a VPN, a Reality cascade, or moving to a clean IP helps.
- **TSPU deployment variance**: Whether a given path detects the traffic depends on that node's TSPU hardware/software version and whether it reassembles TCP. This varies by operator, region, and even mobile-vs-wired on the same operator.
