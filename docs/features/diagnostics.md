# Diagnostics

The `check` subcommand validates your configuration and tests connectivity before accepting clients. Useful for troubleshooting "my proxy doesn't work" without guessing.

```bash
teleproxy check --config /etc/teleproxy/config.toml
```

Or with CLI flags:

```bash
teleproxy check --direct -S <secret> -D ya.ru
```

## What It Checks

| Check | What it does |
|-------|-------------|
| **Configuration** | Parses and validates config (TOML or CLI flags) |
| **DC connectivity** | TCP connects to all 5 Telegram datacenters |
| **Clock sync** | Queries NTP to verify clock is within the 120s anti-replay window |
| **TLS domain probe** | Resolves the fake-TLS domain, connects, and verifies TLS 1.3 |
| **SNI/DNS match** | Warns if the domain resolves to a different IP than the proxy |

TLS and SNI checks only run when `-D` / `domain` is configured.

## Example Output

```
teleproxy check

  Configuration .............. OK (mode: direct, 2 secrets, 1 domain)
  DC 1 (149.154.175.50) ..... OK (45ms)
  DC 2 (149.154.167.51) ..... OK (52ms)
  DC 3 (149.154.175.100) .... OK (41ms)
  DC 4 (149.154.167.91) ..... OK (38ms)
  DC 5 (91.108.56.100) ...... OK (55ms)
  Clock sync ................. OK (drift 0.3s, limit 120s)
  TLS ya.ru .................. OK (5.255.255.242, TLS 1.3)
  SNI ya.ru .................. WARN
    ya.ru resolves to 5.255.255.242, proxy is 1.2.3.4

8 passed, 0 failed, 1 warning
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All checks passed (warnings are OK) |
| 1 | One or more checks failed |
| 2 | Bad arguments (invalid config, missing flags) |

## Options

All options from the main proxy are accepted for config purposes:

```
--config FILE          TOML configuration file
--direct               Direct mode
-S, --secret SECRET    32-char hex secret (repeatable)
-D, --domain DOMAIN    TLS domain[:port] (repeatable)
--dc-override DC:H:P   Override DC address (repeatable)
```

The subcommand runs independently of the proxy — no ports are opened, no engine is started. Safe to run alongside a running instance.

## SNI Mismatch Warning

The SNI check detects whether the fake-TLS domain's DNS points to your proxy's IP. If it doesn't, censors can trivially detect the proxy by comparing the SNI hostname against the connection IP.

To fix this, either:

- Point your own domain's DNS A record to the proxy's IP
- Accept the risk if your threat model doesn't include active SNI probing
