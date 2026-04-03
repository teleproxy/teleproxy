# Connection Links

The `link` subcommand prints a ready-to-share proxy URL and renders a scannable QR code directly in the terminal. Point a phone camera at the screen to connect — no copy-pasting needed.

```bash
teleproxy link --server 203.0.113.1 --port 443 --secret ee1234...abcdef
```

## Output

The command prints the `t.me` proxy URL followed by a QR code encoded with UTF-8 block characters:

```
https://t.me/proxy?server=203.0.113.1&port=443&secret=ee1234...abcdef

█████████████████████████████
██ ▄▄▄▄▄ █▄▀▄ █▄██ ▄▄▄▄▄ ██
██ █   █ █▀█▄  ▄ █ █   █ ██
   ...
```

The QR code works in any terminal that supports UTF-8 — including SSH sessions, Docker logs, and `journalctl` output.

## Automatic Display

QR codes are shown automatically at startup in both deployment methods:

- **Docker**: `start.sh` prints a QR code for each configured secret
- **Bare metal**: `install.sh` prints a QR code after installation completes

No extra configuration is needed.

## Options

```
--server HOST     Server IP or hostname (required)
--port PORT       Proxy port (required)
--secret SECRET   Full client secret including prefix (required)
--label LABEL     Optional label shown next to the URL
```

## Multiple Secrets

When multiple secrets are configured, each gets its own URL and QR code:

```
===== Connection Links =====
https://t.me/proxy?server=203.0.113.1&port=443&secret=ee1234...ab [family]
<QR code>
https://t.me/proxy?server=203.0.113.1&port=443&secret=ee5678...cd [work]
<QR code>
=============================
```

The `[label]` suffix appears in the text output only — the QR code encodes just the URL.

## Manual Usage

Generate a QR code for an existing proxy:

```bash
# Plain secret
teleproxy link --server YOUR_IP --port 443 --secret aabbccdd11223344aabbccdd11223344

# Fake-TLS secret (ee-prefixed)
teleproxy link --server YOUR_IP --port 443 \
  --secret ee11223344556677881122334455667788676f6f676c652e636f6d
```

The secret format is the same as in `tg://proxy` URLs — pass it exactly as your users would see it.
