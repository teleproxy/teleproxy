# Secrets & Limits

## Generating Secrets

Generate a random 16-byte secret:

```bash
teleproxy generate-secret
```

For fake-TLS mode, pass the domain to get the full `ee`-prefixed secret ready for client links:

```bash
teleproxy generate-secret www.google.com
# stdout:  ee<secret><domain-hex>  (use in tg://proxy links)
# stderr:  Secret for -S: <secret>  (use with -S flag)
```

## Multiple Secrets

Up to 16 secrets, each with an optional label:

```bash
./teleproxy ... -S cafe...ab:family -S dead...ef:friends
```

## Secret Labels

Labels identify which secret a connection uses.

CLI:

```bash
./teleproxy ... -S cafe...ab:family -S dead...ef:friends
```

Installer:

```bash
curl -sSL .../install.sh | \
  SECRET_1=cafe...ab SECRET_LABEL_1=family \
  SECRET_2=dead...ef SECRET_LABEL_2=friends \
  sh
```

Docker:

```bash
# Inline labels
SECRET=cafe...ab:family,dead...ef:friends

# Or numbered
SECRET_1=cafe...ab
SECRET_LABEL_1=family
SECRET_2=dead...ef
SECRET_LABEL_2=friends
```

Labels appear in:

- **Logs:** `TLS handshake matched secret [family] from 1.2.3.4:12345`
- **Prometheus:** `teleproxy_secret_connections{secret="family"} 3`
- **Stats:** `secret_family_connections	3`

Unlabeled secrets are auto-labeled `secret_0`, `secret_1`, etc.

Label rules: max 32 chars, alphanumeric plus `_` and `-`.

## Per-Secret Connection Limits

Prevent a leaked secret from consuming all resources:

```bash
# CLI: append :LIMIT after the label
./teleproxy ... -S cafe...ab:family:1000 -S dead...ef:public:200

# Without a label
./teleproxy ... -S cafe...ab::500
```

Installer:

```bash
curl -sSL .../install.sh | \
  SECRET_1=cafe...ab SECRET_LABEL_1=family SECRET_LIMIT_1=1000 \
  SECRET_2=dead...ef SECRET_LABEL_2=public SECRET_LIMIT_2=200 \
  sh
```

Docker:

```bash
# Environment variables
SECRET_LIMIT_1=1000
SECRET_LIMIT_2=200

# Inline
SECRET=cafe...ab:family:1000,dead...ef:public:200
```

When the limit is reached:

- **Fake-TLS (EE):** rejected during TLS handshake — client sees the backend website
- **Obfuscated2 (DD):** connection silently dropped

Multi-worker note: with `-M N` workers, each enforces `limit / N` independently.

Metrics:

- **Stats:** `secret_family_limit 1000`, `secret_family_rejected 42`
- **Prometheus:** `teleproxy_secret_connection_limit{secret="family"} 1000`, `teleproxy_secret_connections_rejected_total{secret="family"} 42`
