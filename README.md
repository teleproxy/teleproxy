# Teleproxy

**[Русский](README.ru.md)** | **[فارسی](README.fa.md)** | **[Tiếng Việt](README.vi.md)**

High-performance MT-Proto proxy for Telegram with DPI resistance, fake-TLS camouflage, and production-grade monitoring.

**Features**: Fake-TLS (EE mode), Direct-to-DC, Dynamic Record Sizing, IP access control, Prometheus metrics, multi-secret support with labels, static binaries, Docker, ARM64.

## Install

### Static Binary (Any Linux)

Pre-built static binaries (musl libc, zero dependencies) are available for every [release](https://github.com/teleproxy/teleproxy/releases):

```bash
# Download (choose amd64 or arm64)
curl -Lo teleproxy https://github.com/teleproxy/teleproxy/releases/latest/download/teleproxy-linux-amd64
chmod +x teleproxy

# Generate a secret
SECRET=$(head -c 16 /dev/urandom | xxd -ps)

# Run in direct mode (simplest — no config files needed)
./teleproxy -S "$SECRET" -H 443 --direct -p 8888 --aes-pwd /dev/null
```

Binaries are available for `linux/amd64` and `linux/arm64`. SHA256 checksums are published alongside each release.

### Manual Build (Advanced)


## Building
Install dependencies, you would need common set of tools for building from source, and development packages for `openssl` and `zlib`.

On Debian/Ubuntu:
```bash
apt install git curl build-essential libssl-dev zlib1g-dev
```
On CentOS/RHEL (not advisable, use packages mentioned above instead):
```bash
yum install openssl-devel zlib-devel
yum groupinstall "Development Tools"
```

Clone the repo:
```bash
git clone https://github.com/teleproxy/teleproxy
cd teleproxy
```

To build, simply run `make`, the binary will be in `objs/bin/teleproxy`:

```bash
make && cd objs/bin
```

If the build has failed, you should run `make clean` before building it again.

## Testing

This repository includes a comprehensive test suite. For detailed instructions, see [TESTING.md](TESTING.md).

To run the tests using Docker:

```bash
# Export environment variables (see TESTING.md)
export TELEPROXY_SECRET=...
make test
```

## Running
1. Obtain a secret, used to connect to telegram servers.
```bash
curl --connect-timeout 10 --max-time 30 --retry 3 -fsSL https://core.telegram.org/getProxySecret -o proxy-secret
```
2. Obtain current telegram configuration. It can change (occasionally), so we encourage you to update it once per day.
```bash
curl --connect-timeout 10 --max-time 30 --retry 3 -fsSL https://core.telegram.org/getProxyConfig -o proxy-multi.conf
```
3. Generate a secret to be used by users to connect to your proxy.
```bash
head -c 16 /dev/urandom | xxd -ps
```
4. Run `teleproxy`:
```bash
./teleproxy -u nobody -p 8888 -H 443 -S <secret> --http-stats --aes-pwd proxy-secret proxy-multi.conf -M 1
```
... where:
- `nobody` is the username. `teleproxy` calls `setuid()` to drop privilegies.
- `443` is the port, used by clients to connect to the proxy.
- `8888` is the local port for statistics (requires `--http-stats`). Like `curl http://localhost:8888/stats`. Stats are accessible from private networks (loopback, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) but not from public IPs.
- `<secret>` is the secret generated at step 3. Also you can set multiple secrets: `-S <secret1> -S <secret2>`. Each secret can have an optional label: `-S <secret>:family -S <secret>:friends`. Labels appear in logs and stats instead of raw secrets, making it easy to identify which secret a connection used. You can also set a per-secret connection limit: `-S <secret>:family:1000` (see [Per-Secret Connection Limits](#per-secret-connection-limits)).
- `--aes-pwd proxy-secret` points to the `proxy-secret` file downloaded at step 1, which contains the encryption key used for MTProto key exchange with Telegram DCs.
- `proxy-secret` and `proxy-multi.conf` are obtained at steps 1 and 2.
- `1` is the number of workers. You can increase the number of workers, if you have a powerful server.

Also feel free to check out other options using `teleproxy --help`.

### IP Access Control

Restrict client connections by IP address using CIDR-based blocklist/allowlist files:

```bash
./teleproxy ... --ip-blocklist blocklist.txt --ip-allowlist allowlist.txt
```

File format (one CIDR range per line, `#` comments allowed):
```
# Block known scanner ranges
185.220.101.0/24
2001:db8::/32
```

- Both IPv4 and IPv6 CIDR notation supported
- `--ip-allowlist`: only matching IPs are accepted (whitelist mode)
- `--ip-blocklist`: matching IPs are rejected
- Files are reloaded on `SIGHUP` — update rules without restarting the proxy
- Rejected connections are tracked via Prometheus metric `teleproxy_ip_acl_rejected_total`

5. Generate the link with following schema: `tg://proxy?server=SERVER_NAME&port=PORT&secret=SECRET` (or let the official bot generate it for you).
6. Register your proxy with [@MTProxybot](https://t.me/MTProxybot) on Telegram.
7. Set received tag with arguments: `-P <proxy tag>`
8. Enjoy.

### Direct-to-DC Mode

By default, Teleproxy routes traffic through Telegram's middle-end (ME) relay servers listed in `proxy-multi.conf`. Direct mode bypasses the ME relays and connects straight to Telegram data centers, reducing latency and simplifying deployment:

```
Default:  Client → Teleproxy → ME relay (proxy-multi.conf) → Telegram DC
Direct:   Client → Teleproxy → Telegram DC
```

To enable direct mode, use `--direct`:

```bash
./teleproxy -u nobody -p 8888 -H 443 -S <secret> --http-stats --direct
```

In direct mode:
- No `proxy-multi.conf` or `proxy-secret` files are needed
- No config file argument is required
- The proxy connects directly to well-known Telegram DC addresses
- **Incompatible with `-P` (proxy tag)** — promoted channels require ME relays

## Using IPv6

Teleproxy supports IPv6. To enable it, pass the `-6` flag and specify only port numbers to `-H` (do not include an address like `[::]:443`).

### Example (direct run)
```bash
./teleproxy -6 -u nobody -p 8888 -H 443 -S <secret> --http-stats --aes-pwd proxy-secret proxy-multi.conf -M 1
```

- `-6` enables IPv6 listening. The proxy binds to `::` (all IPv6 interfaces). On most systems this also accepts IPv4 connections on the same port (dual-stack), unless the kernel forces IPv6-only.
- `-H` accepts a comma-separated list of ports only (e.g., `-H 80,443`). Do not pass IP literals to `-H`.
- Binding to a specific IPv6 address is not currently supported. If you must restrict which address is reachable, use a firewall (ip6tables/nftables/security groups).

### Client side
- You can use either a hostname with an AAAA record or a raw IPv6 address.
- When sharing links, prefer a hostname with an AAAA record. Some clients may not accept raw IPv6 literals in `tg://` links.

Examples:
- Hostname: `tg://proxy?server=proxy.example.com&port=443&secret=<secret>` (with AAAA record on `proxy.example.com`).
- Raw IPv6 (may not be supported by all clients): `tg://proxy?server=[2001:db8::1]&port=443&secret=<secret>`

### Quick checks
- Verify the proxy listens on IPv6:
  ```bash
  ss -ltnp | grep :443
  # Expect to see :::443 among listeners
  ```
- Test locally (stats endpoint):
  ```bash
  curl -6 http://[::1]:8888/stats
  ```

### Troubleshooting IPv6
- Ensure IPv6 is enabled on the host:
  ```bash
  sysctl net.ipv6.conf.all.disable_ipv6
  # should be 0
  ```
- Firewalls/security groups must allow IPv6 on the chosen port (separate from IPv4 rules).
- If IPv4 stops working after enabling `-6`, your system might enforce IPv6-only sockets (V6ONLY). Check `net.ipv6.bindv6only` and firewall rules.
- Use a hostname with an AAAA record to avoid client parsing issues with IPv6 literals in links.

### Systemd example (IPv6)
```ini
[Unit]
Description=Teleproxy (IPv6)
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/teleproxy
ExecStart=/opt/teleproxy/teleproxy -6 -u nobody -p 8888 -H 443 -S <secret> --http-stats -P <proxy tag> --aes-pwd proxy-secret proxy-multi.conf -M 1
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

### Docker notes (IPv6)
- Ensure Docker daemon has IPv6 enabled and the host has routable IPv6.
- Port publishing must include IPv6 (Docker binds to IPv6 only if daemon IPv6 is enabled). See Docker docs for `daemon.json` (`"ipv6": true`, `"fixed-cidr-v6": "…/64"`).
- The provided image’s default entrypoint does not add `-6`. To use IPv6, either run Teleproxy on the host, or build/override the container command to include `-6`.

## Transport Modes and Secret Prefixes

Teleproxy supports different transport modes that provide various levels of obfuscation:

### DD Mode (Random Padding)
Due to some ISPs detecting MTProto proxy by packet sizes, random padding is added to packets when this mode is enabled.

**Client Setup**: Add `dd` prefix to secret (`cafe...babe` => `ddcafe...babe`)

**Server Setup**: Use `-R` argument to allow only clients with random padding enabled

### EE Mode (Fake-TLS + Padding)

EE mode provides enhanced obfuscation by mimicking TLS 1.3 connections, making proxy traffic harder to detect and block.

**Server Setup**:
1. **Add domain configuration**: Choose a website that supports TLS 1.3 (e.g., `www.google.com`, `www.cloudflare.com`)
   ```bash
   ./teleproxy -u nobody -p 8888 -H 443 -S <secret> -D www.google.com --http-stats --aes-pwd proxy-secret proxy-multi.conf -M 1
   ```

2. **Get domain HEX dump**:
   ```bash
   echo -n www.google.com | xxd -plain
   # Output: 7777772e676f6f676c652e636f6d
   ```

**Client Setup**:
Use the format: `ee` + server_secret + domain_hex

**Example**:
- Server secret: `cafe1234567890abcdef1234567890ab`
- Domain: `www.google.com` 
- Domain HEX: `7777772e676f6f676c652e636f6d`
- **Client secret**: `eecafe1234567890abcdef1234567890ab7777772e676f6f676c652e636f6d`

**Quick Generation**:
```bash
# Generate complete client secret automatically
SECRET="cafe1234567890abcdef1234567890ab"
DOMAIN="www.google.com"
echo -n "ee${SECRET}" && echo -n $DOMAIN | xxd -plain
```

**Benefits**:
- ✅ **Traffic appears as TLS 1.3**: Harder to detect and block
- ✅ **Works with modern clients**: Desktop, mobile, and web clients
- ✅ **Domain flexibility**: Choose any TLS 1.3-capable domain
- ✅ **DPI resistant**: Traffic indistinguishable from standard TLS 1.3

### EE Mode with Custom TLS Backend (TCP Splitting)

Instead of mimicking a public website, you can run your own web server (e.g., nginx) behind Teleproxy with a real TLS certificate for your domain. Non-proxy visitors see a fully functioning HTTPS website, making the server indistinguishable from a normal web server.

**How it works:**
- Teleproxy listens on port 443
- nginx runs on a non-standard port (e.g., 8443) with a valid certificate for your domain
- The domain's DNS A record points to the Teleproxy server
- Valid Teleproxy clients connect normally; all other traffic is forwarded to nginx

**Active probing resistance:** Every connection that fails Teleproxy validation — wrong secret, expired timestamp, unknown SNI, replayed handshake, malformed ClientHello, or plain non-TLS traffic — is transparently forwarded to the backend rather than rejected with a TLS error. Anyone probing the server with a standard browser sees a real HTTPS website, making the proxy indistinguishable from a normal web server under active probing.

**Dynamic Record Sizing (DRS):** TLS connections automatically use graduated record sizes that mimic real HTTPS servers (Cloudflare, Go, Caddy): small MTU-sized records during TCP slow-start (~1450 bytes), ramping to ~4096 bytes, then max TLS payload (~16144 bytes). This defeats statistical traffic analysis that fingerprints proxy traffic by its uniform record sizes. No configuration needed — DRS activates automatically for all TLS connections.

**Requirements:**
- The backend must support **TLS 1.3** (Teleproxy verifies this at startup)
- The `-D` value **must be a hostname**, not a raw IP address. Using an IP address (e.g., `-D 127.0.0.1:8443`) breaks `ee` secrets because TLS SNI does not support IP addresses (RFC 6066)

**Setup:**

1. Configure nginx to listen on a local port with TLS 1.3:
   ```nginx
   server {
       listen 127.0.0.1:8443 ssl default_server;
       server_name mywebsite.com;

       ssl_certificate /etc/letsencrypt/live/mywebsite.com/fullchain.pem;
       ssl_certificate_key /etc/letsencrypt/live/mywebsite.com/privkey.pem;
       ssl_protocols TLSv1.3;
       ssl_prefer_server_ciphers off;

       root /var/www/html;

       location / {
           try_files $uri $uri/ =404;
       }
   }
   ```
   > **Certificate renewal**: Use certbot with DNS-01 challenge (`--preferred-challenges dns`). HTTP-01 challenge will not work because Teleproxy occupies port 443.

2. Add an `/etc/hosts` entry so Teleproxy resolves the domain to loopback (needed when nginx only listens on `127.0.0.1`):
   ```
   127.0.0.1 mywebsite.com
   ```
   > **Note**: If nginx listens on all interfaces (`0.0.0.0:8443`) and the domain's DNS already points to this server, you can skip the `/etc/hosts` entry.

3. Run Teleproxy with the domain and port:
   ```bash
   ./teleproxy -u nobody -p 8888 -H 443 -S <secret> -D mywebsite.com:8443 --http-stats --aes-pwd proxy-secret proxy-multi.conf -M 1
   ```

4. Generate the client `ee` secret as usual (using `mywebsite.com` as the domain):
   ```bash
   SECRET="<your_32_hex_secret>"
   echo -n "ee${SECRET}" && echo -n mywebsite.com | xxd -plain
   ```

## Systemd example configuration
1. Create systemd service file (it's standard path for the most Linux distros, but you should check it before):
```bash
nano /etc/systemd/system/teleproxy.service
```
2. Edit this basic service (especially paths and params):
```bash
[Unit]
Description=Teleproxy
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/teleproxy
ExecStart=/opt/teleproxy/teleproxy -u nobody -p 8888 -H 443 -S <secret> -P <proxy tag> <other params>
ExecStart=/opt/teleproxy/teleproxy -u nobody -p 8888 -H 443 -S <secret> --http-stats -P <proxy tag> <other params>
Restart=on-failure

[Install]
WantedBy=multi-user.target
```
3. Reload daemons:
```bash
systemctl daemon-reload
```
4. Test fresh Teleproxy service:
```bash
systemctl restart teleproxy.service
# Check status, it should be active
systemctl status teleproxy.service
```
5. Enable it, to autostart service after reboot:
```bash
systemctl enable teleproxy.service
```

## Docker

### Quick Start

The simplest way to run Teleproxy - no configuration needed:

```bash
docker run -d \
  --name teleproxy \
  -p 443:443 \
  -p 8888:8888 \
  --restart unless-stopped \
  ghcr.io/teleproxy/teleproxy:latest
```

The container automatically:
- Downloads the latest proxy configuration from Telegram
- Generates a random secret if none is provided
- Starts the proxy on port 443

**Connection Links at Startup:**

The container prints ready-to-share connection links in the logs:

```bash
docker logs teleproxy
# ===== Connection Links =====
# https://t.me/proxy?server=203.0.113.1&port=443&secret=eecafe...
# =============================
```

If external IP detection fails, links show `<YOUR_SERVER_IP>` — set `EXTERNAL_IP` to fix.

### Using Pre-built Docker Image (Advanced)

For more control, specify environment variables:

```bash
docker run -d \
  --name teleproxy \
  -p 443:443 \
  -p 8888:8888 \
  -e SECRET=$(head -c 16 /dev/urandom | xxd -ps) \
  -e PROXY_TAG=your_proxy_tag_here \
  -v teleproxy-data:/opt/teleproxy/data \
  --restart unless-stopped \
  ghcr.io/teleproxy/teleproxy:latest
```

#### Environment Variables

- `SECRET`: Proxy secret(s) — 32 hex characters each (auto-generated if not provided)
  - Single: `SECRET=cafe1234567890abcdef1234567890ab`
  - Multiple (comma-separated): `SECRET=secret1,secret2,secret3`
  - With labels: `SECRET=hex1:family,hex2:friends` (see [Secret Labels](#secret-labels))
  - Multiple (numbered): `SECRET_1=aabb...`, `SECRET_2=ccdd...` (up to `SECRET_16`)
  - If both `SECRET` and `SECRET_N` are set, all are combined
  - Maximum 16 secrets (binary limit)
- `SECRET_LABEL_1`, `SECRET_LABEL_2`, ...: Optional labels for numbered secrets (e.g. `SECRET_LABEL_1=family`). See [Secret Labels](#secret-labels)
- `SECRET_LIMIT_1`, `SECRET_LIMIT_2`, ...: Optional per-secret connection limits (e.g. `SECRET_LIMIT_1=1000`). See [Per-Secret Connection Limits](#per-secret-connection-limits)
- `PORT`: Port for client connections (default: 443)
- `STATS_PORT`: Port for statistics endpoint (default: 8888)
- `WORKERS`: Number of worker processes (default: 1)
- `PROXY_TAG`: Proxy tag from [@MTProxybot](https://t.me/MTProxybot) (optional, for channel promotion)
- `DIRECT_MODE`: Connect directly to Telegram DCs instead of through ME relays (true/false, default: false). Incompatible with `PROXY_TAG`. See [Direct-to-DC Mode](#direct-to-dc-mode)
- `RANDOM_PADDING`: Enable random padding only mode (true/false, default: false)
- `EXTERNAL_IP`: Your public IP address for NAT environments (optional)
- `EE_DOMAIN`: Domain for EE Mode (Fake-TLS + Padding), e.g. `www.google.com`. Accepts `host:port` for custom TLS backends (e.g., `mywebsite.com:8443`). See [Custom TLS Backend](#ee-mode-with-custom-tls-backend-tcp-splitting)
- `IP_BLOCKLIST`: Path (inside container) to a file with CIDR ranges to reject (one per line, `#` comments allowed). Example: `--ip-blocklist /opt/teleproxy/blocklist.txt`
- `IP_ALLOWLIST`: Path (inside container) to a file with CIDR ranges to exclusively allow. When set, only matching IPs are accepted. Both IPv4 and IPv6 CIDR notation supported. Files are reloaded on `SIGHUP`.

#### Getting Statistics

```bash
curl http://localhost:8888/stats
```

#### Prometheus Metrics

```bash
curl http://localhost:8888/metrics
```

Returns metrics in [Prometheus exposition format](https://prometheus.io/docs/instrumenting/exposition_formats/), ready for scraping. Available on the same `--http-stats` port, restricted to private networks. Includes per-secret connection metrics when [secret labels](#secret-labels) are configured.

### Using Docker Compose

The simplest Docker Compose setup (create `docker-compose.yml`):

```yaml
services:
  teleproxy:
    image: ghcr.io/teleproxy/teleproxy:latest
    ports:
      - "443:443"
      - "8888:8888"
    restart: unless-stopped
```

Then run:
```bash
docker-compose up -d
docker-compose logs teleproxy | grep "Generated secret"
```

For custom configuration, create a `.env` file:
```bash
SECRET=your_secret_here
PROXY_TAG=your_proxy_tag_here
RANDOM_PADDING=false
```

For multiple secrets (per-group access control):
```bash
# Option A: comma-separated
SECRET=family_secret_hex,friends_secret_hex,public_secret_hex

# Option B: numbered variables
SECRET_1=family_secret_hex
SECRET_2=friends_secret_hex
SECRET_3=public_secret_hex
```

#### Secret Labels

Labels let you identify which secret a connection is using — useful for revoking leaked
secrets or monitoring per-group traffic:

```bash
# Inline labels (CLI)
./teleproxy ... -S cafe1234567890abcdef1234567890ab:family -S dead1234567890abcdef1234567890ef:friends

# Inline labels (Docker)
SECRET=cafe1234567890abcdef1234567890ab:family,dead1234567890abcdef1234567890ef:friends

# Separate label env vars (Docker)
SECRET_1=cafe1234567890abcdef1234567890ab
SECRET_LABEL_1=family
SECRET_2=dead1234567890abcdef1234567890ef
SECRET_LABEL_2=friends
```

Labels appear in:
- **Logs**: `TLS handshake matched secret [family] from 1.2.3.4:12345`
- **Prometheus** (`/metrics`): `teleproxy_secret_connections{secret="family"} 3`
- **Stats** (`/stats`): `secret_family_connections	3`

If no label is given, secrets are auto-labeled `secret_0`, `secret_1`, etc.

Label rules: max 32 characters, alphanumeric plus `_` and `-` only.

#### Per-Secret Connection Limits

Prevent a leaked or widely-shared secret from consuming all proxy resources by setting
a maximum number of concurrent connections per secret:

```bash
# CLI: append :LIMIT after the label
./teleproxy ... -S cafe...90ab:family:1000 -S dead...90ef:public:200

# Without a label, use an empty label field
./teleproxy ... -S cafe...90ab::500

# Docker: numbered env vars
SECRET_1=cafe1234567890abcdef1234567890ab
SECRET_LABEL_1=family
SECRET_LIMIT_1=1000
SECRET_2=dead1234567890abcdef1234567890ef
SECRET_LABEL_2=public
SECRET_LIMIT_2=200

# Docker: inline (comma-separated)
SECRET=cafe...90ab:family:1000,dead...90ef:public:200
```

When the limit is reached, new connections using that secret are rejected:
- **Fake-TLS (EE mode)**: rejected during the TLS handshake — the client is proxied to the
  configured domain, so it sees a normal website (indistinguishable from a non-proxy server).
- **Obfuscated2 (DD mode)**: the connection is silently dropped.

Existing connections are not affected. Other secrets continue operating normally.

**Multi-worker note**: with `-M N` workers, each worker enforces `limit / N` independently.
For single-worker mode (`-M 0` or `-M 1`), the limit is exact.

Limits appear in stats and Prometheus metrics:
- **Stats** (`/stats`): `secret_family_limit	1000`, `secret_family_rejected	42`
- **Prometheus** (`/metrics`): `teleproxy_secret_connection_limit{secret="family"} 1000`,
  `teleproxy_secret_connections_rejected_total{secret="family"} 42`

Secrets without a limit are unlimited (the default, backward-compatible behavior).

And reference it in your `docker-compose.yml`:
```yaml
services:
  teleproxy:
    image: ghcr.io/teleproxy/teleproxy:latest
    ports:
      - "443:443"
      - "8888:8888"
    environment:
      - SECRET=${SECRET}
      - PROXY_TAG=${PROXY_TAG}
      - RANDOM_PADDING=${RANDOM_PADDING}
    restart: unless-stopped
```

### Building Your Own Image

If you want to build the image yourself:

```bash
docker build -t teleproxy .
docker run -d \
  --name teleproxy \
  -p 443:443 \
  -p 8888:8888 \
  teleproxy
```

Check the logs to find your auto-generated secret:
```bash
docker logs teleproxy 2>&1 | grep "Generated secret"
```

### Health Check

The Docker container includes a health check that monitors the statistics endpoint. You can check the container health with:

```bash
docker ps
# Look for the health status in the STATUS column
```

### Automatic Config Refresh

The container includes a daily cron job that automatically refreshes the Telegram DC configuration (`proxy-multi.conf`). This prevents the proxy from becoming unavailable due to stale server addresses — Telegram periodically rotates DC IPs, and without refresh the proxy may silently lose connectivity.

The refresh process:
1. Downloads the latest config from `core.telegram.org`
2. Validates the downloaded file
3. Compares with the current config — skips if unchanged
4. Replaces the config and sends `SIGHUP` to reload without downtime

No user configuration is needed — this runs automatically.

### Volume Mounting

The container stores `proxy-multi.conf` (Telegram DC addresses) in `/opt/teleproxy/data/`. Mount a volume to persist this configuration across container restarts. The `proxy-secret` file is baked into the image at build time and does not require persistence.

If `core.telegram.org` is unreachable (e.g., due to network restrictions), the container will use a cached `proxy-multi.conf` from the data volume when available. On first run without network access, you must manually place `proxy-multi.conf` in the data volume.

Mount a volume:

```bash
-v /path/to/host/data:/opt/teleproxy/data
```

### Available Tags

- `ghcr.io/teleproxy/teleproxy:latest` - Latest stable build from master branch
- `ghcr.io/teleproxy/teleproxy:master` - Latest build from master branch
- `ghcr.io/teleproxy/teleproxy:v*` - Specific version tags (when available)
