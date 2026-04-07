---
description: "Install Teleproxy via one-liner script, manual binary download, or from source. Supports x86_64 and ARM64 on Linux."
---

# Installation

## One-Liner Install (Recommended)

The install script downloads the binary, creates a systemd service, generates a secret, and prints the connection link:

```bash
curl -sSL https://raw.githubusercontent.com/teleproxy/teleproxy/main/install.sh | sh
```

Customize with environment variables:

```bash
curl -sSL https://raw.githubusercontent.com/teleproxy/teleproxy/main/install.sh | PORT=8443 EE_DOMAIN=www.google.com sh
```

### Multiple Secrets

Auto-generate several secrets at once:

```bash
curl -sSL https://raw.githubusercontent.com/teleproxy/teleproxy/main/install.sh | SECRET_COUNT=3 sh
```

Or pass your own as a comma-separated list:

```bash
curl -sSL https://raw.githubusercontent.com/teleproxy/teleproxy/main/install.sh | \
  SECRET=aabbccdd11223344aabbccdd11223344,eeff00112233445566778899aabbccdd sh
```

Numbered secrets with labels and per-secret connection limits:

```bash
curl -sSL https://raw.githubusercontent.com/teleproxy/teleproxy/main/install.sh | \
  SECRET_1=aabbccdd11223344aabbccdd11223344 SECRET_LABEL_1=family \
  SECRET_2=eeff00112233445566778899aabbccdd SECRET_LABEL_2=work SECRET_LIMIT_2=500 \
  sh
```

Each secret gets its own QR code and connection link at the end of installation. You can also add or remove secrets later by editing the config and reloading:

```bash
nano /etc/teleproxy/config.toml
systemctl reload teleproxy
```

After installation, manage with:

```bash
systemctl status teleproxy       # check status
systemctl reload teleproxy       # reload config after editing
nano /etc/teleproxy/config.toml  # edit config (secrets, ports, etc.)
```

To uninstall:

```bash
curl -sSL https://raw.githubusercontent.com/teleproxy/teleproxy/main/install.sh | sh -s -- --uninstall
```

## Updating

Re-run the install script to upgrade to the latest version:

```bash
curl -sSL https://raw.githubusercontent.com/teleproxy/teleproxy/main/install.sh | sh
```

The script replaces the binary and restarts the service. Your existing config (`/etc/teleproxy/config.toml`) — including secrets, ports, and domain settings — is preserved.

To pin a specific version:

```bash
curl -sSL https://raw.githubusercontent.com/teleproxy/teleproxy/main/install.sh | TELEPROXY_VERSION=1.2.3 sh
```

## RPM Repository (RHEL, Rocky, Alma, Fedora)

For RHEL 9, RHEL 10, AlmaLinux, Rocky Linux and Fedora 41/42, install via dnf so updates flow through the package manager:

```bash
dnf install https://teleproxy.github.io/repo/teleproxy-release-latest.noarch.rpm
dnf install teleproxy
systemctl enable --now teleproxy
```

The first install generates a random secret in `/etc/teleproxy/config.toml`; the post-install message prints the connection link. Subsequent `dnf upgrade` runs swap the binary and never touch your config.

The repository is signed with an RSA 4096 / SHA-512 GPG key (RHEL 9 rpm-sequoia compatible). The setup RPM drops both `/etc/yum.repos.d/teleproxy.repo` and the public key into `/etc/pki/rpm-gpg/`.

To uninstall:

```bash
dnf remove teleproxy
```

Your `/etc/teleproxy/config.toml` is left in place so re-installs pick up where you left off.

## Static Binary (Any Linux)

Pre-built static binaries are published with every release — statically linked against musl libc, zero runtime dependencies. Download and run.

=== "amd64"

    ```bash
    curl -Lo teleproxy https://github.com/teleproxy/teleproxy/releases/latest/download/teleproxy-linux-amd64
    chmod +x teleproxy
    ```

=== "arm64"

    ```bash
    curl -Lo teleproxy https://github.com/teleproxy/teleproxy/releases/latest/download/teleproxy-linux-arm64
    chmod +x teleproxy
    ```

SHA256 checksums are published alongside each release for verification.

## Docker

See [Docker Quick Start](../docker/index.md) for the simplest way to run Teleproxy — a single `docker run` command with auto-generated secrets.

## Building from Source

Install build dependencies:

=== "Debian / Ubuntu"

    ```bash
    apt install git curl build-essential libssl-dev zlib1g-dev
    ```

=== "CentOS / RHEL"

    ```bash
    yum groupinstall "Development Tools"
    yum install openssl-devel zlib-devel
    ```

=== "macOS (development)"

    ```bash
    brew install epoll-shim openssl
    ```

    macOS builds use [epoll-shim](https://github.com/jiixyj/epoll-shim) to wrap kqueue behind the Linux epoll API, and Homebrew OpenSSL (keg-only). This is intended for local development — production deployments should use Linux.

Clone and build:

```bash
git clone https://github.com/teleproxy/teleproxy
cd teleproxy
make
```

The compiled binary will be at `objs/bin/teleproxy`.

!!! note
    If the build fails, run `make clean` before retrying.
