#!/bin/sh
# Teleproxy one-liner installer for bare-metal Linux servers.
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/teleproxy/teleproxy/main/install.sh | sh
#
# Environment variables (set before running to customize):
#   PORT              Client port (default: 443)
#   STATS_PORT        Stats port (default: 8888)
#   WORKERS           Worker processes (default: 1)
#   SECRET            Pre-set secret (default: auto-generated)
#   EE_DOMAIN         Enable fake-TLS with this domain
#   TELEPROXY_VERSION Pin a specific version (default: latest)
#
# Uninstall:
#   curl -sSL https://raw.githubusercontent.com/teleproxy/teleproxy/main/install.sh | sh -s -- --uninstall

set -eu

GITHUB_REPO="teleproxy/teleproxy"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/teleproxy"
CONFIG_FILE="$CONFIG_DIR/config.toml"
SERVICE_FILE="/etc/systemd/system/teleproxy.service"
SERVICE_USER="teleproxy"

# Defaults (overridable via env)
PORT="${PORT:-443}"
STATS_PORT="${STATS_PORT:-8888}"
WORKERS="${WORKERS:-1}"
SECRET="${SECRET:-}"
EE_DOMAIN="${EE_DOMAIN:-}"
TELEPROXY_VERSION="${TELEPROXY_VERSION:-}"

# Colors (only when stdout is a terminal)
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' NC=''
fi

info()  { printf "${GREEN}[+]${NC} %s\n" "$1"; }
warn()  { printf "${YELLOW}[!]${NC} %s\n" "$1"; }
die()   { printf "${RED}[x]${NC} %s\n" "$1" >&2; exit 1; }

# ── Uninstall ──────────────────────────────────────────────────

do_uninstall() {
    info "Uninstalling Teleproxy..."
    systemctl disable --now teleproxy 2>/dev/null || true
    rm -f "$SERVICE_FILE"
    systemctl daemon-reload 2>/dev/null || true
    rm -f "$INSTALL_DIR/teleproxy"
    rm -rf "$CONFIG_DIR"
    userdel "$SERVICE_USER" 2>/dev/null || true
    info "Teleproxy uninstalled."
    exit 0
}

# Handle --uninstall flag
for arg in "$@"; do
    case "$arg" in
        --uninstall) do_uninstall ;;
    esac
done

# ── Checks ─────────────────────────────────────────────────────

[ "$(id -u)" -ne 0 ] && die "Run as root (or with sudo)"

OS=$(uname -s)
[ "$OS" = "Linux" ] || die "This installer supports Linux only (detected: $OS)"

ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  ARCH_SUFFIX="amd64" ;;
    aarch64) ARCH_SUFFIX="arm64" ;;
    *)       die "Unsupported architecture: $ARCH (need x86_64 or aarch64)" ;;
esac

if [ ! -d /run/systemd/system ]; then
    die "systemd not detected. Use Docker or set up the service manually."
fi

# Prefer curl, fall back to wget
if command -v curl >/dev/null 2>&1; then
    DL="curl -fsSL -o"
elif command -v wget >/dev/null 2>&1; then
    DL="wget -qO"
else
    die "Neither curl nor wget found"
fi

# ── Download binary ────────────────────────────────────────────

if [ -n "$TELEPROXY_VERSION" ]; then
    URL="https://github.com/$GITHUB_REPO/releases/download/v${TELEPROXY_VERSION}/teleproxy-linux-${ARCH_SUFFIX}"
else
    URL="https://github.com/$GITHUB_REPO/releases/latest/download/teleproxy-linux-${ARCH_SUFFIX}"
fi

RUNNING=0
if systemctl is-active --quiet teleproxy 2>/dev/null; then
    RUNNING=1
    info "Stopping running teleproxy service..."
    systemctl stop teleproxy
fi

info "Downloading teleproxy ($ARCH_SUFFIX)..."
TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT
$DL "$TMP" "$URL" || die "Download failed. Check your network or version."
chmod +x "$TMP"
mv "$TMP" "$INSTALL_DIR/teleproxy"
trap - EXIT
info "Installed to $INSTALL_DIR/teleproxy"

# ── Create system user ─────────────────────────────────────────

if ! id "$SERVICE_USER" >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
    info "Created system user: $SERVICE_USER"
fi

# ── Generate config ────────────────────────────────────────────

mkdir -p "$CONFIG_DIR"

if [ -f "$CONFIG_FILE" ]; then
    info "Keeping existing config: $CONFIG_FILE"
else
    # Generate secret
    if [ -z "$SECRET" ]; then
        SECRET=$("$INSTALL_DIR/teleproxy" generate-secret 2>/dev/null) || \
            SECRET=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')
    fi

    {
        echo "# Teleproxy configuration"
        echo "# Edit and run: systemctl reload teleproxy"
        echo "port = $PORT"
        echo "stats_port = $STATS_PORT"
        echo "http_stats = true"
        echo "user = \"$SERVICE_USER\""
        echo "direct = true"
        echo "workers = $WORKERS"
        if [ -n "$EE_DOMAIN" ]; then
            echo "domain = \"$EE_DOMAIN\""
        fi
        echo ""
        echo "[[secret]]"
        echo "key = \"$SECRET\""
        echo "label = \"default\""
    } > "$CONFIG_FILE"

    chmod 640 "$CONFIG_FILE"
    chown root:"$SERVICE_USER" "$CONFIG_FILE"
    info "Generated config: $CONFIG_FILE"
fi

# ── Systemd unit ───────────────────────────────────────────────

cat > "$SERVICE_FILE" << 'UNIT'
[Unit]
Description=Teleproxy MTProto Proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=teleproxy
ExecStart=/usr/local/bin/teleproxy --config /etc/teleproxy/config.toml
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/etc/teleproxy

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
info "Installed systemd unit"

# ── Start ──────────────────────────────────────────────────────

systemctl enable --now teleproxy
info "Teleproxy is running"

# ── Print connection link ──────────────────────────────────────

# Read secret from config
CFG_SECRET=$(grep '^key' "$CONFIG_FILE" | head -1 | sed 's/.*"\(.*\)"/\1/')

# Detect external IP
EXT_IP=""
if command -v curl >/dev/null 2>&1; then
    EXT_IP=$(curl -s -4 --connect-timeout 5 --max-time 10 https://icanhazip.com 2>/dev/null || \
             curl -s -4 --connect-timeout 5 --max-time 10 https://ifconfig.me 2>/dev/null || true)
fi
EXT_IP=$(echo "$EXT_IP" | tr -d '[:space:]')
EXT_IP="${EXT_IP:-<YOUR_SERVER_IP>}"

# Build secret prefix for connection link
if [ -n "$EE_DOMAIN" ]; then
    DOMAIN_HEX=$(printf '%s' "$EE_DOMAIN" | od -An -tx1 | tr -d ' \n')
    LINK_SECRET="ee${CFG_SECRET}${DOMAIN_HEX}"
else
    LINK_SECRET="$CFG_SECRET"
fi

echo ""
echo "===== Connection Link ====="
teleproxy link --server "$EXT_IP" --port "$PORT" --secret "$LINK_SECRET"
echo "==========================="
echo ""
echo "Manage:"
echo "  systemctl status teleproxy    # check status"
echo "  systemctl reload teleproxy    # reload config (SIGHUP)"
echo "  journalctl -u teleproxy -f    # view logs"
echo "  nano $CONFIG_FILE             # edit config"
echo ""
echo "Upgrade: re-run this script"
echo "Uninstall: curl -sSL ... | sh -s -- --uninstall"
