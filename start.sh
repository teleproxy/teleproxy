#!/bin/sh
set -e

# Save original arguments before positional parameters are repurposed for secrets
ORIG_ARGS="$*"

# Backward-compat: accept old MTPROXY_* env vars with deprecation warning
for _old_var in SECRET SECRET_1 SECRET_2 SECRET_3 SECRET_4 SECRET_5 SECRET_6 \
  SECRET_7 SECRET_8 SECRET_9 SECRET_10 SECRET_11 SECRET_12 SECRET_13 SECRET_14 \
  SECRET_15 SECRET_16; do
    eval "_new_val=\${TELEPROXY_${_old_var}:-}"
    eval "_old_val=\${MTPROXY_${_old_var}:-}"
    if [ -z "$_new_val" ] && [ -n "$_old_val" ]; then
        echo "WARNING: MTPROXY_${_old_var} is deprecated, use TELEPROXY_${_old_var} instead" >&2
        eval "export TELEPROXY_${_old_var}=\"\$_old_val\""
    fi
done

# Direct mode: connect to Telegram DCs without ME relay.
# Must be explicitly enabled. Incompatible with PROXY_TAG.
DIRECT_MODE=${DIRECT_MODE:-false}

# proxy-secret is baked into the image at build time (only needed for ME relay mode)
if [ "$DIRECT_MODE" != "true" ] && [ ! -f proxy-secret ]; then
    echo "ERROR: proxy-secret not found. The Docker image may be corrupted." >&2
    exit 1
fi

# Download/refresh proxy config to data/ (only in ME relay mode)
if [ "$DIRECT_MODE" != "true" ]; then
    CONFIG_PATH="data/proxy-multi.conf"
    NEEDS_DOWNLOAD=0

    if [ ! -f "$CONFIG_PATH" ]; then
        NEEDS_DOWNLOAD=1
    elif [ $(find "$CONFIG_PATH" -mtime +1 2>/dev/null | wc -l) -gt 0 ]; then
        NEEDS_DOWNLOAD=1
    fi

    PROXY_CONFIG_URL=${PROXY_CONFIG_URL:-https://core.telegram.org/getProxyConfig}
    if [ "$NEEDS_DOWNLOAD" -eq 1 ]; then
        echo "Downloading proxy config from $PROXY_CONFIG_URL..."
        if curl --connect-timeout 10 --max-time 30 --retry 3 --retry-delay 2 -fsSL "$PROXY_CONFIG_URL" -o "$CONFIG_PATH.tmp"; then
            mv "$CONFIG_PATH.tmp" "$CONFIG_PATH"
            echo "Proxy config downloaded successfully."
        else
            rm -f "$CONFIG_PATH.tmp"
            if [ -f "$CONFIG_PATH" ]; then
                echo "WARNING: Failed to refresh proxy config, using cached copy." >&2
            else
                echo "ERROR: Failed to download proxy config and no cached copy exists." >&2
                echo "Ensure core.telegram.org is reachable, or provide proxy-multi.conf in the data/ volume." >&2
                exit 1
            fi
        fi
    fi
fi

# Collect secrets from comma-separated SECRET and/or numbered SECRET_N vars.
# Uses positional parameters as a portable array (POSIX sh).
set --

if [ -n "$SECRET" ]; then
    _save_ifs="$IFS"
    IFS=','
    for _s in $SECRET; do
        IFS="$_save_ifs"
        _s=$(printf '%s' "$_s" | tr -d '[:space:]')
        [ -n "$_s" ] && set -- "$@" "$_s"
    done
    IFS="$_save_ifs"
fi

_i=1
while [ "$_i" -le 16 ]; do
    eval "_val=\${SECRET_${_i}:-}"
    _val=$(printf '%s' "$_val" | tr -d '[:space:]')
    if [ -n "$_val" ]; then
        eval "_lbl=\${SECRET_LABEL_${_i}:-}"
        _lbl=$(printf '%s' "$_lbl" | tr -d '[:space:]')
        eval "_lim=\${SECRET_LIMIT_${_i}:-}"
        _lim=$(printf '%s' "$_lim" | tr -d '[:space:]')
        _suffix=""
        if [ -n "$_lbl" ] || [ -n "$_lim" ]; then
            _suffix=":${_lbl}"
        fi
        if [ -n "$_lim" ]; then
            _suffix="${_suffix}:${_lim}"
        fi
        set -- "$@" "${_val}${_suffix}"
    fi
    _i=$((_i + 1))
done

if [ "$#" -eq 0 ]; then
    echo "No SECRET provided, generating one..."
    _gen=$(./teleproxy generate-secret 2>/dev/null)
    set -- "$_gen"
    echo "Generated secret: $_gen"
fi

if [ "$#" -gt 16 ]; then
    echo "ERROR: Maximum 16 secrets supported, got $#" >&2
    exit 1
fi

echo "Configured $# secret(s)"

# Set default values
PORT=${PORT:-443}
STATS_PORT=${STATS_PORT:-8888}
WORKERS=${WORKERS:-1}
PROXY_TAG=${PROXY_TAG:-}
RANDOM_PADDING=${RANDOM_PADDING:-}
# Domain or host:port for TLS-transport mode (e.g. google.com or 127.0.0.1:8443)
EE_DOMAIN=${EE_DOMAIN:-}
# Max connections - lower value avoids rlimit issues in containers
MAX_CONNECTIONS=${MAX_CONNECTIONS:-60000}

# Detect container-local IPv4 for NAT.
LOCAL_IP=$(ip -4 route get 8.8.8.8 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p')
if [ -z "$LOCAL_IP" ]; then
    LOCAL_IP=$(grep -vE '(local|ip6|^fd|^$)' /etc/hosts 2>/dev/null | awk 'NR==1 {print $1}')
fi

# Public IPv4 address to advertise to Telegram DCs.
# Auto-detected if not provided — required for Docker NAT to work.
EXTERNAL_IP=${EXTERNAL_IP:-}
if [ -z "$EXTERNAL_IP" ]; then
    EXTERNAL_IP=$(curl -s -4 --connect-timeout 5 --max-time 10 https://icanhazip.com 2>/dev/null || curl -s -4 --connect-timeout 5 --max-time 10 https://ifconfig.me 2>/dev/null || true)
    if [ -n "$EXTERNAL_IP" ]; then
        echo "Auto-detected external IP: $EXTERNAL_IP"
    fi
fi

NAT_INFO_ARGS=""
if [ -n "$EXTERNAL_IP" ] && [ -n "$LOCAL_IP" ]; then
    NAT_INFO_ARGS="--nat-info $LOCAL_IP:$EXTERNAL_IP"
elif [ -z "$EXTERNAL_IP" ]; then
    echo "WARNING: Could not detect external IP. Set EXTERNAL_IP env var for Docker NAT support." >&2
fi

# Generate TOML config file from environment variables.
# This enables SIGHUP-based secret reload: edit data/config.toml then
#   docker exec <container> kill -HUP 1
TOML_CONFIG="data/config.toml"
{
    echo "# Auto-generated by start.sh — edit and SIGHUP to reload secrets"
    echo "port = $PORT"
    echo "stats_port = $STATS_PORT"
    echo "http_stats = true"
    echo "workers = $WORKERS"
    echo "maxconn = $MAX_CONNECTIONS"
    echo "user = \"teleproxy\""

    if [ "$DIRECT_MODE" = "true" ]; then
        echo "direct = true"
    fi

    if [ -n "$PROXY_TAG" ]; then
        echo "proxy_tag = \"$PROXY_TAG\""
    fi

    if [ "$RANDOM_PADDING" = "true" ]; then
        echo "random_padding_only = true"
    fi

    if [ -n "$EE_DOMAIN" ]; then
        echo "domain = \"$EE_DOMAIN\""
    fi

    if [ -n "$BIND_ADDRESS" ]; then
        echo "bind = \"$BIND_ADDRESS\""
    fi

    if [ "$PREFER_IPV6" = "true" ]; then
        echo "ipv6 = true"
    fi

    if [ -n "$IP_BLOCKLIST" ]; then
        echo "ip_blocklist = \"$IP_BLOCKLIST\""
    fi

    if [ -n "$IP_ALLOWLIST" ]; then
        echo "ip_allowlist = \"$IP_ALLOWLIST\""
    fi

    if [ -n "$STATS_ALLOW_NET" ]; then
        _save_ifs="$IFS"
        IFS=','
        printf 'stats_allow_net = ['
        _first=1
        for _net in $STATS_ALLOW_NET; do
            IFS="$_save_ifs"
            _net=$(printf '%s' "$_net" | tr -d '[:space:]')
            if [ -n "$_net" ]; then
                [ "$_first" = "1" ] || printf ', '
                printf '"%s"' "$_net"
                _first=0
            fi
        done
        IFS="$_save_ifs"
        echo ']'
    fi

    if [ -n "$DC_OVERRIDE" ]; then
        _save_ifs="$IFS"
        IFS=','
        for _dc_entry in $DC_OVERRIDE; do
            IFS="$_save_ifs"
            _dc_entry=$(printf '%s' "$_dc_entry" | tr -d '[:space:]')
            if [ -n "$_dc_entry" ]; then
                _dc_id=$(printf '%s' "$_dc_entry" | cut -d: -f1)
                _dc_host=$(printf '%s' "$_dc_entry" | cut -d: -f2)
                _dc_port=$(printf '%s' "$_dc_entry" | cut -d: -f3)
                echo ""
                echo "[[dc_override]]"
                echo "dc = $_dc_id"
                echo "host = \"$_dc_host\""
                echo "port = $_dc_port"
            fi
        done
        IFS="$_save_ifs"
    fi

    echo ""
    for _s in "$@"; do
        _secret_hex=$(printf '%s' "$_s" | cut -d: -f1)
        _label=$(printf '%s' "$_s" | cut -d: -f2 -s)
        _limit=$(printf '%s' "$_s" | cut -d: -f3 -s)
        echo "[[secret]]"
        echo "key = \"$_secret_hex\""
        [ -n "$_label" ] && echo "label = \"$_label\""
        [ -n "$_limit" ] && echo "limit = $_limit"
        echo ""
    done
} > "$TOML_CONFIG"

echo "Generated $TOML_CONFIG with $# secret(s)"

# Build command using TOML config (engine-level options are now in TOML too)
CMD="./teleproxy --config $TOML_CONFIG --allow-skip-dh $NAT_INFO_ARGS"

if [ "$DIRECT_MODE" != "true" ]; then
    CMD="$CMD --aes-pwd proxy-secret data/proxy-multi.conf"
fi

CMD="$CMD $ORIG_ARGS"

if [ "$DIRECT_MODE" = "true" ]; then
    echo "Direct mode: connecting directly to Telegram DCs (no ME relay)"
fi

echo "Starting Teleproxy with command: $CMD"

# Print ready-to-share connection links
echo ""
echo "===== Connection Links ====="
_host="${EXTERNAL_IP:-<YOUR_SERVER_IP>}"
for _s in "$@"; do
    # Strip :LABEL:LIMIT suffix for URLs (labels/limits are for the proxy, not for clients)
    _secret_hex=$(printf '%s' "$_s" | cut -d: -f1)
    _label=$(printf '%s' "$_s" | cut -d: -f2 -s)
    if [ -n "$EE_DOMAIN" ]; then
        _domain_only=$(printf '%s' "$EE_DOMAIN" | cut -d: -f1)
        _domain_hex=$(printf '%s' "$_domain_only" | od -An -tx1 | tr -d ' \n')
        _full="ee${_secret_hex}${_domain_hex}"
    elif [ "$RANDOM_PADDING" = "true" ]; then
        _full="dd${_secret_hex}"
    else
        _full="$_secret_hex"
    fi
    _label_arg=""
    [ -n "$_label" ] && _label_arg="--label $_label"
    ./teleproxy link --server "$_host" --port "$PORT" --secret "$_full" $_label_arg
done
if [ "$_host" = "<YOUR_SERVER_IP>" ]; then
    echo "(Set EXTERNAL_IP to show your server's IP)"
fi
echo "============================="
echo ""

# Start cron daemon for config refresh (only in ME relay mode)
if [ "$DIRECT_MODE" != "true" ]; then
    crond
fi

exec $CMD
