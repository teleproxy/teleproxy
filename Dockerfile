# Alpine-based multi-stage build (supports amd64 and arm64)
FROM alpine:3.21 AS builder

# Install build dependencies
# linux-headers: provides <linux/futex.h> used by mp-queue.c and jobs.c
# DEBUG_TOOLS=1: adds libunwind for stack traces in crash dumps (test/CI only)
ARG DEBUG_TOOLS=0
RUN apk add --no-cache build-base openssl-dev zlib-dev linux-headers git \
    $([ "$DEBUG_TOOLS" = "1" ] && echo "libunwind-dev")

# Set working directory
WORKDIR /src

# Copy source code
COPY . .

# Build the application
ARG VERSION=unknown
RUN make clean && make -j$(nproc) EXTRA_VERSION="${VERSION}"

# Runtime image
FROM alpine:3.21

# Install runtime dependencies
# curl: config downloads + health check
# openssl: runtime libs (libssl3/libcrypto3) + CLI for secret generation
# zlib: required by teleproxy (-lz)
# iproute2: ip command for local IP detection in NAT setup
# ca-certificates: TLS certificate verification
ARG DEBUG_TOOLS=0
RUN apk add --no-cache curl ca-certificates openssl zlib iproute2 \
    $([ "$DEBUG_TOOLS" = "1" ] && echo "libunwind")

# Create user for running the proxy
RUN adduser -D -H -s /sbin/nologin teleproxy

# Create directory for the application
WORKDIR /opt/teleproxy

# Copy binary from builder stage
COPY --from=builder /src/objs/bin/teleproxy /opt/teleproxy/

# Make binary executable
RUN chmod +x /opt/teleproxy/teleproxy \
    && ln -s teleproxy /opt/teleproxy/mtproto-proxy

# proxy-secret is a static public 128-byte blob used for MTProto key exchange.
# Baking it at build time eliminates the most critical runtime network dependency.
RUN curl --connect-timeout 10 --max-time 30 --retry 3 --retry-delay 2 \
    -fsSL https://core.telegram.org/getProxySecret -o /opt/teleproxy/proxy-secret

# Create data directory for persistent config (proxy-multi.conf)
RUN mkdir -p /opt/teleproxy/data

# Install cron job to refresh proxy-multi.conf from Telegram servers every 6 hours.
# Prevents proxy from becoming unavailable due to stale DC configuration.
# Output is redirected to PID 1's stdout so it appears in `docker logs`.
# busybox crond reads /etc/crontabs/<user> (no user field in entry, unlike Ubuntu cron.d)
COPY teleproxy-config-refresh.sh /opt/teleproxy/config-refresh.sh
RUN chmod +x /opt/teleproxy/config-refresh.sh \
    && echo '0 */6 * * * /opt/teleproxy/config-refresh.sh >> /proc/1/fd/1 2>> /proc/1/fd/2' >> /etc/crontabs/root

# Expose ports
EXPOSE 443 8888

# Add startup script (POSIX sh — no bash dependency)
COPY start.sh /opt/teleproxy/start.sh
RUN chmod +x /opt/teleproxy/start.sh

HEALTHCHECK --interval=30s --timeout=10s --retries=3 --start-period=60s \
    CMD curl -f http://localhost:8888/stats || exit 1

# Set entrypoint
ENTRYPOINT ["/opt/teleproxy/start.sh"]
