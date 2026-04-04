#!/bin/bash
# Teleproxy cloud-init script — paste into "User Data" when creating a VPS.
# Works on Ubuntu 22.04/24.04 and Debian 12.
#
# For a pre-configured version with a unique secret and QR code,
# use the deploy page: https://teleproxy.github.io/deploy/
#
# Customise by exporting variables before the curl line:
#
#   SECRET          32-hex-char secret (auto-generated if empty)
#   EE_DOMAIN       Domain for fake-TLS camouflage (e.g. www.booking.com)
#   PORT            Client port (default: 443)
#   STATS_PORT      Stats port (default: 8888)
#   SECRET_COUNT    Auto-generate this many secrets (1-16)
#
# Example:
#   export EE_DOMAIN=www.booking.com
#   export SECRET_COUNT=3

apt-get update -y && apt-get install -y curl
curl -sSL https://raw.githubusercontent.com/teleproxy/teleproxy/main/install.sh | sh
