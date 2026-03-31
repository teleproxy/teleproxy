#!/usr/bin/env python3
"""E2E test: CDN DC routing in direct mode.

Verifies that CDN DC IDs (200 + base_dc_id) are accepted by the proxy
instead of being rejected as "unknown DC".  Uses raw obfuscated2
connections — no Telegram auth needed.

Sends a crafted obfuscated2 init header targeting each CDN DC and checks
that the proxy does not immediately close the connection.  The proxy will
attempt to connect to the origin DC (e.g., DC 203 → DC 3), which may or
may not succeed depending on network access, but the proxy must not
reject the connection itself.

Environment variables:
    TELEPROXY_HOST      Proxy hostname (default: teleproxy)
    TELEPROXY_PORT      Proxy port (default: 8443)
    TELEPROXY_STATS_PORT Stats port (default: 8888)
    TELEPROXY_SECRET    32-char hex proxy secret (required)
"""

import os
import socket
import struct
import sys
import time
import urllib.request


def build_obfs2_init(secret_hex, target_dc):
    """Build a valid obfuscated2 64-byte init header for the given DC.

    Uses Telethon's MTProxyIO to generate a correctly encrypted header.
    """
    from telethon.network.connection.tcpmtproxy import MTProxyIO
    from telethon.network.connection.tcpintermediate import (
        RandomizedIntermediatePacketCodec,
    )

    secret = bytes.fromhex("dd" + secret_hex)
    header, _enc, _dec = MTProxyIO.init_header(
        secret, target_dc, RandomizedIntermediatePacketCodec
    )
    return header


def check_proxy_alive(host, stats_port):
    """Return True if the proxy stats endpoint responds."""
    url = f"http://{host}:{stats_port}/stats"
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            return resp.status == 200
    except Exception:
        return False


def test_dc_accepted(host, port, secret, target_dc, label=""):
    """Connect targeting a specific DC and verify the proxy accepts it.

    Returns True if the proxy kept the socket open (accepted the DC),
    False if the proxy immediately closed the connection.
    """
    tag = label or f"DC {target_dc}"
    header = build_obfs2_init(secret, target_dc)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    try:
        s.connect((host, port))
        s.sendall(header)

        # Give the proxy time to process the header and either:
        # - accept it (tries to connect to DC) → socket stays open
        # - reject it ("unknown DC") → socket closed immediately
        time.sleep(1.5)

        # Check if the socket is still open
        s.setblocking(False)
        try:
            data = s.recv(1)
            if len(data) == 0:
                print(f"  {tag}: FAIL — connection closed by proxy")
                return False
            # Got data back — proxy is responding (unexpected but OK)
            print(f"  {tag}: OK — connection accepted (got response)")
            return True
        except BlockingIOError:
            # No data but socket still open — proxy accepted the DC
            print(f"  {tag}: OK — connection accepted")
            return True
        except ConnectionResetError:
            print(f"  {tag}: FAIL — connection reset by proxy")
            return False
        except OSError as e:
            if e.errno == 54:  # Connection reset by peer (macOS)
                print(f"  {tag}: FAIL — connection reset by proxy")
                return False
            raise
    except Exception as e:
        print(f"  {tag}: FAIL — {type(e).__name__}: {e}")
        return False
    finally:
        s.close()


def main():
    secret = os.environ.get("TELEPROXY_SECRET", "")
    if not secret:
        print("ERROR: TELEPROXY_SECRET required")
        sys.exit(1)

    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    port = int(os.environ.get("TELEPROXY_PORT", "8443"))
    stats_port = os.environ.get("TELEPROXY_STATS_PORT", "8888")

    print("=== CDN DC Routing Tests ===\n")

    # Verify proxy is running
    if not check_proxy_alive(host, stats_port):
        print(f"ERROR: proxy stats not reachable at {host}:{stats_port}")
        sys.exit(1)
    print(f"Proxy alive at {host}:{stats_port}\n")

    all_ok = True

    # Control: regular DC 2 should always work
    if not test_dc_accepted(host, port, secret, 2, "DC 2 (control)"):
        print("\nFAIL: even regular DC 2 was rejected — proxy misconfigured?")
        sys.exit(1)

    # CDN DCs: 201-205
    for dc in (201, 203, 205):
        if not test_dc_accepted(host, port, secret, dc, f"CDN DC {dc}"):
            all_ok = False

    # Media CDN: -203 (negative = media flag)
    if not test_dc_accepted(host, port, secret, -203, "media CDN DC -203"):
        all_ok = False

    # Verify proxy is still alive after all connections
    print()
    if not check_proxy_alive(host, stats_port):
        print("FAIL: proxy crashed during CDN DC tests")
        sys.exit(1)
    print("Proxy still healthy after all tests")

    print(f"\n=== Result: {'PASS' if all_ok else 'FAIL'} ===")
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
