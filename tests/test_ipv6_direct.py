#!/usr/bin/env python3
"""E2E test: IPv6 auto-detection in direct mode.

Verifies that a direct-mode proxy with auto-detected IPv6 does not crash
when receiving IPv6 connections.  The bug (issue #17) was a mismatch
between socket creation (IPv6 dual-stack) and listener registration
(missing C_IPV6 flag), causing an assertion failure on the first
IPv6 connection.

This test must run in a Docker network with IPv6 enabled.

Environment variables:
    TELEPROXY_HOST       Proxy hostname (default: teleproxy)
    TELEPROXY_PORT       Proxy port (default: 8443)
    TELEPROXY_STATS_PORT Stats port (default: 8888)
"""

import os
import socket
import sys
import time
import urllib.request


def check_proxy_alive(host, stats_port):
    """Return True if the proxy stats endpoint responds."""
    url = f"http://{host}:{stats_port}/stats"
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            return resp.status == 200
    except Exception:
        return False


def resolve_ipv6(host):
    """Resolve host to an IPv6 address, or return None."""
    try:
        results = socket.getaddrinfo(host, None, socket.AF_INET6,
                                     socket.SOCK_STREAM)
        if results:
            return results[0][4][0]
    except (socket.gaierror, OSError):
        pass
    return None


def test_ipv6_connect(host, port):
    """Connect to the proxy via IPv6 and verify it doesn't crash.

    Returns True if the connection was accepted (proxy didn't crash).
    """
    ipv6_addr = resolve_ipv6(host)
    if not ipv6_addr:
        print(f"  SKIP: could not resolve {host} to IPv6 address")
        return True  # Not a failure, just no IPv6 available

    print(f"  Connecting to [{ipv6_addr}]:{port} via IPv6...")

    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        s.connect((ipv6_addr, port))
        # Send a few bytes (doesn't need to be valid MTProxy data).
        # The proxy will reject the data as an invalid handshake, but
        # the critical test is that accept() doesn't crash the proxy.
        s.sendall(b"\x00" * 64)
        time.sleep(0.5)
        print("  IPv6 connection accepted (proxy did not crash)")
        return True
    except ConnectionRefusedError:
        print("  FAIL: connection refused on IPv6")
        return False
    except Exception as e:
        # Connection reset or timeout is fine — proxy processed the
        # connection without crashing.
        print(f"  IPv6 connection handled: {type(e).__name__}: {e}")
        return True
    finally:
        s.close()


def main():
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    port = int(os.environ.get("TELEPROXY_PORT", "8443"))
    stats_port = os.environ.get("TELEPROXY_STATS_PORT", "8888")

    print("=== IPv6 Auto-Detection Tests ===\n")

    # Step 1: Verify proxy is running (IPv4)
    if not check_proxy_alive(host, stats_port):
        print(f"ERROR: proxy stats not reachable at {host}:{stats_port}")
        sys.exit(1)
    print(f"Proxy alive at {host}:{stats_port}")

    # Step 2: Connect via IPv6
    print("\nTesting IPv6 connection...")
    ipv6_ok = test_ipv6_connect(host, port)

    # Step 3: Verify proxy survived the IPv6 connection
    print("\nChecking proxy health after IPv6 connection...")
    time.sleep(1)
    if not check_proxy_alive(host, stats_port):
        print("FAIL: proxy crashed after IPv6 connection (issue #17)")
        sys.exit(1)
    print("Proxy still healthy")

    print(f"\n=== Result: {'PASS' if ipv6_ok else 'FAIL'} ===")
    sys.exit(0 if ipv6_ok else 1)


if __name__ == "__main__":
    main()
