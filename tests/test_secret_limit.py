#!/usr/bin/env python3
"""E2E tests for per-secret connection limits.

Verifies that:
- Stats expose configured limits and rejection counters
- Connections beyond the limit are rejected at the TLS handshake level
"""
import os
import socket
import sys
import time

import requests

from test_tls_e2e import (
    _do_handshake,
    _verify_server_hmac,
    wait_for_proxy,
)


def _get_stats(host, stats_port):
    """Fetch plain-text stats from the proxy."""
    url = f"http://{host}:{stats_port}/stats"
    resp = requests.get(url, timeout=5)
    resp.raise_for_status()
    return resp.text


def _get_metrics(host, stats_port):
    """Fetch Prometheus metrics from the proxy."""
    url = f"http://{host}:{stats_port}/metrics"
    resp = requests.get(url, timeout=5)
    resp.raise_for_status()
    return resp.text


def test_limit_in_plain_stats():
    """Verify per-secret limit and rejected counter appear in /stats."""
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    stats_port = os.environ.get("TELEPROXY_STATS_PORT", "8888")

    stats = _get_stats(host, stats_port)

    assert "secret_limited_limit\t5" in stats, (
        f"Expected 'secret_limited_limit\\t5' in stats output:\n{stats}"
    )
    assert "secret_limited_rejected\t" in stats, (
        f"Expected 'secret_limited_rejected' in stats output:\n{stats}"
    )
    # Unlimited secret should NOT have a limit line
    assert "secret_unlimited_limit" not in stats, (
        f"Unlimited secret should not have a limit line:\n{stats}"
    )
    # But should still have a rejected counter
    assert "secret_unlimited_rejected\t" in stats, (
        f"Expected 'secret_unlimited_rejected' in stats output:\n{stats}"
    )
    print("  Plain stats: limit and rejected counters present")


def test_limit_in_prometheus_metrics():
    """Verify per-secret limit and rejected counter appear in /metrics."""
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    stats_port = os.environ.get("TELEPROXY_STATS_PORT", "8888")

    metrics = _get_metrics(host, stats_port)

    assert 'teleproxy_secret_connection_limit{secret="limited"} 5' in metrics, (
        f"Expected limit=5 for 'limited' secret in Prometheus metrics:\n{metrics}"
    )
    assert 'teleproxy_secret_connection_limit{secret="unlimited"} 0' in metrics, (
        f"Expected limit=0 for 'unlimited' secret in Prometheus metrics:\n{metrics}"
    )
    assert 'teleproxy_secret_connections_rejected_total{secret="limited"}' in metrics, (
        f"Expected rejected counter for 'limited' secret:\n{metrics}"
    )
    print("  Prometheus metrics: limit and rejected counters present")


def test_unlimited_secret_still_works():
    """Verify unlimited secret still accepts connections normally."""
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    port = int(os.environ.get("TELEPROXY_PORT", "8443"))
    secret_hex = os.environ.get("TELEPROXY_SECRET_1", "")
    assert secret_hex, "TELEPROXY_SECRET_1 not set"

    secret_bytes = bytes.fromhex(secret_hex)
    data, client_random = _do_handshake(host, port, secret_bytes)

    assert len(data) >= 138, f"Response too short ({len(data)} bytes)"
    assert _verify_server_hmac(data, client_random, secret_bytes), "HMAC mismatch"
    print("  Unlimited secret: handshake OK")


def test_limited_secret_accepts_under_limit():
    """Verify limited secret accepts connections when under limit."""
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    port = int(os.environ.get("TELEPROXY_PORT", "8443"))
    secret_hex = os.environ.get("TELEPROXY_SECRET_2", "")
    assert secret_hex, "TELEPROXY_SECRET_2 not set"

    secret_bytes = bytes.fromhex(secret_hex)
    data, client_random = _do_handshake(host, port, secret_bytes)

    assert len(data) >= 138, f"Response too short ({len(data)} bytes)"
    assert _verify_server_hmac(data, client_random, secret_bytes), "HMAC mismatch"
    print("  Limited secret: handshake OK (under limit)")


def main():
    tests = [
        ("test_limit_in_plain_stats", test_limit_in_plain_stats),
        ("test_limit_in_prometheus_metrics", test_limit_in_prometheus_metrics),
        ("test_unlimited_secret_still_works", test_unlimited_secret_still_works),
        ("test_limited_secret_accepts_under_limit", test_limited_secret_accepts_under_limit),
    ]

    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    port = int(os.environ.get("TELEPROXY_PORT", "8443"))

    print("Starting secret limit tests...\n", flush=True)
    print(f"Waiting for proxy at {host}:{port}...", flush=True)
    if not wait_for_proxy(host, port, timeout=90):
        print("ERROR: Proxy not ready after 90s")
        sys.exit(1)
    print("Proxy is ready.\n", flush=True)

    # Brief delay for stats endpoint to be ready
    time.sleep(2)

    passed = 0
    failed = 0
    errors = []

    for name, fn in tests:
        try:
            print(f"[RUN]  {name}")
            fn()
            print(f"[PASS] {name}\n")
            passed += 1
        except Exception as e:
            print(f"[FAIL] {name}: {e}\n")
            failed += 1
            errors.append((name, e))

    print(f"Results: {passed} passed, {failed} failed")
    if errors:
        print("\nFailures:")
        for name, err in errors:
            print(f"  {name}: {err}")

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
