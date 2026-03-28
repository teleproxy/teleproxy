#!/usr/bin/env python3
"""E2E tests for Teleproxy multi-secret support.

Verifies that the proxy accepts fake-TLS handshakes using each of
multiple configured secrets, and still rejects unknown secrets.
"""
import os
import sys

from test_tls_e2e import (
    _do_handshake,
    _verify_server_hmac,
    wait_for_proxy,
)


def test_multi_secret_handshake():
    """Verify fake-TLS handshake succeeds with each configured secret."""
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    port = int(os.environ.get("TELEPROXY_PORT", "8443"))
    secrets_csv = os.environ.get("TELEPROXY_SECRETS", "")

    assert secrets_csv, "TELEPROXY_SECRETS environment variable not set"
    secrets = [s.strip() for s in secrets_csv.split(",") if s.strip()]
    assert len(secrets) >= 2, f"Expected at least 2 secrets, got {len(secrets)}"

    for i, secret_hex in enumerate(secrets):
        secret_bytes = bytes.fromhex(secret_hex)
        data, client_random = _do_handshake(host, port, secret_bytes)

        assert len(data) >= 138, (
            f"Secret #{i+1} ({secret_hex[:8]}...): Response too short "
            f"({len(data)} bytes)"
        )
        assert _verify_server_hmac(data, client_random, secret_bytes), (
            f"Secret #{i+1} ({secret_hex[:8]}...): HMAC mismatch"
        )
        print(f"  Secret #{i+1} ({secret_hex[:8]}...): handshake OK")


def test_wrong_secret_still_rejected():
    """Verify that an unknown secret is rejected with multiple secrets configured."""
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    port = int(os.environ.get("TELEPROXY_PORT", "8443"))
    secrets_csv = os.environ.get("TELEPROXY_SECRETS", "")

    assert secrets_csv, "TELEPROXY_SECRETS environment variable not set"
    first_secret = secrets_csv.split(",")[0].strip()

    # Flip all bits to get an unknown secret
    wrong_secret = bytes(b ^ 0xFF for b in bytes.fromhex(first_secret))

    data, client_random = _do_handshake(host, port, wrong_secret)
    assert len(data) >= 10, "No response for wrong secret"
    assert not _verify_server_hmac(data, client_random, wrong_secret), (
        "HMAC matched with wrong secret — should have been rejected"
    )
    print("  Wrong secret correctly rejected with multi-secret config")


def main():
    tests = [
        ("test_multi_secret_handshake", test_multi_secret_handshake),
        ("test_wrong_secret_still_rejected", test_wrong_secret_still_rejected),
    ]

    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    port = int(os.environ.get("TELEPROXY_PORT", "8443"))

    print("Starting multi-secret TLS tests...\n", flush=True)
    print(f"Waiting for proxy at {host}:{port}...", flush=True)
    if not wait_for_proxy(host, port, timeout=90):
        print("ERROR: Proxy not ready after 90s")
        sys.exit(1)
    print("Proxy is ready.\n", flush=True)

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
