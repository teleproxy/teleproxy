#!/usr/bin/env python3
"""E2E tests for wildcard SNI matching in fake-TLS mode.

Covers issue #44: an operator configured with `-D *.example.com:backend` must
have the proxy emulate a TLS handshake for any single-label subdomain of
example.com, while still falling back to the real backend for unrelated SNIs.

The proxy is configured with EE_DOMAIN=*.example.com and EE_BACKEND points to
an nginx instance serving a real `*.example.com` cert.  Each test sends one
ClientHello with a chosen SNI and checks whether the proxy generated the
ServerHello (HMAC matches) or transparently forwarded to the backend.
"""
import os
import socket
import ssl
import sys
import time

from test_tls_e2e import (
    _do_handshake,
    _verify_server_hmac,
    wait_for_proxy,
)


def _expect_proxy_handled(domain):
    """Send a ClientHello and assert the proxy generated the ServerHello.

    Args:
        domain: SNI hostname to embed in the ClientHello.

    Raises:
        AssertionError: If the proxy did not produce the response (HMAC mismatch)
            or no response was received.
    """
    host = os.environ["TELEPROXY_HOST"]
    port = int(os.environ["TELEPROXY_PORT"])
    secret_bytes = bytes.fromhex(os.environ["TELEPROXY_SECRET"])

    data, client_random = _do_handshake(host, port, secret_bytes, domain=domain)
    assert len(data) >= 138, (
        f"SNI={domain!r}: response too short ({len(data)} bytes) — proxy rejected the ClientHello"
    )
    assert _verify_server_hmac(data, client_random, secret_bytes), (
        f"SNI={domain!r}: server_random HMAC mismatch — proxy did not emulate the response, "
        f"wildcard match failed"
    )


def _expect_forwarded_to_backend(domain):
    """Send a ClientHello and assert the proxy forwarded to the real backend.

    Args:
        domain: SNI hostname that should NOT match the configured wildcard.

    Raises:
        AssertionError: If the proxy generated the ServerHello (HMAC matched)
            when it should have forwarded to the backend.
    """
    host = os.environ["TELEPROXY_HOST"]
    port = int(os.environ["TELEPROXY_PORT"])
    secret_bytes = bytes.fromhex(os.environ["TELEPROXY_SECRET"])

    data, client_random = _do_handshake(host, port, secret_bytes, domain=domain)
    assert len(data) >= 10, (
        f"SNI={domain!r}: no response from backend ({len(data)} bytes)"
    )
    assert not _verify_server_hmac(data, client_random, secret_bytes), (
        f"SNI={domain!r}: HMAC matched — proxy emulated this SNI when it should "
        f"have forwarded to the backend"
    )


def test_wildcard_sni_matches_single_label():
    """SNI `proxy.example.com` matches `*.example.com`."""
    _expect_proxy_handled("proxy.example.com")
    print("  proxy.example.com matched the wildcard")


def test_wildcard_sni_matches_other_subdomain():
    """A different single-label subdomain also matches.

    Proves the match isn't specific to the backend hostname used at probe time.
    """
    _expect_proxy_handled("node-7.example.com")
    print("  node-7.example.com matched the wildcard")


def test_apex_does_not_match():
    """RFC 6125: `*.example.com` does NOT match the apex `example.com`."""
    _expect_forwarded_to_backend("example.com")
    print("  example.com correctly forwarded to backend (no label)")


def test_multilabel_does_not_match():
    """RFC 6125: `*` matches exactly one label, not multiple."""
    _expect_forwarded_to_backend("a.b.example.com")
    print("  a.b.example.com correctly forwarded to backend (multi-label)")


def test_literal_wildcard_sni_does_not_match():
    """A client sending the literal `*.example.com` as SNI must not match.

    Real clients never do this, but a probing censor might — and the proxy
    must not treat `*` as a special byte in the SNI itself.
    """
    _expect_forwarded_to_backend("*.example.com")
    print("  literal *.example.com SNI correctly forwarded to backend")


def test_unrelated_suffix_does_not_match():
    """A different domain suffix never matches."""
    _expect_forwarded_to_backend("evil.example.org")
    print("  evil.example.org correctly forwarded to backend")


def test_browser_tls_against_wildcard_backend_works():
    """A standard TLS client against the proxy completes a real handshake.

    This is the operator-side regression test for the original mtg#394 failure
    mode: with a wildcard cert on the backend, a normal HTTPS probe to the
    proxy must terminate against the real backend cert, not against the
    default vhost serving an unrelated cert.
    """
    host = os.environ["TELEPROXY_HOST"]
    port = int(os.environ["TELEPROXY_PORT"])

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect((socket.gethostbyname(host), port))
    ssock = ctx.wrap_socket(sock, server_hostname="probe.example.com")

    cert = ssock.getpeercert(binary_form=True)
    version = ssock.version()
    ssock.close()

    assert cert is not None, "No certificate received from backend"
    assert version, "No TLS version negotiated"
    print(f"  Browser TLS handshake succeeded: {version}, cert={len(cert)} bytes")


def main():
    """Run the wildcard SNI matching suite.

    Returns:
        Exit code 0 on full success, 1 if any required test failed.
    """
    tests = [
        ("test_wildcard_sni_matches_single_label", test_wildcard_sni_matches_single_label),
        ("test_wildcard_sni_matches_other_subdomain", test_wildcard_sni_matches_other_subdomain),
        ("test_apex_does_not_match", test_apex_does_not_match),
        ("test_multilabel_does_not_match", test_multilabel_does_not_match),
        ("test_literal_wildcard_sni_does_not_match", test_literal_wildcard_sni_does_not_match),
        ("test_unrelated_suffix_does_not_match", test_unrelated_suffix_does_not_match),
        ("test_browser_tls_against_wildcard_backend_works", test_browser_tls_against_wildcard_backend_works),
    ]

    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    proxy_port = os.environ.get("TELEPROXY_PORT", "8443")
    print(f"Waiting for proxy at {host}:{proxy_port}...", flush=True)
    if not wait_for_proxy(host, proxy_port, timeout=90):
        print("ERROR: Proxy not ready, aborting tests")
        sys.exit(1)
    # Give the fingerprint probe time to settle so the first real request
    # sees the captured ServerHello parameters, not the random fallback.
    time.sleep(2)
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
        except AssertionError as e:
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
