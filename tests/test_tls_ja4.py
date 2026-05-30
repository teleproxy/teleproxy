#!/usr/bin/env python3
"""E2E tests for the JA4 ClientHello fingerprint counter (issue #102).

Runs after test_tls_e2e.py has already driven a fake-TLS ClientHello
through the proxy, so the proxy's worker-local ja4_table must contain
at least one entry. Verifies that:

  1. /stats lists `ja4_seen<TAB><hash><TAB><count>` lines.
  2. The reported hash exactly matches the foxio JA4 spec computed
     in Python against the ClientHello bytes our build emits.
  3. /metrics exposes the matching `teleproxy_ja4_seen{hash="..."}` sample.
"""
import hashlib
import os
import socket
import struct
import sys
import time
import urllib.request

from test_tls_e2e import build_client_hello


def compute_ja4(ch: bytes) -> str:
    """Compute the JA4 fingerprint for a TLS 1.3 ClientHello buffer.

    Args:
        ch: Raw ClientHello bytes starting at the TLS record header.

    Returns:
        The 36-char JA4 string ("t13d1615h2_xxxxxxxxxxxx_xxxxxxxxxxxx").
    """
    def is_grease(v: int) -> bool:
        return (v & 0x0F0F) == 0x0A0A and (v >> 8) == (v & 0xFF)

    pos = 43 + 1 + ch[43]
    cs_len = struct.unpack(">H", ch[pos:pos + 2])[0]
    pos += 2
    ciphers, end = [], pos + cs_len
    while pos + 2 <= end:
        v = struct.unpack(">H", ch[pos:pos + 2])[0]
        pos += 2
        if not is_grease(v):
            ciphers.append(f"{v:04x}")

    pos += 1 + ch[pos]  # compression_methods
    ext_total = struct.unpack(">H", ch[pos:pos + 2])[0]
    pos += 2
    ext_end = pos + ext_total

    sni, alpn_first, alpn_last, tls_minor = 0, 0, 0, 2
    exts_sorted: list[str] = []
    sigalgs: list[str] = []
    ext_count_total = 0

    while pos + 4 <= ext_end:
        t = struct.unpack(">H", ch[pos:pos + 2])[0]
        ln = struct.unpack(">H", ch[pos + 2:pos + 4])[0]
        pos += 4

        if not is_grease(t):
            ext_count_total += 1
            if t == 0x0000:
                sni = 1
            elif t == 0x002b and ln >= 1:
                list_len = ch[pos]
                for k in range(0, list_len, 2):
                    v = struct.unpack(">H", ch[pos + 1 + k:pos + 3 + k])[0]
                    if v >> 8 == 3 and 1 <= (v & 0xFF) <= 4 and (v & 0xFF) > tls_minor:
                        tls_minor = v & 0xFF
            elif t == 0x000d and ln >= 2:
                sa_len = struct.unpack(">H", ch[pos:pos + 2])[0]
                for k in range(0, sa_len, 2):
                    v = struct.unpack(">H", ch[pos + 2 + k:pos + 4 + k])[0]
                    sigalgs.append(f"{v:04x}")
            elif t == 0x0010 and ln >= 3:
                first_len = ch[pos + 2]
                alpn_first, alpn_last = ch[pos + 3], ch[pos + 3 + first_len - 1]

            if t not in (0x0000, 0x0010):
                exts_sorted.append(f"{t:04x}")

        pos += ln

    b_input = ",".join(sorted(ciphers))
    c_input = ",".join(sorted(exts_sorted))
    if sigalgs:
        c_input += "_" + ",".join(sigalgs)

    ja4_b = hashlib.sha256(b_input.encode()).hexdigest()[:12] if ciphers else "0" * 12
    ja4_c = hashlib.sha256(c_input.encode()).hexdigest()[:12] if (exts_sorted or sigalgs) else "0" * 12

    if alpn_first:
        ap = chr(alpn_first) + chr(alpn_last)
    else:
        ap = "00"

    return f"t1{tls_minor - 1}{'d' if sni else 'i'}{len(ciphers):02d}{ext_count_total:02d}{ap}_{ja4_b}_{ja4_c}"


def fetch(path: str) -> str:
    """GET a path from the proxy's stats endpoint.

    Args:
        path: Path including the leading slash (e.g. "/stats", "/metrics").

    Returns:
        The response body as a decoded string.
    """
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    port = os.environ.get("TELEPROXY_STATS_PORT", "8888")
    return urllib.request.urlopen(f"http://{host}:{port}{path}", timeout=5).read().decode()


def trigger_handshake() -> bytes:
    """Send one fake-TLS ClientHello to the proxy and return the buffer used.

    Returns:
        The exact 517-byte ClientHello bytes whose JA4 must appear in /stats.
    """
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    port = int(os.environ.get("TELEPROXY_PORT", "8443"))
    domain = os.environ.get("TLS_BACKEND_HOST", "tls-backend")
    hello = build_client_hello(domain)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect((socket.gethostbyname(host), port))
    sock.sendall(bytes(hello))
    # Drain a few bytes (or fail) to give the proxy a chance to record JA4
    # — JA4 fires pre-HMAC, before our HMAC-less request is rejected.
    sock.settimeout(0.5)
    try:
        sock.recv(64)
    except socket.timeout:
        pass
    sock.close()
    return bytes(hello)


def test_ja4_seen_in_stats() -> None:
    """Verify /stats lists ja4_seen with the expected hash and count >= 1."""
    hello = trigger_handshake()
    expected = compute_ja4(hello)
    # Small delay so the stats snapshot picks up the increment.
    time.sleep(0.5)
    body = fetch("/stats")
    ja4_lines = [ln for ln in body.splitlines() if ln.startswith("ja4_seen\t")]
    assert ja4_lines, f"/stats missing ja4_seen lines:\n{body[-400:]}"
    matched = [ln for ln in ja4_lines if ln.split("\t")[1] == expected]
    assert matched, f"expected JA4 {expected} not in /stats; got: {ja4_lines}"
    count = int(matched[0].split("\t")[2])
    assert count >= 1, f"ja4_seen count for {expected} is {count}, want >= 1"
    print(f"  /stats ja4_seen={expected} count={count}")


def test_ja4_in_prometheus_metrics() -> None:
    """Verify /metrics exposes teleproxy_ja4_seen with the expected hash."""
    hello = trigger_handshake()
    expected = compute_ja4(hello)
    time.sleep(0.5)
    body = fetch("/metrics")
    assert "# TYPE teleproxy_ja4_seen counter" in body, \
        f"/metrics missing teleproxy_ja4_seen HELP/TYPE block:\n{body[-400:]}"
    needle = f'teleproxy_ja4_seen{{hash="{expected}"}}'
    matched = [ln for ln in body.splitlines() if ln.startswith(needle)]
    assert matched, f"expected metric {needle} not in /metrics output"
    print(f"  /metrics {matched[0]}")


def main() -> None:
    """Drive the JA4 e2e suite."""
    tests = [
        ("test_ja4_seen_in_stats", test_ja4_seen_in_stats),
        ("test_ja4_in_prometheus_metrics", test_ja4_in_prometheus_metrics),
    ]
    failed = 0
    for name, fn in tests:
        print(f"[RUN]  {name}", flush=True)
        try:
            fn()
            print(f"[PASS] {name}\n", flush=True)
        except AssertionError as exc:
            print(f"[FAIL] {name}: {exc}\n", flush=True)
            failed += 1
        except (OSError, ValueError) as exc:
            print(f"[FAIL] {name}: {exc}\n", flush=True)
            failed += 1
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
