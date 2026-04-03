#!/usr/bin/env python3
"""E2E tests for Teleproxy TLS handshake probing and emulation.

Uses a real Telethon client to connect through the proxy (proving the full
fake-TLS handshake pipeline works), and raw socket probes to independently
measure the TLS backend's parameters for comparison.
"""
import asyncio
import hashlib
import hmac as hmac_mod
import os
import socket
import ssl
import struct
import sys
import time


# ============================================================
# TLS ClientHello builder (replicates create_request from C)
# net/net-tcp-rpc-ext-server.c:333-389
# ============================================================

TLS_REQUEST_LENGTH = 517


def _generate_greases():
    """Generate 7 GREASE values per the TLS GREASE spec."""
    greases = bytearray(os.urandom(7))
    for i in range(7):
        greases[i] = (greases[i] & 0xF0) | 0x0A
    for i in range(1, 7, 2):
        if greases[i] == greases[i - 1]:
            greases[i] ^= 0x10
    return greases


def build_client_hello(domain):
    """Build a 517-byte TLS ClientHello matching Teleproxy's create_request().

    Args:
        domain: SNI hostname to include in the ClientHello.

    Returns:
        bytearray of exactly 517 bytes.
    """
    buf = bytearray(TLS_REQUEST_LENGTH)
    pos = 0
    greases = _generate_greases()
    domain_bytes = domain.encode("ascii")
    domain_length = len(domain_bytes)

    def add(data):
        nonlocal pos
        buf[pos : pos + len(data)] = data
        pos += len(data)

    def add_random(n):
        nonlocal pos
        buf[pos : pos + n] = os.urandom(n)
        pos += n

    def add_length(length):
        nonlocal pos
        struct.pack_into(">H", buf, pos, length)
        pos += 2

    def add_grease(num):
        nonlocal pos
        buf[pos] = greases[num]
        buf[pos + 1] = greases[num]
        pos += 2

    # TLS record header (type=handshake, version=TLS1.0, length=512)
    # + handshake header (type=ClientHello, body_length=508)
    # + ClientHello version (TLS 1.2)
    add(b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03")

    # client_random (32 bytes)
    add_random(32)

    # session_id_length (32) + session_id
    add(b"\x20")
    add_random(32)

    # cipher_suites_length (34) + GREASE + 16 cipher suites
    add(b"\x00\x22")
    add_grease(0)
    add(
        b"\x13\x01\x13\x02\x13\x03\xc0\x2b\xc0\x2f\xc0\x2c\xc0\x30\xcc\xa9\xcc\xa8"
        b"\xc0\x13\xc0\x14\x00\x9c\x00\x9d\x00\x2f\x00\x35\x00\x0a"
    )

    # compression_methods_length(1) + null + extensions_length(401=0x0191)
    add(b"\x01\x00\x01\x91")

    # --- Extensions ---

    # GREASE extension (empty)
    add_grease(2)
    add(b"\x00\x00")

    # SNI extension (type=0x0000)
    add(b"\x00\x00")
    add_length(domain_length + 5)
    add_length(domain_length + 3)
    add(b"\x00")
    add_length(domain_length)
    add(domain_bytes)

    # extended_master_secret (type=0x0017, empty)
    add(b"\x00\x17\x00\x00")

    # renegotiation_info (type=0xff01, length=1, data=0x00)
    add(b"\xff\x01\x00\x01\x00")

    # supported_groups (type=0x000a, length=10, list_length=8)
    add(b"\x00\x0a\x00\x0a\x00\x08")
    add_grease(4)
    add(b"\x00\x1d\x00\x17\x00\x18")

    # ec_point_formats (type=0x000b)
    add(b"\x00\x0b\x00\x02\x01\x00")

    # session_ticket (type=0x0023, empty)
    add(b"\x00\x23\x00\x00")

    # ALPN (type=0x0010): h2 + http/1.1
    add(
        b"\x00\x10\x00\x0e\x00\x0c\x02\x68\x32\x08\x68\x74\x74\x70\x2f\x31\x2e\x31"
    )

    # status_request (type=0x0005)
    add(b"\x00\x05\x00\x05\x01\x00\x00\x00\x00")

    # signature_algorithms (type=0x000d)
    add(
        b"\x00\x0d\x00\x14\x00\x12\x04\x03\x08\x04\x04"
        b"\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01\x02\x01"
    )

    # signed_certificate_timestamp (type=0x0012, empty)
    add(b"\x00\x12\x00\x00")

    # key_share (type=0x0033, length=43, list_length=41)
    add(b"\x00\x33\x00\x2b\x00\x29")
    add_grease(4)
    add(b"\x00\x01\x00")  # GREASE key share: group(2) + length(1) + data(1=\x00)
    add(b"\x00\x1d\x00\x20")  # x25519: group(2) + length(32)
    add_random(32)  # X25519 public key (random is fine for probing)

    # psk_key_exchange_modes (type=0x002d)
    add(b"\x00\x2d\x00\x02\x01\x01")

    # supported_versions (type=0x002b, length=11, list_length=10)
    add(b"\x00\x2b\x00\x0b\x0a")
    add_grease(6)
    add(b"\x03\x04\x03\x03\x03\x02\x03\x01")

    # compress_certificate (type=0x001b)
    add(b"\x00\x1b\x00\x03\x02\x00\x02")

    # GREASE extension (length=1, data=0x00)
    add_grease(3)
    add(b"\x00\x01\x00")

    # padding extension (type=0x0015)
    add(b"\x00\x15")
    padding_length = TLS_REQUEST_LENGTH - 2 - pos
    assert padding_length >= 0, f"ClientHello overflow: pos={pos}, need padding={padding_length}"
    add_length(padding_length)
    # Rest is already zero (bytearray default)

    assert pos + padding_length == TLS_REQUEST_LENGTH, (
        f"Size mismatch: pos={pos} + padding={padding_length} != {TLS_REQUEST_LENGTH}"
    )
    return buf


# ============================================================
# Raw TLS probe — independently measure backend parameters
# ============================================================


def probe_real_tls(host, port=443):
    """Probe a real TLS server and parse ServerHello parameters.

    Args:
        host: Hostname or IP of the TLS server.
        port: Port number.

    Returns:
        Dict with is_reversed_extension_order, encrypted_record_sizes,
        encrypted_record_count, total_encrypted_size.
    """
    hello = build_client_hello(host)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect((socket.gethostbyname(host), port))
    sock.sendall(bytes(hello))

    # Read response (server sends everything in one burst)
    data = b""
    deadline = time.time() + 3
    while time.time() < deadline:
        try:
            chunk = sock.recv(16384)
            if not chunk:
                break
            data += chunk
        except socket.timeout:
            break
    sock.close()

    return parse_tls_server_hello(data)


def parse_tls_server_hello(data):
    """Parse raw TLS ServerHello + CCS + encrypted records.

    Args:
        data: Raw bytes received from the TLS server.

    Returns:
        Dict with parsed TLS parameters.
    """
    result = {}

    if len(data) < 10:
        raise ValueError(f"Response too short: {len(data)} bytes")

    # TLS record header
    if data[:3] != b"\x16\x03\x03":
        raise ValueError(f"Not a TLS ServerHello: \\x{data[0]:02x}\\x{data[1]:02x}\\x{data[2]:02x}")

    record_len = struct.unpack(">H", data[3:5])[0]

    # Handshake type
    if data[5] != 0x02:
        raise ValueError(f"Not a ServerHello handshake: 0x{data[5]:02x}")

    # Parse body to find extensions (variable offset due to session_id)
    pos = 9  # skip record header(5) + handshake header(4)
    pos += 2  # version
    pos += 32  # server_random
    session_id_len = data[pos]
    pos += 1 + session_id_len  # session_id
    pos += 2  # cipher_suite
    pos += 1  # compression

    # Extensions
    ext_len = struct.unpack(">H", data[pos : pos + 2])[0]
    pos += 2
    extensions = []
    ext_end = pos + ext_len
    while pos < ext_end:
        ext_id = struct.unpack(">H", data[pos : pos + 2])[0]
        ext_data_len = struct.unpack(">H", data[pos + 2 : pos + 4])[0]
        extensions.append({"id": ext_id, "length": ext_data_len})
        pos += 4 + ext_data_len

    result["extensions"] = extensions
    result["is_reversed_extension_order"] = (
        int(extensions[0]["id"] == 0x2B) if extensions else -1
    )

    # Move past ServerHello record
    pos = 5 + record_len

    # ChangeCipherSpec
    if pos + 6 > len(data):
        raise ValueError(f"Missing CCS (only {len(data)} bytes, need {pos + 6})")
    if data[pos : pos + 6] != b"\x14\x03\x03\x00\x01\x01":
        raise ValueError(f"Bad CCS at offset {pos}: {data[pos:pos+6].hex()}")
    pos += 6

    # Encrypted application data records
    encrypted_records = []
    while pos + 5 <= len(data) and data[pos : pos + 3] == b"\x17\x03\x03":
        rec_len = struct.unpack(">H", data[pos + 3 : pos + 5])[0]
        if pos + 5 + rec_len > len(data):
            break  # partial record, skip
        encrypted_records.append(rec_len)
        pos += 5 + rec_len

    result["encrypted_record_sizes"] = encrypted_records
    result["encrypted_record_count"] = len(encrypted_records)
    result["total_encrypted_size"] = sum(encrypted_records)

    return result


# ============================================================
# Helpers
# ============================================================


def _do_handshake(host, port, secret_bytes, domain=None, timestamp_offset=0):
    """Build and send a fake-TLS ClientHello, return raw response + client_random.

    The SNI domain MUST match the proxy's -D/EE_DOMAIN setting for the proxy
    to validate the HMAC and generate an emulated ServerHello.  If SNI doesn't
    match, the proxy forwards the connection to the real backend without HMAC
    validation.

    Args:
        host: Proxy hostname.
        port: Proxy listening port.
        secret_bytes: 16-byte proxy secret.
        domain: SNI domain for the ClientHello. Defaults to EE_DOMAIN env var.
        timestamp_offset: Seconds to add to current time for the embedded timestamp.
            Use negative values for timestamps in the past.

    Returns:
        Tuple of (response_data, client_random) where response_data is the raw
        bytes received from the proxy and client_random is the 32-byte value
        embedded in the ClientHello.
    """
    if domain is None:
        # EE_DOMAIN matches the proxy's -D setting; fall back to TLS_BACKEND_HOST
        # for the direct CI environment where EE_DOMAIN is not set but
        # TLS_BACKEND_HOST equals the proxy's -D domain (e.g. ya.ru).
        domain = os.environ.get(
            "EE_DOMAIN", os.environ.get("TLS_BACKEND_HOST", "172.30.0.10")
        )
    hello = build_client_hello(domain)

    hello_zeroed = bytearray(hello)
    hello_zeroed[11:43] = b"\x00" * 32
    expected = hmac_mod.new(secret_bytes, bytes(hello_zeroed), hashlib.sha256).digest()

    timestamp = int(time.time()) + timestamp_offset
    ts_bytes = struct.pack("<I", timestamp)
    xored_ts = bytes(a ^ b for a, b in zip(ts_bytes, expected[28:32]))
    client_random = expected[:28] + xored_ts
    hello[11:43] = client_random

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect((socket.gethostbyname(host), port))
    sock.sendall(bytes(hello))

    # Read the full response. The proxy (or backend) sends ServerHello + CCS +
    # encrypted records in one burst. We need the complete data for HMAC
    # verification.  After 138 bytes we can parse the encrypted record length
    # to know the exact total.
    data = b""
    expected_total = 0
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            chunk = sock.recv(16384)
            if not chunk:
                break
            data += chunk
            # Once we have the app-data header, compute expected total
            if expected_total == 0 and len(data) >= 138:
                # ServerHello(127) + CCS(6) + app-data header(5) = 138
                enc_len = struct.unpack(">H", data[136:138])[0]
                expected_total = 138 + enc_len
            if expected_total > 0 and len(data) >= expected_total:
                break
        except socket.timeout:
            break
    sock.close()

    return data, bytes(client_random)


def _verify_server_hmac(response_data, client_random, secret_bytes):
    """Check whether the server_random in a ServerHello matches the proxy's HMAC.

    The proxy computes server_random = HMAC-SHA256(secret, client_random + zeroed_response).
    If this matches, the proxy (not the real backend) generated the response.

    Args:
        response_data: Raw bytes of the full ServerHello response.
        client_random: The 32-byte client_random sent in the ClientHello.
        secret_bytes: 16-byte proxy secret.

    Returns:
        True if the server_random HMAC matches (proxy handled the connection).
    """
    if len(response_data) < 43:
        return False

    server_random = response_data[11:43]

    zeroed = bytearray(response_data)
    zeroed[11:43] = b"\x00" * 32

    buf = client_random + bytes(zeroed)
    expected = hmac_mod.new(secret_bytes, buf, hashlib.sha256).digest()
    return expected[:32] == server_random


def wait_for_proxy(host, port, timeout=60):
    """Poll proxy port until it accepts TCP connections.

    The stats HTTP port binds to 127.0.0.1 (localhost only), so we check
    the proxy port (which binds to 0.0.0.0) for cross-container readiness.

    Args:
        host: Proxy hostname.
        port: Proxy listening port (not stats port).
        timeout: Max seconds to wait.

    Returns:
        True if proxy is ready, False on timeout.
    """
    deadline = time.time() + timeout
    last_err = None
    while time.time() < deadline:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((socket.gethostbyname(host), int(port)))
            s.close()
            return True
        except Exception as e:
            last_err = e
        time.sleep(2)
    print(f"  Proxy not ready after {timeout}s (last error: {last_err})")
    return False


# ============================================================
# Test cases
# ============================================================


def test_proxy_accepts_connections():
    """Verify proxy port accepts TCP connections."""
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    port = int(os.environ.get("TELEPROXY_PORT", "8443"))

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((socket.gethostbyname(host), port))
    s.close()
    print(f"  Proxy port {host}:{port} accepts TCP connections")


def test_fake_tls_handshake():
    """Send a fake-TLS ClientHello with correct HMAC to the proxy and verify
    the emulated ServerHello response.

    This is the core E2E test for the fake-TLS protocol:
    1. Build a ClientHello (same format as create_request in C)
    2. Compute HMAC-SHA256(secret, hello_with_zeroed_random)
    3. Embed the HMAC + timestamp in client_random
    4. Send to proxy, receive emulated ServerHello
    5. Validate: TLS 1.3 structure, session_id echo, extensions, encrypted data

    No Telegram DC connectivity needed — this only tests the proxy's TLS layer.
    """
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    port = int(os.environ.get("TELEPROXY_PORT", "8443"))
    secret_hex = os.environ.get("TELEPROXY_SECRET", "")
    # Use the -D domain so SNI lookup succeeds; for IP-based -D, any SNI works
    # since default_domain_info is used as fallback
    domain = os.environ.get("TLS_BACKEND_HOST", "tls-backend")

    assert secret_hex, "TELEPROXY_SECRET environment variable not set"
    secret_bytes = bytes.fromhex(secret_hex)

    # Build ClientHello
    hello = build_client_hello(domain)

    # Compute HMAC (mirrors proxy validation at net/net-tcp-rpc-ext-server.c:1209-1232)
    # 1. Zero out client_random (bytes 11-42)
    hello_zeroed = bytearray(hello)
    hello_zeroed[11:43] = b"\x00" * 32
    # 2. HMAC-SHA256(secret, full_zeroed_hello)
    expected = hmac_mod.new(secret_bytes, bytes(hello_zeroed), hashlib.sha256).digest()
    # 3. client_random[0:28] = expected[0:28]
    #    client_random[28:32] = timestamp XOR expected[28:32]
    timestamp = int(time.time())
    ts_bytes = struct.pack("<I", timestamp)
    xored_ts = bytes(a ^ b for a, b in zip(ts_bytes, expected[28:32]))
    client_random = expected[:28] + xored_ts
    hello[11:43] = client_random

    # Connect and send
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect((socket.gethostbyname(host), port))
    sock.sendall(bytes(hello))

    # Read ServerHello response
    data = b""
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            chunk = sock.recv(16384)
            if not chunk:
                break
            data += chunk
            # ServerHello(127) + CCS(6) + at least one encrypted header(5) = 138 minimum
            if len(data) >= 138:
                break
        except socket.timeout:
            break
    sock.close()

    assert len(data) >= 138, (
        f"Response too short ({len(data)} bytes) — proxy likely rejected the ClientHello. "
        f"First bytes: {data[:20].hex() if data else 'empty'}"
    )

    # Parse the emulated ServerHello
    result = parse_tls_server_hello(data)

    # Validate TLS 1.3 structure
    assert len(result["extensions"]) == 2, (
        f"Expected 2 extensions (key_share + supported_versions), got {len(result['extensions'])}"
    )
    ext_ids = {ext["id"] for ext in result["extensions"]}
    assert ext_ids == {0x33, 0x2B}, f"Expected extensions 0x33 and 0x2b, got {ext_ids}"

    # Validate session_id is echoed correctly
    sent_session_id = bytes(hello[44:76])
    # Session ID in ServerHello is at offset 44 (fixed for 32-byte session_id)
    received_session_id = data[44:76]
    assert sent_session_id == received_session_id, "Session ID not echoed correctly"

    # Validate encrypted data exists
    assert result["encrypted_record_count"] >= 1, "No encrypted records in ServerHello"
    assert result["total_encrypted_size"] > 0, "Zero-length encrypted data"

    print(
        f"  Fake-TLS handshake OK: "
        f"reversed_ext={result['is_reversed_extension_order']}, "
        f"encrypted_records={result['encrypted_record_count']}, "
        f"total_encrypted={result['total_encrypted_size']}, "
        f"session_id_echoed=True"
    )
    return result


def test_emulation_matches_backend():
    """Compare proxy's emulated ServerHello with the real backend's parameters.

    Probes the real TLS backend directly and connects to the proxy with
    fake-TLS, then compares the extension order — it must match.
    """
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    port = int(os.environ.get("TELEPROXY_PORT", "8443"))
    secret_hex = os.environ.get("TELEPROXY_SECRET", "")
    domain = os.environ.get("TLS_BACKEND_HOST", "tls-backend")
    backend_port = int(os.environ.get("TLS_BACKEND_PORT", "443"))

    # Get real backend parameters
    backend = probe_real_tls(domain, backend_port)

    # Get proxy's emulated parameters via fake-TLS handshake
    hello = build_client_hello(domain)
    hello_zeroed = bytearray(hello)
    hello_zeroed[11:43] = b"\x00" * 32
    secret_bytes = bytes.fromhex(secret_hex)
    expected = hmac_mod.new(secret_bytes, bytes(hello_zeroed), hashlib.sha256).digest()
    timestamp = int(time.time())
    ts_bytes = struct.pack("<I", timestamp)
    xored_ts = bytes(a ^ b for a, b in zip(ts_bytes, expected[28:32]))
    hello[11:43] = expected[:28] + xored_ts

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect((socket.gethostbyname(host), port))
    sock.sendall(bytes(hello))
    data = b""
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            chunk = sock.recv(16384)
            if not chunk:
                break
            data += chunk
        except socket.timeout:
            break
    sock.close()

    proxy = parse_tls_server_hello(data)

    # Extension order MUST match the real backend
    assert proxy["is_reversed_extension_order"] == backend["is_reversed_extension_order"], (
        f"Extension order mismatch: proxy={proxy['is_reversed_extension_order']}, "
        f"backend={backend['is_reversed_extension_order']}"
    )

    print(
        f"  Emulation comparison:"
        f"\n    Backend: records={backend['encrypted_record_count']}, "
        f"sizes={backend['encrypted_record_sizes']}, total={backend['total_encrypted_size']}"
        f"\n    Proxy:   records={proxy['encrypted_record_count']}, "
        f"sizes={proxy['encrypted_record_sizes']}, total={proxy['total_encrypted_size']}"
        f"\n    Extension order match: YES"
    )

    # Total encrypted size should be in the right ballpark.  The proxy adds
    # uniform noise in [-32, +32] to defeat DPI size fingerprinting, so allow
    # ±36 (32 noise + 4 for per-record variance across independent probes).
    assert abs(proxy["total_encrypted_size"] - backend["total_encrypted_size"]) <= 36, (
        f"Total encrypted size mismatch: proxy={proxy['total_encrypted_size']}, "
        f"backend={backend['total_encrypted_size']}"
    )


def test_server_random_hmac():
    """Verify the proxy's emulated ServerHello has a correct server_random HMAC.

    The proxy computes server_random = HMAC-SHA256(secret, client_random + zeroed_response).
    Verifying this proves the proxy (not the real backend) generated the response.
    """
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    port = int(os.environ.get("TELEPROXY_PORT", "8443"))
    secret_hex = os.environ.get("TELEPROXY_SECRET", "")
    assert secret_hex, "TELEPROXY_SECRET environment variable not set"
    secret_bytes = bytes.fromhex(secret_hex)

    data, client_random = _do_handshake(host, port, secret_bytes)

    assert len(data) >= 138, (
        f"Response too short ({len(data)} bytes) — proxy likely rejected the ClientHello"
    )
    assert _verify_server_hmac(data, client_random, secret_bytes), (
        "server_random HMAC mismatch — proxy did not generate this ServerHello"
    )
    print("  server_random HMAC verified: proxy generated the ServerHello")


def test_wrong_secret_rejected():
    """Verify that a ClientHello signed with the wrong secret is rejected.

    The proxy should forward the connection to the real TLS backend.
    We detect this by checking that the server_random HMAC does NOT match.
    """
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    port = int(os.environ.get("TELEPROXY_PORT", "8443"))
    secret_hex = os.environ.get("TELEPROXY_SECRET", "")
    assert secret_hex, "TELEPROXY_SECRET environment variable not set"
    real_secret = bytes.fromhex(secret_hex)

    # Use a different secret for the HMAC (flip every bit of the real secret)
    wrong_secret = bytes(b ^ 0xFF for b in real_secret)

    data, client_random = _do_handshake(host, port, wrong_secret)

    assert len(data) >= 10, (
        f"No response received ({len(data)} bytes) — expected backend ServerHello"
    )
    assert not _verify_server_hmac(data, client_random, real_secret), (
        "server_random HMAC matched with wrong secret — proxy should have rejected this"
    )
    print("  Wrong secret correctly rejected: response is from real backend")


def test_stale_timestamp_rejected():
    """Verify that a ClientHello with a 10-minute-old timestamp is rejected.

    With the tightened 2-minute replay window (MAX_ALLOWED_TIMESTAMP_ERROR=120s),
    a timestamp 600 seconds in the past should be rejected.
    """
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    port = int(os.environ.get("TELEPROXY_PORT", "8443"))
    secret_hex = os.environ.get("TELEPROXY_SECRET", "")
    assert secret_hex, "TELEPROXY_SECRET environment variable not set"
    secret_bytes = bytes.fromhex(secret_hex)

    data, client_random = _do_handshake(
        host, port, secret_bytes, timestamp_offset=-600
    )

    assert len(data) >= 10, (
        f"No response received ({len(data)} bytes) — expected backend ServerHello"
    )
    assert not _verify_server_hmac(data, client_random, secret_bytes), (
        "server_random HMAC matched with stale timestamp — "
        "proxy should have rejected this (600s > 120s window)"
    )
    print("  Stale timestamp (600s) correctly rejected")


def test_near_limit_timestamp_accepted():
    """Verify that a ClientHello with a 90-second-old timestamp is accepted.

    With MAX_ALLOWED_TIMESTAMP_ERROR=120s, a timestamp 90 seconds in the past
    is within the window and should be accepted.
    """
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    port = int(os.environ.get("TELEPROXY_PORT", "8443"))
    secret_hex = os.environ.get("TELEPROXY_SECRET", "")
    assert secret_hex, "TELEPROXY_SECRET environment variable not set"
    secret_bytes = bytes.fromhex(secret_hex)

    data, client_random = _do_handshake(
        host, port, secret_bytes, timestamp_offset=-90
    )

    assert len(data) >= 138, (
        f"Response too short ({len(data)} bytes) — proxy rejected the ClientHello"
    )
    assert _verify_server_hmac(data, client_random, secret_bytes), (
        "server_random HMAC mismatch — proxy should have accepted this "
        "(90s < 120s window)"
    )
    print("  Near-limit timestamp (90s) correctly accepted")


def test_unknown_sni_falls_back():
    """Verify that a ClientHello with an unknown SNI is forwarded to the backend.

    When the SNI in the ClientHello does not match any configured -D domain,
    the proxy falls back to default_domain_info and forwards the connection
    to the real backend. This tests the anti-detection path: a censor probing
    with a ClientHello for a different domain sees a real TLS server.
    """
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    port = int(os.environ.get("TELEPROXY_PORT", "8443"))
    secret_hex = os.environ.get("TELEPROXY_SECRET", "")
    assert secret_hex, "TELEPROXY_SECRET environment variable not set"
    secret_bytes = bytes.fromhex(secret_hex)

    # Use a domain that does NOT match the proxy's -D setting
    data, client_random = _do_handshake(
        host, port, secret_bytes, domain="unknown.example.com"
    )

    assert len(data) >= 10, (
        f"No response received ({len(data)} bytes) — expected backend ServerHello"
    )
    assert not _verify_server_hmac(data, client_random, secret_bytes), (
        "server_random HMAC matched with unknown SNI — proxy should have "
        "forwarded to backend"
    )
    print("  Unknown SNI correctly forwarded to backend")


def test_duplicate_client_random_rejected():
    """Verify that replaying the same ClientHello is detected and rejected.

    The proxy tracks seen client_random values to prevent replay attacks.
    The first handshake should succeed; the second with identical bytes should
    be forwarded to the real backend.
    """
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    port = int(os.environ.get("TELEPROXY_PORT", "8443"))
    secret_hex = os.environ.get("TELEPROXY_SECRET", "")
    assert secret_hex, "TELEPROXY_SECRET environment variable not set"
    secret_bytes = bytes.fromhex(secret_hex)
    domain = os.environ.get(
        "EE_DOMAIN", os.environ.get("TLS_BACKEND_HOST", "172.30.0.10")
    )

    # Build ClientHello and embed HMAC + timestamp
    hello = build_client_hello(domain)
    hello_zeroed = bytearray(hello)
    hello_zeroed[11:43] = b"\x00" * 32
    expected = hmac_mod.new(
        secret_bytes, bytes(hello_zeroed), hashlib.sha256
    ).digest()
    timestamp = int(time.time())
    ts_bytes = struct.pack("<I", timestamp)
    xored_ts = bytes(a ^ b for a, b in zip(ts_bytes, expected[28:32]))
    client_random = expected[:28] + xored_ts
    hello[11:43] = client_random
    hello_bytes = bytes(hello)

    def send_hello():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((socket.gethostbyname(host), port))
        sock.sendall(hello_bytes)
        data = b""
        expected_total = 0
        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                chunk = sock.recv(16384)
                if not chunk:
                    break
                data += chunk
                if expected_total == 0 and len(data) >= 138:
                    enc_len = struct.unpack(">H", data[136:138])[0]
                    expected_total = 138 + enc_len
                if expected_total > 0 and len(data) >= expected_total:
                    break
            except socket.timeout:
                break
        sock.close()
        return data

    # First send — proxy should accept (valid HMAC, fresh client_random)
    data1 = send_hello()
    assert len(data1) >= 138, (
        f"First send too short ({len(data1)} bytes) — proxy should accept"
    )
    assert _verify_server_hmac(data1, client_random, secret_bytes), (
        "First send: HMAC mismatch — proxy should have accepted this handshake"
    )

    # Second send — identical bytes, duplicate client_random → forwarded to backend
    data2 = send_hello()
    assert len(data2) >= 10, (
        f"Second send: no response ({len(data2)} bytes) — expected backend response"
    )
    assert not _verify_server_hmac(data2, client_random, secret_bytes), (
        "Second send: HMAC matched — proxy should have rejected duplicate "
        "client_random"
    )
    print("  Duplicate client_random correctly rejected on replay")


def test_browser_tls_sees_real_backend():
    """Verify a standard TLS client gets the real backend's certificate.

    This is the core anti-detection test: a censor probing with a regular
    HTTPS connection (e.g. curl, browser) should complete a real TLS handshake
    with the backend server, not receive a TLS error or proxy-generated response.
    """
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    port = int(os.environ.get("TELEPROXY_PORT", "8443"))

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


def _patch_telethon_faketls():
    """Patch TelethonFakeTLS to read all encrypted records in ServerHello.

    The upstream library only reads the first encrypted record, but the proxy
    computes the HMAC over all records. This patch reads all \x17\x03\x03
    records so the HMAC verification succeeds with multi-record responses.
    """
    import TelethonFakeTLS.FakeTLS.TLSInOut as tls_io

    async def _read_server_hello(self):
        # ServerHello(127) + CCS(6) = 133 bytes
        buf = bytearray(await self.upstream.readexactly(133))
        # Read all encrypted application data records
        while True:
            try:
                header = await asyncio.wait_for(
                    self.upstream.readexactly(5), timeout=0.5
                )
            except asyncio.TimeoutError:
                break
            buf += header
            if header[:3] != b"\x17\x03\x03":
                break
            rec_len = int.from_bytes(header[3:5], "big")
            buf += await self.upstream.readexactly(rec_len)
        return bytes(buf)

    tls_io.FakeTLSStreamReader.read_server_hello = _read_server_hello


def test_telethon_connects():
    """Connect to proxy using Telethon — a real MTProto client with fake-TLS.

    If Telethon's connect() succeeds, it proves:
    1. Proxy accepted the fake-TLS ClientHello (HMAC validated)
    2. Proxy emulated a valid ServerHello (Telethon's parser accepted it)
    3. MTProto key exchange completed (Telegram DC is reachable through proxy)
    """
    from telethon import TelegramClient
    from TelethonFakeTLS import ConnectionTcpMTProxyFakeTLS

    _patch_telethon_faketls()

    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    port = int(os.environ.get("TELEPROXY_PORT", "8443"))
    secret = os.environ.get("TELEPROXY_SECRET", "")
    ee_domain = os.environ.get("EE_DOMAIN", "172.30.0.10")

    assert secret, "TELEPROXY_SECRET environment variable not set"

    async def _connect():
        client = TelegramClient(
            ":memory:",
            api_id=1,
            api_hash="b6b154c3707471f5339bd661645ed3d6",
            connection=ConnectionTcpMTProxyFakeTLS,
            # TelethonFakeTLS internally prepends "ee" — pass secret+domain only
            proxy=(host, port, secret + ee_domain.encode().hex()),
        )
        try:
            await asyncio.wait_for(client.connect(), timeout=30)
            connected = client.is_connected()
            return connected
        except Exception as e:
            # Distinguish TLS/connection errors from higher-level API errors.
            # If we got past the TLS handshake, the proxy works even if
            # the Telegram API rejects our dummy credentials.
            err_str = str(e).lower()
            if "auth" in err_str or "api_id" in err_str:
                print(f"  TLS handshake succeeded, API rejected (expected): {e}")
                return True
            raise
        finally:
            try:
                await client.disconnect()
            except Exception:
                pass

    connected = asyncio.run(_connect())
    assert connected, "Telethon failed to connect through Teleproxy with fake-TLS"
    print("  Telethon connected through proxy via fake-TLS successfully")


def test_tls_data_after_handshake():
    """Send CCS + obfuscated2 header + data immediately after TLS handshake.

    Exercises the direct-mode race condition where client data arrives before
    the proxy has finished its outbound DC connection setup. The proxy must
    not crash (SIGSEGV) and must keep the connection open for at least a few
    seconds while it processes the data.

    This also validates that DRS conn_types have check_conn_functions called
    (missing defaults for .reader/.writer caused crashes pre-fix).
    """
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    port = int(os.environ.get("TELEPROXY_PORT", "8443"))
    secret = os.environ.get("TELEPROXY_SECRET", "")
    assert secret, "TELEPROXY_SECRET not set"
    secret_bytes = bytes.fromhex(secret)

    # Step 1: perform the TLS handshake
    response_data, client_random = _do_handshake(host, port, secret_bytes)
    assert _verify_server_hmac(response_data, client_random, secret_bytes), \
        "HMAC mismatch — handshake failed"

    # Step 2: now do a FULL connection — handshake + CCS + obfuscated2 + payload
    # all sent in one burst to maximize the race window
    domain = os.environ.get(
        "EE_DOMAIN", os.environ.get("TLS_BACKEND_HOST", "172.30.0.10")
    )
    hello = build_client_hello(domain)
    hello_zeroed = bytearray(hello)
    hello_zeroed[11:43] = b"\x00" * 32
    expected = hmac_mod.new(secret_bytes, bytes(hello_zeroed), hashlib.sha256).digest()
    timestamp = int(time.time())
    ts_bytes = struct.pack("<I", timestamp)
    xored_ts = bytes(a ^ b for a, b in zip(ts_bytes, expected[28:32]))
    cr = expected[:28] + xored_ts
    hello[11:43] = cr

    # Build 64-byte obfuscated2-like header.  We intentionally skip the
    # AES-CTR encryption of bytes 56-63 — the proxy will decrypt and see a
    # non-matching tag, entering skip mode.  That's fine: this test only
    # verifies the proxy doesn't crash from the data burst, not that the
    # MTProto layer succeeds.
    obfs_header = bytearray(os.urandom(64))
    while (obfs_header[0] == 0xef or
           obfs_header[:4] in (b"HEAD", b"POST", b"GET ", b"OPTI") or
           obfs_header[4:8] == b"\x00\x00\x00\x00"):
        obfs_header = bytearray(os.urandom(64))

    # Wrap in TLS record
    obfs_len = len(obfs_header)
    tls_obfs = (b"\x17\x03\x03"
                + struct.pack(">H", obfs_len)
                + bytes(obfs_header))

    # Fake MTProto payload (just random bytes — proxy will relay them)
    payload = os.urandom(64)
    payload_len = len(payload)
    tls_payload = (b"\x17\x03\x03"
                   + struct.pack(">H", payload_len)
                   + payload)

    # CCS + obfuscated2 header + payload — all in one TCP write
    ccs = b"\x14\x03\x03\x00\x01\x01"
    burst = ccs + tls_obfs + tls_payload

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect((socket.gethostbyname(host), port))

    # Send ClientHello
    sock.sendall(bytes(hello))

    # Read ServerHello
    srv_data = b""
    deadline = time.time() + 3
    expected_total = 0
    while time.time() < deadline:
        try:
            chunk = sock.recv(16384)
            if not chunk:
                break
            srv_data += chunk
            if expected_total == 0 and len(srv_data) >= 138:
                enc_len = struct.unpack(">H", srv_data[136:138])[0]
                expected_total = 138 + enc_len
            if expected_total > 0 and len(srv_data) >= expected_total:
                break
        except socket.timeout:
            break

    assert len(srv_data) >= 133, f"ServerHello too short: {len(srv_data)} bytes"

    # Send the burst: CCS + obfs header + payload all at once
    sock.sendall(burst)

    # Give the proxy time to process (and potentially crash)
    sock.settimeout(2)
    try:
        sock.recv(4096)
    except (socket.timeout, ConnectionResetError, BrokenPipeError):
        pass
    sock.close()

    # The critical check: proxy must still be alive and accepting connections.
    # If check_conn_functions was missing or the data race caused a SIGSEGV,
    # the proxy process is dead and this will fail with ConnectionRefused.
    time.sleep(0.5)
    probe = socket.create_connection(
        (socket.gethostbyname(host), port), timeout=3
    )
    probe.close()
    print("  CCS + obfuscated2 + payload burst accepted, proxy stayed alive")


def test_probe_backend_tls13():
    """Independently probe the TLS backend and verify TLS 1.3 parameters.

    Returns:
        Parsed TLS parameters for use in comparison tests.
    """
    host = os.environ.get("TLS_BACKEND_HOST", "tls-backend")
    port = int(os.environ.get("TLS_BACKEND_PORT", "443"))

    result = probe_real_tls(host, port)

    assert result["is_reversed_extension_order"] in (0, 1), (
        f"Unexpected extension order value: {result['is_reversed_extension_order']}"
    )
    assert result["total_encrypted_size"] > 100, (
        f"Encrypted size suspiciously small: {result['total_encrypted_size']}"
    )
    assert result["encrypted_record_count"] >= 1, "No encrypted records found"

    print(
        f"  Backend TLS 1.3 OK: "
        f"reversed_ext={result['is_reversed_extension_order']}, "
        f"records={result['encrypted_record_count']}, "
        f"sizes={result['encrypted_record_sizes']}, "
        f"total={result['total_encrypted_size']}"
    )
    return result


# ============================================================
# Main
# ============================================================


def main():
    # Tests that MUST pass for the suite to succeed
    required_tests = [
        ("test_proxy_accepts_connections", test_proxy_accepts_connections),
        ("test_fake_tls_handshake", test_fake_tls_handshake),
        ("test_server_random_hmac", test_server_random_hmac),
        ("test_probe_backend_tls13", test_probe_backend_tls13),
        ("test_emulation_matches_backend", test_emulation_matches_backend),
        ("test_wrong_secret_rejected", test_wrong_secret_rejected),
        ("test_stale_timestamp_rejected", test_stale_timestamp_rejected),
        ("test_near_limit_timestamp_accepted", test_near_limit_timestamp_accepted),
        ("test_unknown_sni_falls_back", test_unknown_sni_falls_back),
        ("test_duplicate_client_random_rejected", test_duplicate_client_random_rejected),
        ("test_browser_tls_sees_real_backend", test_browser_tls_sees_real_backend),
        ("test_tls_data_after_handshake", test_tls_data_after_handshake),
    ]

    # Tests that warn on failure (require Telegram DC connectivity + correct
    # platform — may fail under Rosetta emulation on Apple Silicon)
    optional_tests = [
        ("test_telethon_connects", test_telethon_connects),
    ]

    print("Starting TLS E2E tests...\n", flush=True)

    # Wait for proxy to be ready (use proxy port, not stats — stats binds to localhost only)
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    proxy_port = os.environ.get("TELEPROXY_PORT", "8443")
    print(f"Waiting for proxy at {host}:{proxy_port}...", flush=True)
    if not wait_for_proxy(host, proxy_port, timeout=90):
        print("ERROR: Proxy not ready, aborting tests")
        sys.exit(1)
    print("Proxy is ready.\n", flush=True)

    passed = 0
    failed = 0
    warned = 0
    errors = []

    for name, test_fn in required_tests:
        try:
            print(f"[RUN]  {name}")
            test_fn()
            print(f"[PASS] {name}\n")
            passed += 1
        except Exception as e:
            print(f"[FAIL] {name}: {e}\n")
            failed += 1
            errors.append((name, e))

    for name, test_fn in optional_tests:
        try:
            print(f"[RUN]  {name}")
            test_fn()
            print(f"[PASS] {name}\n")
            passed += 1
        except Exception as e:
            print(f"[WARN] {name}: {e} (non-fatal, requires Telegram DC connectivity)\n")
            warned += 1

    print(f"Results: {passed} passed, {failed} failed, {warned} warned")
    if errors:
        print("\nFailures:")
        for name, err in errors:
            print(f"  {name}: {err}")

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
