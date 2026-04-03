#!/usr/bin/env python3
"""E2E tests for the `teleproxy link` subcommand.

Validates that the subcommand prints a correct URL and renders a QR
code that decodes back to that URL.  Uses pyzbar for QR decoding.
"""
import os
import subprocess
import sys

from PIL import Image
from pyzbar.pyzbar import decode as qr_decode

BIN = os.environ.get("TELEPROXY_BIN", "/usr/local/bin/teleproxy")

passed = 0
failed = 0


def run_link(*args, timeout=10):
    """Run teleproxy link with given args, return (exit_code, stdout, stderr)."""
    cmd = [BIN, "link"] + list(args)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"


def check(name, condition, detail=""):
    global passed, failed
    if condition:
        passed += 1
        print(f"  PASS  {name}")
    else:
        failed += 1
        msg = f"  FAIL  {name}"
        if detail:
            msg += f"\n        {detail}"
        print(msg)


# ── QR parsing helpers ──────────────────────────────────────────

# UTF-8 byte sequences for the half-block characters
FULL_BLOCK = "\u2588"   # both light (inverted rendering)
UPPER_HALF = "\u2580"   # top light, bottom dark
LOWER_HALF = "\u2584"   # top dark, bottom light
# space = both dark


def parse_qr_output(stdout):
    """Parse UTF-8 half-block QR output into a PIL Image.

    Returns (url_line, image) where url_line is the first line (the URL)
    and image is a black-and-white PIL Image of the QR code.
    """
    lines = stdout.rstrip("\n").split("\n")
    url_line = lines[0]

    # QR lines are everything after the URL
    qr_lines = lines[1:]

    # Build pixel grid: two rows per text line
    rows = []
    for line in qr_lines:
        top_row = []
        bot_row = []
        for ch in line:
            if ch == FULL_BLOCK:
                # Inverted: both light → both white in QR
                top_row.append(255)
                bot_row.append(255)
            elif ch == UPPER_HALF:
                # Top light, bottom dark
                top_row.append(255)
                bot_row.append(0)
            elif ch == LOWER_HALF:
                # Top dark, bottom light
                top_row.append(0)
                bot_row.append(255)
            elif ch == " ":
                # Both dark
                top_row.append(0)
                bot_row.append(0)
            else:
                # Unknown char — treat as white (quiet zone)
                top_row.append(255)
                bot_row.append(255)
        if top_row:
            rows.append(top_row)
            rows.append(bot_row)

    if not rows:
        return url_line, None

    # All rows should have the same width
    width = max(len(r) for r in rows)
    for r in rows:
        while len(r) < width:
            r.append(255)

    height = len(rows)

    # Scale up for better detection (pyzbar needs some pixel density)
    scale = 8
    img = Image.new("L", (width * scale, height * scale), 255)
    pixels = img.load()
    for y, row in enumerate(rows):
        for x, val in enumerate(row):
            for dy in range(scale):
                for dx in range(scale):
                    pixels[x * scale + dx, y * scale + dy] = val

    return url_line, img


def decode_qr(stdout):
    """Decode QR from teleproxy link output. Returns (url_text, decoded_qr_text)."""
    url_line, img = parse_qr_output(stdout)
    if img is None:
        return url_line, None

    results = qr_decode(img)
    if not results:
        return url_line, None

    return url_line, results[0].data.decode("utf-8")


def assert_qr_valid(name, server, port, secret, label=None):
    """Run teleproxy link and verify the QR decodes to the expected URL."""
    args = ["--server", server, "--port", port, "--secret", secret]
    if label:
        args += ["--label", label]

    code, out, err = run_link(*args)
    check(f"{name}: exit 0", code == 0, f"got exit {code}, stderr: {err}")

    expected_url = f"https://t.me/proxy?server={server}&port={port}&secret={secret}"

    url_text, qr_text = decode_qr(out)

    # URL line should contain the expected URL
    check(f"{name}: URL in output",
          expected_url in url_text,
          f"expected '{expected_url}' in '{url_text}'")

    # Label should appear in text but NOT in QR
    if label:
        check(f"{name}: label in text",
              f"[{label}]" in url_text,
              f"'{url_text}' missing [{label}]")

    # QR should decode to the URL (without label)
    check(f"{name}: QR decodes correctly",
          qr_text == expected_url,
          f"decoded: '{qr_text}', expected: '{expected_url}'")


# ── Test cases ──────────────────────────────────────────────────

print("=== QR decodability tests ===")

# 1. Plain hex secret
assert_qr_valid("plain secret",
                "1.2.3.4", "443",
                "aabbccdd11223344aabbccdd11223344")

# 2. EE-prefixed secret (fake-TLS with domain)
assert_qr_valid("ee-prefixed secret",
                "203.0.113.42", "8443",
                "ee11223344556677881122334455667788676f6f676c652e636f6d")

# 3. DD-prefixed secret (random padding)
assert_qr_valid("dd-prefixed secret",
                "10.0.0.1", "443",
                "ddaabbccdd11223344aabbccdd11223344")

# 4. With label (label in text, not in QR)
assert_qr_valid("secret with label",
                "192.168.1.1", "443",
                "aabbccdd11223344aabbccdd11223344",
                label="family")

# 5. IPv6 server
assert_qr_valid("ipv6 server",
                "2001:db8::1", "443",
                "aabbccdd11223344aabbccdd11223344")

# 6. Long ee secret (long domain → larger QR)
domain_hex = "".join(f"{ord(c):02x}" for c in "cdn.telegram.org")
assert_qr_valid("long ee secret",
                "1.2.3.4", "443",
                f"ee11223344556677881122334455667788{domain_hex}")


print("\n=== Argument validation tests ===")

# 7. Missing --server
code, out, err = run_link("--port", "443", "--secret", "aa" * 16)
check("missing --server → exit 2", code == 2, f"got exit {code}")

# 8. Missing --port
code, out, err = run_link("--server", "1.2.3.4", "--secret", "aa" * 16)
check("missing --port → exit 2", code == 2, f"got exit {code}")

# 9. Missing --secret
code, out, err = run_link("--server", "1.2.3.4", "--port", "443")
check("missing --secret → exit 2", code == 2, f"got exit {code}")

# 10. No arguments at all
code, out, err = run_link()
check("no arguments → exit 2", code == 2, f"got exit {code}")


# ── Summary ─────────────────────────────────────────────────────

print(f"\n{'=' * 40}")
print(f"Results: {passed} passed, {failed} failed")

if failed > 0:
    sys.exit(1)
print("All tests passed!")
