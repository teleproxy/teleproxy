"""Test that buffer allocation failures don't crash the proxy.

Reproduces the crash from GitHub PR #54: when alloc_msg_buffer() returns NULL
under memory pressure, assert() kills the process with SIGABRT.

Strategy: open many partial connections that each send less than 64 bytes (the
obfs2 header size). The proxy buffers the partial data in c->in, holding one
2KB buffer per connection indefinitely. This fills the buffer chunk (~1000
buffers). The next allocation needs a new chunk, which the test build denies
via FAULT_ALLOC_LIMIT. On buggy code, assert(0) fires in net_server_socket_reader.
On fixed code, the connection is dropped gracefully and the proxy survives.
"""

import os
import socket
import sys
import time
import requests

HOST = os.environ.get("TELEPROXY_HOST", "teleproxy")
PORT = int(os.environ.get("TELEPROXY_PORT", "8443"))
STATS_PORT = int(os.environ.get("TELEPROXY_STATS_PORT", "8888"))
STATS_URL = f"http://{HOST}:{STATS_PORT}/stats"

# Partial connections to fill the buffer chunk
PARTIAL_CONNS = int(os.environ.get("PARTIAL_CONNS", "950"))
# Bytes to send per partial connection (< 64 for incomplete obfs2 header)
PARTIAL_BYTES = int(os.environ.get("PARTIAL_BYTES", "10"))
# Burst connections after filling the chunk (to trigger replacement alloc failure)
BURST_CONNS = int(os.environ.get("BURST_CONNS", "50"))


def check_alive(label="", show_buffers=False):
    """Check that teleproxy stats endpoint responds."""
    tag = f" ({label})" if label else ""
    try:
        r = requests.get(STATS_URL, timeout=5)
        if r.status_code == 200:
            if show_buffers:
                for line in r.text.splitlines():
                    if "buffer" in line.lower():
                        print(f"    {line.strip()}")
            print(f"  ALIVE{tag}: stats endpoint OK")
            return True
        print(f"  DEAD{tag}: stats returned {r.status_code}")
        return False
    except Exception as e:
        print(f"  DEAD{tag}: {e}")
        return False


def main():
    passed = 0
    failed = 0

    def check(name, condition, detail=""):
        nonlocal passed, failed
        if condition:
            passed += 1
            print(f"  PASS  {name}")
        else:
            failed += 1
            print(f"  FAIL  {name}  {detail}")

    target = socket.gethostbyname(HOST)

    # Step 1: Baseline
    print("Step 1: Baseline health check")
    check("baseline_alive", check_alive("baseline"))
    if failed:
        print("Proxy not alive at baseline, aborting")
        sys.exit(1)

    # Step 2: Fill the buffer chunk with partial connections.
    # Each sends < 64 bytes, so the proxy buffers the partial obfs2 header
    # in c->in, holding a 2KB buffer indefinitely until the connection closes.
    print(f"\nStep 2: Opening {PARTIAL_CONNS} partial connections "
          f"(each sends {PARTIAL_BYTES} bytes)")
    partial_sockets = []
    partial_data = os.urandom(PARTIAL_BYTES)
    for i in range(PARTIAL_CONNS):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((target, PORT))
            s.sendall(partial_data)
            partial_sockets.append(s)
        except OSError:
            pass  # connection failures expected under buffer pressure
        if (i + 1) % 200 == 0:
            print(f"  Opened {i + 1}/{PARTIAL_CONNS}...")

    opened = len(partial_sockets)
    print(f"  Opened {opened}/{PARTIAL_CONNS} partial connections")

    # Brief pause for the proxy to process all the partial reads
    time.sleep(2)

    # Step 3: Verify proxy is still alive with the chunk nearly full
    print("\nStep 3: Mid-fill health check")
    mid_alive = check_alive("mid-fill", show_buffers=True)
    if not mid_alive:
        print("Proxy died during partial fill (unexpected)")
        for s in partial_sockets:
            try:
                s.close()
            except OSError:
                pass  # best-effort cleanup, socket may already be reset
        check("survived_partial_fill", False, "died before burst")
        print(f"\nResults: {passed} passed, {failed} failed")
        sys.exit(1 if failed else 0)

    # Step 4: Burst connections to trigger the allocation failure.
    # The buffer chunk is now full. New connections cause readv() which
    # consumes recv buffers. The replacement allocation needs a new chunk,
    # which is denied by FAULT_ALLOC_LIMIT → alloc_msg_buffer returns NULL.
    # On buggy code: assert(0) fires → SIGABRT → proxy dies.
    # On fixed code: connection dropped gracefully → proxy survives.
    print(f"\nStep 4: Burst {BURST_CONNS} connections to trigger alloc failure")
    burst_data = os.urandom(4096)
    for i in range(BURST_CONNS):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((target, PORT))
            s.sendall(burst_data)
            s.close()
        except OSError:
            pass  # connection failures expected under buffer pressure

    # Brief pause for crash to manifest
    time.sleep(3)

    # Step 5: Final health check — did the proxy survive?
    print("\nStep 5: Post-burst health check")
    alive = False
    for attempt in range(5):
        if check_alive(f"post-burst attempt {attempt + 1}"):
            alive = True
            break
        time.sleep(1)

    check("survived_alloc_failure", alive,
          "proxy crashed on buffer allocation failure (assert in "
          "net_server_socket_reader or rwm_process_encrypt_decrypt)")

    # Step 6: Clean up partial connections
    print("\nStep 6: Closing partial connections")
    for s in partial_sockets:
        try:
            s.close()
        except OSError:
            pass  # best-effort cleanup, socket may already be reset
    print(f"  Closed {opened} partial connections")

    # Step 7: Verify proxy still works after cleanup
    if alive:
        time.sleep(1)
        print("\nStep 7: Post-cleanup health check")
        check("alive_after_cleanup", check_alive("post-cleanup"))

    print(f"\nResults: {passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
