"""Verify pre-handshake sockets are dropped on timeout when no fake-TLS is set.

Issue #63: scanners and probes that open a TCP connection but never send the
obfs2 handshake header used to sit on the proxy until OS-level keepalive
killed them (~2 hours), inflating ``total_connections`` indefinitely.

The proxy schedules a 10-second handshake alarm (``tcp_rpcs_ext_init_accepted``
in ``net-tcp-rpc-ext-server.c``).  When fake-TLS isn't configured, the alarm
handler used to no-op; now it drops the unhandshaked socket.

Strategy: dd-mode (no fake-TLS), open N TCP sockets, send nothing, wait past
the 10-second alarm, read ``/stats`` and assert ``total_connections`` is back
to baseline.
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

JUNK_CONNS = int(os.environ.get("JUNK_CONNS", "200"))
HANDSHAKE_TIMEOUT_S = 10
SETTLE_S = 5


def read_total_connections() -> int:
    """Return the ``total_connections`` gauge from /stats.

    Returns:
        Current active TCP connection count reported by the proxy.

    Raises:
        RuntimeError: If /stats doesn't include the counter.
    """
    r = requests.get(STATS_URL, timeout=5)
    r.raise_for_status()
    for line in r.text.splitlines():
        if line.startswith("total_connections\t"):
            return int(line.split("\t", 1)[1])
    raise RuntimeError("total_connections not found in /stats")


def main() -> None:
    """Open junk sockets, wait past the handshake alarm, assert counters drop."""
    target = socket.gethostbyname(HOST)
    print(f"Target: {target}:{PORT}")

    baseline = read_total_connections()
    print(f"Baseline total_connections: {baseline}")

    print(f"Opening {JUNK_CONNS} TCP sockets, sending nothing")
    sockets = []
    for _ in range(JUNK_CONNS):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((target, PORT))
        sockets.append(s)

    time.sleep(1)
    peak = read_total_connections()
    print(f"After open total_connections: {peak}")
    if peak < baseline + JUNK_CONNS // 2:
        print(f"FAIL: peak ({peak}) didn't grow as expected (baseline {baseline})")
        sys.exit(1)

    wait = HANDSHAKE_TIMEOUT_S + SETTLE_S
    print(f"Waiting {wait}s for handshake alarm to fire on each socket")
    time.sleep(wait)

    settled = read_total_connections()
    print(f"After timeout total_connections: {settled} (baseline {baseline})")

    for s in sockets:
        s.close()

    if settled > baseline + 5:
        print(
            f"FAIL: total_connections did not drain "
            f"(settled={settled}, baseline={baseline}, leaked={settled - baseline})"
        )
        sys.exit(1)

    print("PASS: pre-handshake sockets dropped on timeout")


if __name__ == "__main__":
    main()
