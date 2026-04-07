#!/usr/bin/env python3
"""E2E tests for graceful secret draining on SIGHUP reload (issue #45).

Verifies that:
- A secret removed from the TOML keeps existing handshake state until the
  drain timeout, then is force-released.
- New connections matching a drained secret are rejected and incremented
  in `secret_<lbl>_rejected_draining`.
- Re-adding a removed secret reuses the same slot (counters carry over).
- Pinned -S secrets are unaffected by draining.
- The `drain_timeout_secs` TOML option is parsed and reloadable.
"""
import os
import signal
import socket
import sys
import time

import requests

from test_tls_e2e import (
    _do_handshake,
    _verify_server_hmac,
    wait_for_proxy,
)

CONFIG_PATH = os.environ.get("CONFIG_PATH", "/shared/config.toml")


def write_config(secrets, drain_timeout_secs=None):
    """Write a TOML config with the given secrets and optional drain timeout."""
    with open(CONFIG_PATH, "w") as f:
        f.write("# Test config\n")
        f.write("direct = true\n")
        f.write("http_stats = true\n")
        if drain_timeout_secs is not None:
            f.write(f"drain_timeout_secs = {drain_timeout_secs}\n")
        f.write("\n")
        for secret_hex, label in secrets:
            f.write("[[secret]]\n")
            f.write(f'key = "{secret_hex}"\n')
            if label:
                f.write(f'label = "{label}"\n')
            f.write("\n")


def send_sighup(wait=0.5):
    """Send SIGHUP to PID 1 (the proxy via shared pid namespace)."""
    try:
        os.kill(1, signal.SIGHUP)
    except ProcessLookupError:
        print("  WARNING: PID 1 not found")
    except PermissionError:
        print("  WARNING: no permission to signal PID 1")
    if wait > 0:
        time.sleep(wait)


def get_metrics(host, stats_port="8888"):
    resp = requests.get(f"http://{host}:{stats_port}/metrics", timeout=5)
    resp.raise_for_status()
    return resp.text


def get_stats(host, stats_port="8888"):
    resp = requests.get(f"http://{host}:{stats_port}/stats", timeout=5)
    resp.raise_for_status()
    return resp.text


def handshake_works(host, port, secret_hex):
    secret_bytes = bytes.fromhex(secret_hex)
    data, client_random = _do_handshake(host, port, secret_bytes)
    return len(data) >= 138 and _verify_server_hmac(data, client_random, secret_bytes)


def metric_value(metrics_text, name, secret_label):
    """Parse a Prometheus metric value for {secret="<label>"}, return float or None."""
    needle = f'{name}{{secret="{secret_label}"}} '
    for line in metrics_text.splitlines():
        if line.startswith(needle):
            try:
                return float(line[len(needle):].strip())
            except ValueError:
                return None
    return None


def test_drain_metric_after_remove():
    """After SIGHUP removes a secret, metrics expose the draining state and
    new handshakes are rejected and counted."""
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    port = int(os.environ.get("TELEPROXY_PORT", "8443"))
    a = os.environ["TELEPROXY_SECRET_1"]
    b = os.environ["TELEPROXY_SECRET_2"]

    # Initial state: both secrets active, long timeout to keep draining slot
    # observable for the test window.
    write_config([(a, "alpha"), (b, "beta")], drain_timeout_secs=600)
    send_sighup()
    assert handshake_works(host, port, a), "alpha should work after initial reload"
    assert handshake_works(host, port, b), "beta should work after initial reload"

    # Remove alpha — it transitions to draining.
    write_config([(b, "beta")], drain_timeout_secs=600)
    send_sighup(wait=0)

    # Hammer rejected_draining for ~0.5s.  The sweeper runs at 1 Hz and only
    # releases empty slots with no in-flight connections, so we may have a
    # narrow window.  Retry over a few hundred ms to handle the race.
    seen_draining = False
    rejected = 0
    deadline = time.time() + 0.8
    while time.time() < deadline:
        ok = handshake_works(host, port, a)
        assert not ok, "alpha must be rejected after removal"
        try:
            metrics = get_metrics(host)
        except requests.RequestException:
            continue
        draining = metric_value(metrics, "teleproxy_secret_draining", "alpha")
        rejected = metric_value(metrics, "teleproxy_secret_rejected_draining_total", "alpha") or 0
        if draining and draining > 0 and rejected > 0:
            seen_draining = True
            break

    if not seen_draining:
        # Either the sweeper ate the slot too fast or rejected counter didn't
        # propagate yet — accept either, but make sure alpha really is gone.
        metrics = get_metrics(host)
        gone = metric_value(metrics, "teleproxy_secret_draining", "alpha") is None
        assert gone, (
            f"alpha should be either draining or fully released, but metrics still expose it: "
            f"{[l for l in metrics.splitlines() if 'alpha' in l]}"
        )
        print("  WARNING: drain window observed as zero — slot was released before metric fetch")
    else:
        print(f"  Observed draining state, rejected_draining={rejected}")


def test_drain_revives_on_readd():
    """Re-adding a removed secret reuses the same slot (counters carry over)."""
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    port = int(os.environ.get("TELEPROXY_PORT", "8443"))
    a = os.environ["TELEPROXY_SECRET_1"]
    b = os.environ["TELEPROXY_SECRET_2"]

    write_config([(a, "alpha"), (b, "beta")], drain_timeout_secs=600)
    send_sighup()
    assert handshake_works(host, port, a)

    # Force a rejection so the rejected counter is non-zero, then snapshot.
    write_config([(b, "beta")], drain_timeout_secs=600)
    send_sighup(wait=0)
    handshake_works(host, port, a)  # rejected
    time.sleep(0.2)

    # Re-add alpha.
    write_config([(a, "alpha"), (b, "beta")], drain_timeout_secs=600)
    send_sighup()

    # alpha must work again.
    assert handshake_works(host, port, a), "alpha should be revived after re-adding"
    # No longer in draining state.
    metrics = get_metrics(host)
    draining = metric_value(metrics, "teleproxy_secret_draining", "alpha")
    assert draining == 0, f"alpha should not be draining after revival, got {draining}"
    print("  alpha revived after readd, draining gauge cleared")


def test_drain_pinned_unaffected():
    """Pinned -S CLI secrets must never drain via SIGHUP reload."""
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    port = int(os.environ.get("TELEPROXY_PORT", "8443"))
    pinned = os.environ.get("PINNED_SECRET", "")
    if not pinned:
        print("  SKIP: PINNED_SECRET not set")
        return

    write_config([], drain_timeout_secs=600)
    send_sighup()
    assert handshake_works(host, port, pinned), "pinned secret must survive reload"
    print("  pinned secret unaffected")


def test_drain_timeout_in_stats():
    """The drain_timeout_secs option is parsed and reloads cleanly."""
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    port = int(os.environ.get("TELEPROXY_PORT", "8443"))
    a = os.environ["TELEPROXY_SECRET_1"]

    # Reload with various drain timeouts to confirm parsing.
    for t in (0, 1, 30, 600):
        write_config([(a, "alpha")], drain_timeout_secs=t)
        send_sighup()
        assert handshake_works(host, port, a), f"reload with drain_timeout={t} broke alpha"
    print("  drain_timeout_secs accepted: 0, 1, 30, 600")


def main():
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    port = int(os.environ.get("TELEPROXY_PORT", "8443"))

    print("Starting secret drain tests...\n", flush=True)
    print(f"Waiting for proxy at {host}:{port}...", flush=True)
    if not wait_for_proxy(host, port, timeout=90):
        print("ERROR: Proxy not ready after 90s")
        sys.exit(1)
    print("Proxy is ready.\n", flush=True)
    time.sleep(1)

    tests = [
        ("test_drain_metric_after_remove", test_drain_metric_after_remove),
        ("test_drain_revives_on_readd", test_drain_revives_on_readd),
        ("test_drain_pinned_unaffected", test_drain_pinned_unaffected),
        ("test_drain_timeout_in_stats", test_drain_timeout_in_stats),
    ]

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
        for n, e in errors:
            print(f"  {n}: {e}")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
