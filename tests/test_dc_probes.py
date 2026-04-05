#!/usr/bin/env python3
"""E2E tests for DC health probes and Prometheus metrics.

Verifies that when dc_probe_interval is configured, the proxy
periodically probes all 5 Telegram DCs and exposes latency data
on both /stats (text) and /metrics (Prometheus) endpoints.
"""
import http.client
import os
import sys
import time


def get_stats(host, port, path="/stats"):
    """Fetch stats from proxy HTTP endpoint."""
    conn = http.client.HTTPConnection(host, int(port), timeout=5)
    conn.request("GET", path)
    resp = conn.getresponse()
    body = resp.read().decode()
    conn.close()
    return body


def parse_stat(stats_body, key):
    """Extract a stat value from tab-separated stats output."""
    for line in stats_body.splitlines():
        parts = line.split("\t", 1)
        if len(parts) == 2 and parts[0] == key:
            return parts[1].strip()
    return None


passed = 0
failed = 0


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


host = os.environ.get("TELEPROXY_HOST", "teleproxy")
stats_port = int(os.environ.get("TELEPROXY_STATS_PORT", "8888"))


# Wait for at least one probe cycle to complete
# (probe interval = 5s in docker-compose, wait 12s for safety)
print("Waiting for DC probes to complete...")
time.sleep(12)


# ── Text stats tests (/stats) ─────────────────────────────────

print("\n=== Text stats (/stats) ===")

stats = get_stats(host, stats_port, path="/stats")

check("dc_probe_interval present",
      parse_stat(stats, "dc_probe_interval") is not None,
      f"stats:\n{stats[:300]}")

val = parse_stat(stats, "dc_probe_interval")
if val:
    check("dc_probe_interval = 5",
          val == "5",
          f"got {val}")

for dc in range(1, 6):
    check(f"dc{dc}_probe_count present",
          parse_stat(stats, f"dc{dc}_probe_count") is not None)
    check(f"dc{dc}_probe_failures present",
          parse_stat(stats, f"dc{dc}_probe_failures") is not None)
    check(f"dc{dc}_probe_latency_last present",
          parse_stat(stats, f"dc{dc}_probe_latency_last") is not None)
    check(f"dc{dc}_probe_latency_avg present",
          parse_stat(stats, f"dc{dc}_probe_latency_avg") is not None)


# ── Prometheus metrics tests (/metrics) ────────────────────────

print("\n=== Prometheus metrics (/metrics) ===")

metrics = get_stats(host, stats_port, path="/metrics")

check("histogram HELP line",
      "# HELP teleproxy_dc_latency_seconds" in metrics)
check("histogram TYPE line",
      "# TYPE teleproxy_dc_latency_seconds histogram" in metrics)
check("failure counter HELP",
      "# HELP teleproxy_dc_probe_failures_total" in metrics)
check("last latency gauge HELP",
      "# HELP teleproxy_dc_latency_last_seconds" in metrics)

for dc in range(1, 6):
    prefix = f'teleproxy_dc_latency_seconds_bucket{{dc="{dc}",le="0.005"}}'
    check(f"DC {dc} first bucket present",
          prefix in metrics)

    inf = f'teleproxy_dc_latency_seconds_bucket{{dc="{dc}",le="+Inf"}}'
    check(f"DC {dc} +Inf bucket present",
          inf in metrics)

    s = f'teleproxy_dc_latency_seconds_sum{{dc="{dc}"}}'
    check(f"DC {dc} sum present",
          s in metrics)

    c = f'teleproxy_dc_latency_seconds_count{{dc="{dc}"}}'
    check(f"DC {dc} count present",
          c in metrics)

    f_line = f'teleproxy_dc_probe_failures_total{{dc="{dc}"}}'
    check(f"DC {dc} failures counter present",
          f_line in metrics)

    l_line = f'teleproxy_dc_latency_last_seconds{{dc="{dc}"}}'
    check(f"DC {dc} last latency gauge present",
          l_line in metrics)


# ── Histogram monotonicity ─────────────────────────────────────

print("\n=== Histogram structure ===")

for dc in range(1, 6):
    buckets = []
    for line in metrics.splitlines():
        tag = f'teleproxy_dc_latency_seconds_bucket{{dc="{dc}"'
        if tag in line:
            val = int(line.split()[-1])
            buckets.append(val)
    if buckets:
        mono = all(buckets[i] >= buckets[i - 1] for i in range(1, len(buckets)))
        check(f"DC {dc} buckets monotonically non-decreasing",
              mono,
              f"buckets: {buckets}")
    else:
        check(f"DC {dc} buckets monotonically non-decreasing",
              False, "no bucket lines found")


# ── Probe values ──────────────────────────────────────────────

print("\n=== Probe values ===")

total_count = 0
total_failures = 0
for dc in range(1, 6):
    cnt = parse_stat(stats, f"dc{dc}_probe_count")
    fail = parse_stat(stats, f"dc{dc}_probe_failures")
    last = parse_stat(stats, f"dc{dc}_probe_latency_last")
    cnt_val = int(cnt) if cnt else 0
    fail_val = int(fail) if fail else 0
    total_count += cnt_val
    total_failures += fail_val
    print(f"  DC {dc}: count={cnt_val} failures={fail_val} last={last}")

total_attempted = total_count + total_failures
check("at least one DC probe attempted",
      total_attempted > 0,
      f"total count={total_count} failures={total_failures}")


# ── Summary ───────────────────────────────────────────────────

print(f"\n{'=' * 40}")
print(f"Results: {passed} passed, {failed} failed")

if failed > 0:
    sys.exit(1)
print("All DC probe tests passed!")
