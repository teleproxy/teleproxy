import socket
import time
import requests
import sys
import os

def test_http_stats():
    """Test that the HTTP stats endpoint is accessible."""
    print("Testing HTTP stats...")
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    stats_port = os.environ.get("TELEPROXY_STATS_PORT", "8888")
    url = f"http://{host}:{stats_port}/stats"
    try:
        ip = socket.gethostbyname(host)
        print(f"Resolved {host} to {ip}")
    except Exception as e:
        print(f"Could not resolve {host}: {e}")

    for i in range(5):
        try:
            response = requests.get(url, timeout=3)
            if response.status_code == 200:
                print(f"HTTP stats OK: {response.text[:50]}...")
                return True
            else:
                print(f"HTTP stats failed: {response.status_code}")
        except Exception as e:
            print(f"HTTP stats exception (attempt {i+1}): {e}")
        time.sleep(1)
    return False

def test_prometheus_metrics():
    """Test that the Prometheus metrics endpoint returns valid exposition format."""
    print("Testing Prometheus metrics...")
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    stats_port = os.environ.get("TELEPROXY_STATS_PORT", "8888")
    url = f"http://{host}:{stats_port}/metrics"

    for i in range(5):
        try:
            response = requests.get(url, timeout=3)
            if response.status_code != 200:
                print(f"Prometheus metrics failed: {response.status_code}")
                time.sleep(1)
                continue

            body = response.text

            # Verify Prometheus exposition format markers
            assert "# HELP" in body, "Missing # HELP lines"
            assert "# TYPE" in body, "Missing # TYPE lines"

            # Verify key metrics exist
            required_metrics = [
                "teleproxy_queries_total",
                "teleproxy_ext_connections",
                "teleproxy_uptime_seconds",
                "teleproxy_workers",
                "teleproxy_forwarded_queries_total",
                "teleproxy_active_connections",
            ]
            for metric in required_metrics:
                assert metric in body, f"Missing metric: {metric}"

            # Verify metric values are numeric
            for line in body.strip().split("\n"):
                if line.startswith("#") or not line.strip():
                    continue
                parts = line.split()
                assert len(parts) == 2, f"Bad metric line: {line}"
                name, value = parts
                try:
                    float(value)
                except ValueError:
                    raise AssertionError(f"Non-numeric value for {name}: {value}")

            # Verify counter and gauge types are declared
            assert "# TYPE teleproxy_queries_total counter" in body
            assert "# TYPE teleproxy_uptime_seconds gauge" in body

            print(f"Prometheus metrics OK: {len(body)} bytes, "
                  f"{sum(1 for l in body.split(chr(10)) if not l.startswith('#') and l.strip())} metrics")
            return True
        except AssertionError as e:
            print(f"Prometheus metrics assertion failed: {e}")
            return False
        except Exception as e:
            print(f"Prometheus metrics exception (attempt {i+1}): {e}")
        time.sleep(1)
    return False


def test_mtproto_port():
    """Test that the MTProto port accepts TCP connections."""
    print("Testing MTProto port...")
    host = os.environ.get("TELEPROXY_HOST", "teleproxy")
    port = int(os.environ.get("TELEPROXY_PORT", 443))
    try:
        ip = socket.gethostbyname(host)
        print(f"Connecting to {ip}:{port}")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((ip, port))
        s.close()
        print("MTProto port OK")
        return True
    except Exception as e:
        print(f"MTProto port exception: {e}")
        return False

def check_upstream_connectivity():
    """Check if we can connect to Telegram's DCs (informational only)."""
    targets = [
        ("149.154.167.50", 443),
        ("149.154.167.50", 8888),
        ("91.108.4.166", 8888)
    ]
    
    for dc_ip, dc_port in targets:
        print(f"Checking upstream connectivity to Telegram DC {dc_ip}:{dc_port}...")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((dc_ip, dc_port))
            s.close()
            print(f"Upstream connectivity to Telegram DC {dc_ip}:{dc_port} OK")
        except Exception as e:
            print(f"WARNING: Could not connect to Telegram DC {dc_ip}:{dc_port}: {e}")
            print("This indicates a network issue (ISP blocking, firewall, etc.)")
            if dc_port == 8888:
                print("Teleproxy often uses port 8888 to connect to DCs. If this is blocked, proxy will fail.")

if __name__ == "__main__":
    print("Starting tests...", flush=True)
    
    # Check upstream connectivity first (informational)
    check_upstream_connectivity()

    # Small buffer — docker-compose healthcheck ensures the proxy is ready
    time.sleep(2)
    
    stats_ok = test_http_stats()
    metrics_ok = test_prometheus_metrics()
    mtproto_ok = test_mtproto_port()

    failed = []
    if not mtproto_ok:
        failed.append("MTProto port")
    if not stats_ok:
        failed.append("HTTP stats")
    if not metrics_ok:
        failed.append("Prometheus metrics")

    if failed:
        print(f"Tests FAILED: {', '.join(failed)}")
        sys.exit(1)
    else:
        print("Tests passed!")
        sys.exit(0)
