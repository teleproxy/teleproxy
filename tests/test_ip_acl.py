"""IP ACL integration tests.

Run with a mode argument:
  python test_ip_acl.py blocked    — verify connections are rejected (from blocked IP)
  python test_ip_acl.py allowed    — verify connections succeed (from non-blocked IP)
"""
import socket
import sys
import os


def test_blocked_connection():
    """Test that TCP connections from a blocked IP are rejected on the proxy port."""
    print("Testing blocked connection on proxy port...")
    host = os.environ.get("TELEPROXY_HOST", "172.31.0.2")
    port = int(os.environ.get("TELEPROXY_PORT", 8443))

    rejected = 0
    attempts = 5

    for i in range(attempts):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((host, port))
            try:
                s.send(b"\x00")
                data = s.recv(1)
                if not data:
                    rejected += 1
                    print(f"  Attempt {i+1}: connection closed by proxy (blocked)")
                else:
                    print(f"  Attempt {i+1}: unexpected data received")
            except (ConnectionResetError, BrokenPipeError):
                rejected += 1
                print(f"  Attempt {i+1}: connection reset (blocked)")
            except socket.timeout:
                print(f"  Attempt {i+1}: timeout (unexpected)")
            finally:
                s.close()
        except ConnectionRefusedError:
            rejected += 1
            print(f"  Attempt {i+1}: connection refused (blocked)")
        except ConnectionResetError:
            rejected += 1
            print(f"  Attempt {i+1}: connection reset (blocked)")
        except socket.timeout:
            print(f"  Attempt {i+1}: timeout (unexpected)")
        except Exception as e:
            print(f"  Attempt {i+1}: {type(e).__name__}: {e}")

    if rejected >= attempts:
        print(f"Blocked connection test PASSED: {rejected}/{attempts} rejected")
        return True
    print(f"Blocked connection test FAILED: only {rejected}/{attempts} rejected")
    return False


def test_allowed_connection():
    """Test that a non-blocked IP can connect to the proxy port."""
    print("Testing non-blocked connection on proxy port...")
    host = os.environ.get("TELEPROXY_HOST", "172.31.0.2")
    port = int(os.environ.get("TELEPROXY_PORT", 8443))

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((host, port))
        # Connection accepted — proxy keeps it open waiting for protocol data
        s.close()
        print("  Non-blocked connection accepted - PASS")
        return True
    except Exception as e:
        print(f"  Non-blocked connection failed: {e} - FAIL")
        return False


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: test_ip_acl.py <blocked|allowed>")
        sys.exit(2)

    mode = sys.argv[1]
    print(f"Starting IP ACL tests (mode={mode})...", flush=True)

    if mode == "blocked":
        ok = test_blocked_connection()
    elif mode == "allowed":
        ok = test_allowed_connection()
    else:
        print(f"Unknown mode: {mode}")
        sys.exit(2)

    sys.exit(0 if ok else 1)
