#!/usr/bin/env python3
"""Live connectivity test for a Teleproxy instance.

Tests a running Teleproxy by performing an obfuscated2 handshake via Telethon.
Designed for quick iteration against a production or staging proxy.

Usage:
    python3 tests/test_live_proxy.py [--host HOST] [--port PORT] [--secret SECRET]

Defaults target localhost:8444.
"""
import argparse
import asyncio
import os
import socket
import sys
import time


def test_tcp_connectivity(host: str, port: int, timeout: float = 5.0) -> bool:
    """Verify basic TCP connectivity to the proxy.

    Args:
        host: Proxy hostname or IP.
        port: Proxy port.
        timeout: Connection timeout in seconds.

    Returns:
        True if TCP connection succeeds.
    """
    print(f"[1/3] TCP connectivity to {host}:{port} ... ", end="", flush=True)
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        print("OK")
        return True
    except Exception as e:
        print(f"FAILED: {e}")
        return False


def test_telethon_obfs2(host: str, port: int, secret_hex: str,
                        timeout: float = 30.0) -> bool:
    """Connect via Telethon using obfuscated2 (dd-prefix) random padding.

    Args:
        host: Proxy hostname or IP.
        port: Proxy port.
        secret_hex: 32-char hex secret (without dd prefix).
        timeout: Connection timeout in seconds.

    Returns:
        True if the MTProto handshake succeeds or reaches the API layer.
    """
    print(f"[2/3] Telethon obfuscated2 (dd) connection ... ", end="", flush=True)

    try:
        from telethon import TelegramClient
        from telethon.network.connection import (
            ConnectionTcpMTProxyRandomizedIntermediate,
        )
    except ImportError:
        print("SKIP (telethon not installed)")
        return True

    async def _connect():
        client = TelegramClient(
            ":memory:",
            api_id=1,
            api_hash="b6b154c3707471f5339bd661645ed3d6",
            connection=ConnectionTcpMTProxyRandomizedIntermediate,
            proxy=(host, port, "dd" + secret_hex),
        )
        try:
            await asyncio.wait_for(client.connect(), timeout=timeout)
            connected = client.is_connected()
            return connected, None
        except Exception as e:
            err_str = str(e).lower()
            # If we got past the handshake to the API layer, the proxy works.
            if "auth" in err_str or "api_id" in err_str:
                return True, f"handshake OK, API rejected (expected): {e}"
            return False, str(e)
        finally:
            try:
                await client.disconnect()
            except Exception:
                pass

    ok, detail = asyncio.run(_connect())
    if ok:
        msg = "OK"
        if detail:
            msg += f" ({detail})"
        print(msg)
    else:
        print(f"FAILED: {detail}")
    return ok


DC_ADDRESSES = {
    1: "149.154.175.50",
    2: "149.154.167.51",
    3: "149.154.175.100",
    4: "149.154.167.91",
    5: "91.108.56.100",
}


def test_telethon_multiple_dcs(host: str, port: int, secret_hex: str,
                               timeout: float = 20.0) -> dict:
    """Test connectivity to multiple Telegram DCs through the proxy.

    Uses real DC IP addresses so Telethon can encode the correct DC target
    in the obfuscated2 handshake.

    Args:
        host: Proxy hostname or IP.
        port: Proxy port.
        secret_hex: 32-char hex secret (without dd prefix).
        timeout: Per-DC connection timeout in seconds.

    Returns:
        Dict mapping DC IDs to (success, detail) tuples.
    """
    print("[3/3] Multi-DC connectivity test ...", flush=True)

    try:
        from telethon import TelegramClient
        from telethon.network.connection import (
            ConnectionTcpMTProxyRandomizedIntermediate,
        )
        from telethon.sessions import StringSession
    except ImportError:
        print("  SKIP (telethon not installed)")
        return {}

    dc_results = {}

    async def _test_dc(dc_id: int):
        dc_ip = DC_ADDRESSES.get(dc_id, "149.154.167.51")
        client = TelegramClient(
            StringSession(),
            api_id=1,
            api_hash="b6b154c3707471f5339bd661645ed3d6",
            connection=ConnectionTcpMTProxyRandomizedIntermediate,
            proxy=(host, port, "dd" + secret_hex),
        )
        client.session.set_dc(dc_id, dc_ip, 443)
        try:
            await asyncio.wait_for(client.connect(), timeout=timeout)
            return True, "connected"
        except Exception as e:
            err_str = str(e).lower()
            if "auth" in err_str or "api_id" in err_str:
                return True, "handshake OK (API rejected as expected)"
            return False, str(e)
        finally:
            try:
                await client.disconnect()
            except Exception:
                pass

    async def _run_all():
        for dc_id in [1, 2, 3, 4, 5]:
            ok, detail = await _test_dc(dc_id)
            dc_results[dc_id] = (ok, detail)
            status = "OK" if ok else "FAILED"
            print(f"  DC{dc_id}: {status} — {detail}")

    asyncio.run(_run_all())
    return dc_results


def main():
    parser = argparse.ArgumentParser(description="Live Teleproxy connectivity test")
    parser.add_argument("--host", default="localhost",
                        help="Proxy hostname")
    parser.add_argument("--port", type=int, default=8444,
                        help="Proxy port")
    parser.add_argument("--secret", default="d7f04aa6631130af1a153e7a5e12c291",
                        help="16-byte hex secret (without dd/ee prefix)")
    parser.add_argument("--skip-multi-dc", action="store_true",
                        help="Skip multi-DC test")
    args = parser.parse_args()

    print(f"Testing Teleproxy at {args.host}:{args.port}")
    print(f"Secret: {args.secret}")
    print()

    results = []

    # Test 1: TCP
    results.append(test_tcp_connectivity(args.host, args.port))

    if not results[-1]:
        print("\nTCP connection failed — proxy is unreachable.")
        sys.exit(1)

    print()

    # Test 2: Telethon obfuscated2
    results.append(test_telethon_obfs2(args.host, args.port, args.secret))

    print()

    # Test 3: Multi-DC (optional)
    if not args.skip_multi_dc:
        dc_results = test_telethon_multiple_dcs(args.host, args.port, args.secret)
        if dc_results:
            failed_dcs = [dc for dc, (ok, _) in dc_results.items() if not ok]
            if failed_dcs:
                results.append(False)
                print(f"\n  FAILED DCs: {failed_dcs}")
            else:
                results.append(True)

    print()
    if all(results):
        print("ALL TESTS PASSED")
        sys.exit(0)
    else:
        print("SOME TESTS FAILED")
        sys.exit(1)


if __name__ == "__main__":
    main()
