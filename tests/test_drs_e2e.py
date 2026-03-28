#!/usr/bin/env python3
"""E2E test for Dynamic Record Sizing (DRS).

Connects to a DRS-enabled Teleproxy via TelethonFakeTLS with a real Telegram
session and calls get_me() to verify the full data path works correctly
with variable TLS record sizes.

Usage:
    python3 tests/test_drs_e2e.py \
        --host HOST --port PORT --secret SECRET \
        --domain DOMAIN --session SESSION_PATH

Environment variables (alternative to CLI args):
    TELEPROXY_HOST, TELEPROXY_PORT, TELEPROXY_SECRET, EE_DOMAIN,
    TGP_API_ID, TGP_API_HASH, TELETHON_SESSION
"""

import argparse
import asyncio
import os
import shutil
import sys
import tempfile


def _patch_telethon_faketls():
    """Patch TelethonFakeTLS bugs.

    1. read_server_hello: upstream only reads the first encrypted record,
       but the proxy computes HMAC over all records.
    2. FakeTLSStreamWriter: upstream never sends CCS (ChangeCipherSpec)
       before the first data record, but the proxy requires it.
    """
    import TelethonFakeTLS.FakeTLS.TLSInOut as tls_io

    # Fix 1: read all encrypted records in ServerHello
    async def _read_server_hello(self):
        buf = bytearray(await self.upstream.readexactly(133))
        while True:
            try:
                header = await asyncio.wait_for(
                    self.upstream.readexactly(5), timeout=0.5
                )
            except (asyncio.TimeoutError, EOFError):
                break
            buf += header
            if header[:3] != b"\x17\x03\x03":
                break
            rec_len = int.from_bytes(header[3:5], "big")
            buf += await self.upstream.readexactly(rec_len)
        return bytes(buf)

    tls_io.FakeTLSStreamReader.read_server_hello = _read_server_hello

    # Fix 2: send CCS before the first application data record.
    # FakeTLSStreamWriter uses __slots__=() so we can't add attributes.
    # Instead, wrap the write method with a closure that tracks state.
    _orig_write = tls_io.FakeTLSStreamWriter.write
    _ccs_sent_writers = set()

    def _writer_write_with_ccs(self, data, extra={}):
        if id(self) not in _ccs_sent_writers:
            _ccs_sent_writers.add(id(self))
            self.upstream.write(b"\x14\x03\x03\x00\x01\x01")
        return _orig_write(self, data, extra)

    tls_io.FakeTLSStreamWriter.write = _writer_write_with_ccs


async def run_test(host, port, secret, domain, session_path, api_id, api_hash):
    """Connect through Teleproxy and call get_me()."""
    from telethon import TelegramClient
    from TelethonFakeTLS import ConnectionTcpMTProxyFakeTLS

    _patch_telethon_faketls()

    proxy_secret = secret + domain.encode().hex()

    # Copy session to a temp file so we don't modify the original
    tmp_dir = tempfile.mkdtemp(prefix="drs_test_")
    tmp_session = os.path.join(tmp_dir, "session")
    shutil.copy2(session_path, tmp_session + ".session")

    try:
        client = TelegramClient(
            tmp_session,
            api_id=api_id,
            api_hash=api_hash,
            connection=ConnectionTcpMTProxyFakeTLS,
            proxy=(host, port, proxy_secret),
        )

        print(f"Connecting to proxy at {host}:{port} (domain={domain})...")
        await asyncio.wait_for(client.connect(), timeout=30)

        if not client.is_connected():
            print("FAIL: Client did not connect")
            return False

        print("Connected. Calling get_me()...")
        me = await asyncio.wait_for(client.get_me(), timeout=15)

        if me is None:
            print("FAIL: get_me() returned None")
            return False

        print(f"OK: get_me() returned user_id={me.id}, "
              f"username={me.username}")

        await client.disconnect()
        return True

    except Exception as e:
        print(f"FAIL: {type(e).__name__}: {e}")
        return False
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(description="DRS E2E test")
    parser.add_argument("--host", default=os.environ.get("TELEPROXY_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int,
                        default=int(os.environ.get("TELEPROXY_PORT", "443")))
    parser.add_argument("--secret",
                        default=os.environ.get("TELEPROXY_SECRET", ""))
    parser.add_argument("--domain",
                        default=os.environ.get("EE_DOMAIN", "google.com"))
    parser.add_argument("--session",
                        default=os.environ.get("TELETHON_SESSION", ""))
    parser.add_argument("--api-id", type=int,
                        default=int(os.environ.get("TGP_API_ID", "0")))
    parser.add_argument("--api-hash",
                        default=os.environ.get("TGP_API_HASH", ""))

    args = parser.parse_args()

    if not args.secret:
        print("ERROR: --secret or TELEPROXY_SECRET required")
        sys.exit(1)
    if not args.api_id or not args.api_hash:
        print("ERROR: --api-id/--api-hash or TGP_API_ID/TGP_API_HASH required")
        sys.exit(1)
    if not os.path.exists(args.session):
        print(f"ERROR: Session file not found: {args.session}")
        sys.exit(1)

    ok = asyncio.run(
        run_test(args.host, args.port, args.secret, args.domain,
                 args.session, args.api_id, args.api_hash)
    )
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
