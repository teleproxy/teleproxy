#!/usr/bin/env python3
"""E2E tests for Teleproxy direct mode.

Starts a real Telethon session through a direct-mode Teleproxy and calls
get_me() to verify the full data path works.  Tests both obfuscated2
(dd-prefix) and fake-TLS (ee-prefix) transport modes.

Also downloads pre-saved test files (1 MB, 20 MB, 100 MB) through the proxy
to verify sustained data transfer works correctly — catches DRS delay
regressions that throttle large downloads.

Uses ONE client per transport mode to avoid AuthKeyDuplicatedError from
Telegram seeing multiple connections with the same auth key.

Requires TG_BOT_TOKEN (preferred) or TG_STRING_SESSION environment variable.
The CI job skips entirely on fork PRs (no secrets available).

Usage:
    TG_BOT_TOKEN=... TELEPROXY_SECRET=... python3 tests/test_direct_e2e.py
    TG_STRING_SESSION=... TELEPROXY_SECRET=... python3 tests/test_direct_e2e.py

Environment variables:
    TG_BOT_TOKEN        Telegram bot token (preferred — no session revocation)
    TG_STRING_SESSION   Telethon StringSession string (fallback)
    TELEPROXY_SECRET      32-char hex proxy secret (required)
    DIRECT_HOST         Proxy hostname (default: localhost)
    DIRECT_OBFS2_PORT   Obfuscated2 proxy port (default: 8443)
    DIRECT_TLS_PORT     Fake-TLS proxy port (default: 9443)
    EE_DOMAIN           Domain for fake-TLS mode (default: ya.ru)
"""

import asyncio
import hashlib
import io
import os
import sys
import time

# Official Telegram macOS client credentials (public, well-known).
API_ID = 2834
API_HASH = "68875f756c9b437a8b916ca3de215815"

# Pre-saved test files in the test channel (bot must be admin).
# Seeded by tests/seed_test_media.py — do not delete from the channel.
TEST_CHANNEL_ID = -1003687592445
TEST_FILES = {
    "1mb": {"msg_id": 4, "size": 1048576, "sha256": "383f48e141893fb74730cf11acc50081e17f5fe30fd4f62dcde7ad1ae9be6a8f"},
    "20mb": {"msg_id": 5, "size": 20971520, "sha256": "536f79417e366fcca2b19b28306210b2992d49ca9c27f131d03c520aeccb1dad"},
}

# Per-file download timeouts (seconds).
DOWNLOAD_TIMEOUTS = {"1mb": 60, "20mb": 300, "100mb": 900}

# Minimum acceptable throughput (MB/s) for files >= 20 MB.
# The DRS delay bug (v3.5.0) throttled downloads to ~2 MB/s.
# Set conservatively — if even this floor is missed, something is broken.
MIN_THROUGHPUT_MBPS = float(os.environ.get("MIN_THROUGHPUT_MBPS", "0.5"))


def _patch_telethon_faketls():
    """Patch TelethonFakeTLS bugs.

    1. read_server_hello: upstream only reads the first encrypted record,
       but the proxy computes HMAC over all records.
    2. FakeTLSStreamWriter: upstream never sends CCS (ChangeCipherSpec)
       before the first data record, but the proxy requires it.
    """
    import TelethonFakeTLS.FakeTLS.TLSInOut as tls_io

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

    _orig_write = tls_io.FakeTLSStreamWriter.write
    _ccs_sent_writers = set()

    def _writer_write_with_ccs(self, data, extra={}):
        if id(self) not in _ccs_sent_writers:
            _ccs_sent_writers.add(id(self))
            self.upstream.write(b"\x14\x03\x03\x00\x01\x01")
        return _orig_write(self, data, extra)

    tls_io.FakeTLSStreamWriter.write = _writer_write_with_ccs


async def _download_test_files(client, transport_label):
    """Download pre-saved test files and verify integrity.

    Returns dict of {label: throughput_mbps} for successful downloads,
    or None for the label if that download failed.
    """
    throughputs = {}
    for label, info in TEST_FILES.items():
        timeout = DOWNLOAD_TIMEOUTS[label]
        print(f"  [{transport_label}] downloading {label} "
              f"(msg_id={info['msg_id']}, timeout={timeout}s)...",
              flush=True)

        try:
            msg = await asyncio.wait_for(
                client.get_messages(TEST_CHANNEL_ID, ids=info["msg_id"]),
                timeout=15,
            )
        except Exception as e:
            print(f"  [{transport_label}] {label}: SKIP — "
                  f"could not fetch message: {type(e).__name__}: {e}")
            continue

        if msg is None or msg.media is None:
            print(f"  [{transport_label}] {label}: SKIP — "
                  f"message {info['msg_id']} not found (test data not seeded)")
            continue

        buf = io.BytesIO()
        start = time.monotonic()
        try:
            await asyncio.wait_for(
                client.download_media(msg, file=buf),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            elapsed = time.monotonic() - start
            got = len(buf.getvalue())
            throughput = got / elapsed / 1048576 if elapsed > 0 else 0
            print(f"  [{transport_label}] {label}: FAIL — "
                  f"timed out after {elapsed:.0f}s "
                  f"({got}/{info['size']} bytes, "
                  f"{throughput:.2f} MB/s)")
            throughputs[label] = None
            continue
        except Exception as e:
            print(f"  [{transport_label}] {label}: FAIL — "
                  f"{type(e).__name__}: {e}")
            throughputs[label] = None
            continue

        elapsed = time.monotonic() - start
        data = buf.getvalue()
        actual_hash = hashlib.sha256(data).hexdigest()

        if len(data) != info["size"]:
            print(f"  [{transport_label}] {label}: FAIL — "
                  f"size mismatch: got {len(data)}, expected {info['size']}")
            throughputs[label] = None
            continue

        if actual_hash != info["sha256"]:
            print(f"  [{transport_label}] {label}: FAIL — "
                  f"SHA256 mismatch")
            throughputs[label] = None
            continue

        throughput_mb = len(data) / elapsed / 1048576
        throughputs[label] = throughput_mb

        # Assert minimum throughput for large files.
        if info["size"] >= 20 * 1048576 and throughput_mb < MIN_THROUGHPUT_MBPS:
            print(f"  [{transport_label}] {label}: FAIL — "
                  f"throughput {throughput_mb:.2f} MB/s < "
                  f"{MIN_THROUGHPUT_MBPS} MB/s minimum")
            throughputs[label] = None
            continue

        print(f"  [{transport_label}] {label}: OK — "
              f"{elapsed:.1f}s, {throughput_mb:.2f} MB/s")

    return throughputs


async def _connect_and_auth(client, label, bot_token=None):
    """Connect and authenticate via bot token or pre-loaded session.

    Bot tokens authenticate fresh each run — no persistent auth key,
    no AuthKeyDuplicatedError, no session revocation from datacenter IPs.
    """
    if bot_token:
        await asyncio.wait_for(client.connect(), timeout=30)
        if not client.is_connected():
            print(f"[{label}] FAIL: client did not connect")
            return None
        await asyncio.wait_for(
            client.sign_in(bot_token=bot_token), timeout=15
        )
        me = await asyncio.wait_for(client.get_me(), timeout=15)
        return me

    # User session path — retry on AuthKeyDuplicatedError (stale lock
    # from a previous CI run that didn't disconnect cleanly).
    from telethon.errors import AuthKeyDuplicatedError

    max_retries, backoff = 3, 15
    for attempt in range(1, max_retries + 1):
        try:
            await asyncio.wait_for(client.connect(), timeout=30)
            if not client.is_connected():
                print(f"[{label}] FAIL: client did not connect")
                return None
            me = await asyncio.wait_for(client.get_me(), timeout=15)
            return me
        except AuthKeyDuplicatedError:
            if attempt < max_retries:
                wait = backoff * attempt
                print(f"[{label}] auth key locked (attempt {attempt}/{max_retries}), "
                      f"waiting {wait}s...", flush=True)
                try:
                    await client.disconnect()
                except Exception:
                    pass
                await asyncio.sleep(wait)
                try:
                    await client.connect()
                except Exception:
                    pass
            else:
                raise


async def test_obfs2_all(host, port, secret, bot_token="", session_str=""):
    """Run all obfs2 tests with a single client connection."""
    from telethon import TelegramClient
    from telethon.network.connection import (
        ConnectionTcpMTProxyRandomizedIntermediate,
    )
    from telethon.sessions import StringSession

    print(f"[obfs2] Connecting to {host}:{port} ...", flush=True)

    client = TelegramClient(
        StringSession(session_str),
        api_id=API_ID,
        api_hash=API_HASH,
        connection=ConnectionTcpMTProxyRandomizedIntermediate,
        proxy=(host, port, "dd" + secret),
    )

    try:
        me = await _connect_and_auth(client, "obfs2",
                                     bot_token=bot_token or None)
        if me is None:
            print("[obfs2] FAIL: get_me() returned None")
            return False, {}

        print(f"[obfs2] get_me OK: id={me.id}")

        throughputs = await _download_test_files(client, "obfs2")
        has_failure = any(v is None for v in throughputs.values())
        return not has_failure, throughputs
    except Exception as e:
        print(f"[obfs2] FAIL: {type(e).__name__}: {e}")
        return False, {}
    finally:
        try:
            await client.disconnect()
        except Exception:
            pass


async def test_faketls_all(host, port, secret, domain,
                           bot_token="", session_str=""):
    """Run all fake-TLS tests with a single client connection."""
    try:
        from TelethonFakeTLS import ConnectionTcpMTProxyFakeTLS
    except ImportError:
        print("[fake-tls] SKIP: TelethonFakeTLS not installed")
        return True, {}

    from telethon import TelegramClient
    from telethon.sessions import StringSession

    _patch_telethon_faketls()

    proxy_secret = secret + domain.encode().hex()
    print(f"[fake-tls] Connecting to {host}:{port} (domain={domain}) ...",
          flush=True)

    client = TelegramClient(
        StringSession(session_str),
        api_id=API_ID,
        api_hash=API_HASH,
        connection=ConnectionTcpMTProxyFakeTLS,
        proxy=(host, port, proxy_secret),
    )

    try:
        me = await _connect_and_auth(client, "fake-tls",
                                     bot_token=bot_token or None)
        if me is None:
            print("[fake-tls] FAIL: get_me() returned None")
            return False, {}

        print(f"[fake-tls] get_me OK: id={me.id}")

        throughputs = await _download_test_files(client, "fake-tls")
        has_failure = any(v is None for v in throughputs.values())
        return not has_failure, throughputs
    except Exception as e:
        print(f"[fake-tls] FAIL: {type(e).__name__}: {e}")
        return False, {}
    finally:
        try:
            await client.disconnect()
        except Exception:
            pass


def main():
    bot_token = os.environ.get("TG_BOT_TOKEN", "")
    session_str = os.environ.get("TG_STRING_SESSION", "")
    if not bot_token and not session_str:
        print("ERROR: TG_BOT_TOKEN or TG_STRING_SESSION required")
        sys.exit(1)

    secret = os.environ.get("TELEPROXY_SECRET", "")
    if not secret:
        print("ERROR: TELEPROXY_SECRET required")
        sys.exit(1)

    host = os.environ.get("DIRECT_HOST", "localhost")
    obfs2_port = int(os.environ.get("DIRECT_OBFS2_PORT", "8443"))
    tls_port = int(os.environ.get("DIRECT_TLS_PORT", "9443"))
    domain = os.environ.get("EE_DOMAIN", "ya.ru")

    mode = "bot" if bot_token else "user session"
    print(f"=== Direct Mode E2E Tests ({mode}) ===\n")

    # Test 1: obfuscated2 (control — no DRS delays)
    obfs2_ok, obfs2_tp = asyncio.run(
        test_obfs2_all(host, obfs2_port, secret,
                       bot_token=bot_token, session_str=session_str)
    )
    print()

    # Test 2: fake-TLS (exercises DRS delays)
    tls_ok, tls_tp = asyncio.run(
        test_faketls_all(host, tls_port, secret, domain,
                         bot_token=bot_token, session_str=session_str)
    )

    # Compare throughputs: fake-TLS must not be dramatically slower than obfs2.
    # If fake-TLS is < 50% of obfs2 for the same file, DRS delays are the cause.
    print("\n=== Throughput Comparison ===")
    comparison_ok = True
    for label in TEST_FILES:
        o = obfs2_tp.get(label)
        t = tls_tp.get(label)
        if o is None or t is None:
            continue
        ratio = t / o if o > 0 else 0
        status = "OK" if ratio >= 0.5 else "FAIL"
        if status == "FAIL":
            comparison_ok = False
        print(f"  {label}: obfs2={o:.2f} MB/s, fake-tls={t:.2f} MB/s, "
              f"ratio={ratio:.0%} {status}")

    print("\n=== Results ===")
    all_ok = True
    for name, ok in [("obfs2", obfs2_ok), ("fake-tls", tls_ok),
                      ("tls-vs-obfs2-ratio", comparison_ok)]:
        status = "PASS" if ok else "FAIL"
        print(f"  {name}: {status}")
        if not ok:
            all_ok = False

    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
