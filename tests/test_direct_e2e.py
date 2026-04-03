#!/usr/bin/env python3
"""E2E tests for Teleproxy direct mode.

Starts a real Telethon session through a direct-mode Teleproxy and calls
get_me() to verify the full data path works.  Tests both obfuscated2
(dd-prefix) and fake-TLS (ee-prefix) transport modes.

Also downloads pre-saved test files through the proxy to verify sustained
data transfer works correctly — catches DRS delay regressions that throttle
large downloads.  Small files (~50-100 KB) are downloaded in rapid succession
to catch sticker/icon loading regressions where DRS delays re-apply between
quick sequential requests.

Uses ONE client per transport mode to avoid AuthKeyDuplicatedError from
Telegram seeing multiple connections with the same auth key.

Supports three auth modes (checked in order):
  1. TG_TEST_SESSION  — user session on Telegram's test DC (preferred for CI)
  2. TG_BOT_TOKEN     — bot token on production DC
  3. TG_STRING_SESSION — user session on production DC (last resort)

Test DC sessions route through the proxy via dc_id + 10000, so the proxy's
direct_dc_lookup() maps to the test DC table (149.154.167.40 etc.).

Usage:
    TG_TEST_SESSION=... TELEPROXY_SECRET=... python3 tests/test_direct_e2e.py
    TG_BOT_TOKEN=... TELEPROXY_SECRET=... python3 tests/test_direct_e2e.py

Environment variables:
    TG_TEST_SESSION     Telethon StringSession for test DC (preferred)
    TG_BOT_TOKEN        Telegram bot token (production DC)
    TG_STRING_SESSION   Telethon StringSession string (production DC)
    TELEPROXY_SECRET    32-char hex proxy secret (required)
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
import urllib.request

# Custom API credentials avoid anti-abuse when user sessions are used from
# datacenter IPs.  Falls back to public macOS client ID for bot token auth.
API_ID = int(os.environ.get("TG_API_ID", "2834"))
API_HASH = os.environ.get("TG_API_HASH", "68875f756c9b437a8b916ca3de215815")

# Pre-saved test files in the test channel (bot must be admin).
# Seeded by tests/seed_test_media.py — do not delete from the channel.
#
# Production DC (bot token):
PROD_CHANNEL_ID = -1003687592445
PROD_TEST_FILES = {
    "1mb": {"msg_id": 4, "size": 1048576, "sha256": "383f48e141893fb74730cf11acc50081e17f5fe30fd4f62dcde7ad1ae9be6a8f"},
}

# Test DC (user session) — seeded separately, test DC data may be wiped.
# Re-seed with: .venv/bin/python tests/seed_test_media.py --test-dc
#
# Small files (50kb, 100kb) exercise the DRS slow-start phase where
# inter-record delays are applied.  If the 30s delay reset is broken,
# rapid sequential small downloads will fail or be very slow.
TEST_DC_CHANNEL_ID = int(os.environ.get("TEST_DC_CHANNEL_ID", "-1008005586427"))
TEST_DC_FILES = {
    "50kb": {"msg_id": 2, "size": 51200, "sha256": "3d321cb085962e4e67f88ebcf8582213f8ab33f3d435078fd9916aa966091e42"},
    "100kb": {"msg_id": 3, "size": 102400, "sha256": "4d128dd82d4611d79c11e66db430cb7c8a2cec8e03f2c8c9dbd85782ad90ce00"},
    "1mb": {"msg_id": 4, "size": 1048576, "sha256": "397f45f514848283f5efc1c3c173e06cbc42bd7a391a295c31f17e7ed69e8f8d"},
    "20mb": {"msg_id": 5, "size": 20971520, "sha256": "4a378f3b944021f30ad3c038e979b0a6af014663195c1f318838a70c356a6804"},
}

# Per-file download timeouts (seconds).
DOWNLOAD_TIMEOUTS = {"50kb": 30, "100kb": 30, "1mb": 60, "20mb": 300, "100mb": 900}

# Small files for rapid sequential download test (sticker/icon scenario).
# The DRS 30s delay reset bug (upstream v3.5.3) caused delays to re-apply
# between quick sequential small downloads, breaking sticker/icon loading.
SMALL_FILE_LABELS = ("50kb", "100kb")

# Minimum acceptable throughput (MB/s) for files >= 20 MB.
# The DRS delay bug (v3.5.0) throttled downloads to ~2 MB/s.
# Set conservatively — if even this floor is missed, something is broken.
# Test DC is inherently slower (~0.2 MB/s) than production (~2+ MB/s).
PROD_MIN_THROUGHPUT_MBPS = float(os.environ.get("MIN_THROUGHPUT_MBPS", "0.5"))
TEST_DC_MIN_THROUGHPUT_MBPS = float(os.environ.get("MIN_THROUGHPUT_MBPS", "0.1"))


def _patch_mtproxy_test_dc():
    """Patch MTProxy header to add 10000 to dc_id.

    The proxy uses dc_id >= 10000 to route to test DCs. Telethon encodes
    the session's dc_id (2) in the MTProxy header, but we need 10002.
    This patch transparently adds the offset so the proxy routes to the
    correct test DC without modifying the session itself.
    """
    from telethon.network.connection.tcpmtproxy import MTProxyIO

    _orig = MTProxyIO.init_header

    @staticmethod
    def _patched(secret, dc_id, packet_codec):
        return _orig(secret, dc_id + 10000, packet_codec)

    MTProxyIO.init_header = _patched


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
        if not info["sha256"]:
            continue  # Not yet seeded
        if label in SMALL_FILE_LABELS:
            continue  # Tested separately in _download_small_files
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


async def _download_small_files(client, transport_label):
    """Download small files in rapid succession and verify integrity.

    Exercises the DRS slow-start phase where inter-record delays are applied.
    If delays fire on every record instead of once per burst, these small
    files will be measurably slower on fake-TLS than on obfs2.

    Returns (all_ok, total_elapsed_seconds).
    """
    small_files = {k: v for k, v in TEST_FILES.items()
                   if k in SMALL_FILE_LABELS and v["sha256"]}
    if not small_files:
        print(f"  [{transport_label}] small files: SKIP — not seeded")
        return True, 0.0

    print(f"  [{transport_label}] downloading {len(small_files)} small files "
          f"in rapid succession...", flush=True)

    all_ok = True
    total_elapsed = 0.0
    for label, info in small_files.items():
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
                  f"message {info['msg_id']} not found (not seeded)")
            continue

        buf = io.BytesIO()
        start = time.monotonic()
        try:
            await asyncio.wait_for(
                client.download_media(msg, file=buf),
                timeout=DOWNLOAD_TIMEOUTS.get(label, 30),
            )
        except Exception as e:
            print(f"  [{transport_label}] {label}: FAIL — "
                  f"{type(e).__name__}: {e}")
            all_ok = False
            continue

        elapsed = time.monotonic() - start
        total_elapsed += elapsed
        data = buf.getvalue()
        actual_hash = hashlib.sha256(data).hexdigest()

        if len(data) != info["size"]:
            print(f"  [{transport_label}] {label}: FAIL — "
                  f"size mismatch: got {len(data)}, expected {info['size']}")
            all_ok = False
            continue

        if actual_hash != info["sha256"]:
            print(f"  [{transport_label}] {label}: FAIL — "
                  f"SHA256 mismatch: got {actual_hash[:16]}..., "
                  f"expected {info['sha256'][:16]}...")
            all_ok = False
            continue

        print(f"  [{transport_label}] {label}: OK — "
              f"{len(data)} bytes, {elapsed:.2f}s, SHA256 verified")

    return all_ok, total_elapsed


def _check_proxy_stats(stats_port):
    """Query proxy stats endpoint and verify direct mode health.

    Returns (ok, details_dict).
    """
    host = os.environ.get("DIRECT_HOST", "localhost")
    url = f"http://{host}:{stats_port}/stats"
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            text = resp.read().decode()
    except Exception as e:
        print(f"  stats: SKIP — could not reach {url}: {e}")
        return True, {}

    stats = {}
    for line in text.splitlines():
        parts = line.split("\t", 1)
        if len(parts) == 2:
            try:
                stats[parts[0]] = int(parts[1])
            except ValueError:
                try:
                    stats[parts[0]] = float(parts[1])
                except ValueError:
                    stats[parts[0]] = parts[1]

    details = {}
    ok = True

    # direct_dc_connections_failed must be 0
    failed = stats.get("direct_dc_connections_failed", 0)
    details["dc_connect_failures"] = failed
    if failed > 0:
        print(f"  stats: FAIL — direct_dc_connections_failed={failed}")
        ok = False

    # Connection counters must be consistent
    created = stats.get("direct_dc_connections_created", 0)
    active = stats.get("direct_dc_connections_active", 0)
    details["dc_connections_created"] = created
    details["dc_connections_active"] = active
    if active > created:
        print(f"  stats: FAIL — active ({active}) > created ({created})")
        ok = False

    dc_closed = stats.get("direct_dc_connections_dc_closed", 0)
    details["dc_connections_dc_closed"] = dc_closed

    retries = stats.get("direct_dc_retries", 0)
    details["dc_retries"] = retries

    if ok:
        print(f"  stats: OK — created={created}, active={active}, "
              f"failed={failed}, dc_closed={dc_closed}, retries={retries}")

    return ok, details


def _check_drs_delay_stats(stats_port):
    """Verify DRS delays are bounded after real file downloads.

    With per-burst delays (DRS_DELAY_RECORDS), the vast majority of records
    should skip the delay.  If delays_applied is a large fraction of total
    records, the per-record delay bug has regressed.

    Returns True if the ratio is healthy or if no data was transferred.
    """
    host = os.environ.get("DIRECT_HOST", "localhost")
    url = f"http://{host}:{stats_port}/stats"
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            text = resp.read().decode()
    except Exception as e:
        print(f"  SKIP — could not reach {url}: {e}")
        return True

    applied = skipped = 0
    for line in text.splitlines():
        parts = line.split("\t", 1)
        if len(parts) != 2:
            continue
        if parts[0] == "drs_delays_applied":
            applied = int(parts[1])
        elif parts[0] == "drs_delays_skipped":
            skipped = int(parts[1])

    total = applied + skipped
    if total == 0:
        print("  SKIP — no DRS delay decisions recorded")
        return True

    skip_pct = skipped * 100 // total
    print(f"  applied={applied}, skipped={skipped}, "
          f"total={total}, skip_rate={skip_pct}%")

    # With per-burst delays, skip rate should be very high (>80%).
    # The old per-record delay code would show skip rates of ~30-50%
    # because delays fired on every record during slow-start tail.
    if skip_pct < 80:
        print(f"  FAIL — skip rate {skip_pct}% < 80% "
              f"(DRS delays firing too often)")
        return False

    print(f"  OK — {skip_pct}% of delay decisions skipped")
    return True


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


async def test_obfs2_all(host, port, secret, bot_token="", session_str="",
                        test_files=None):
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

        if test_files:
            throughputs = await _download_test_files(client, "obfs2")
            small_ok, small_time = await _download_small_files(client, "obfs2")
        else:
            throughputs = {}
            small_ok, small_time = True, 0.0
        has_failure = any(v is None for v in throughputs.values())
        return not has_failure and small_ok, throughputs, small_time
    except Exception as e:
        print(f"[obfs2] FAIL: {type(e).__name__}: {e}")
        return False, {}, 0.0
    finally:
        try:
            await client.disconnect()
        except Exception:
            pass


async def test_faketls_all(host, port, secret, domain,
                           bot_token="", session_str="", test_files=None):
    """Run all fake-TLS tests with a single client connection."""
    try:
        from TelethonFakeTLS import ConnectionTcpMTProxyFakeTLS
    except ImportError:
        print("[fake-tls] SKIP: TelethonFakeTLS not installed")
        return True, {}, 0.0

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
            return False, {}, 0.0

        print(f"[fake-tls] get_me OK: id={me.id}")

        if test_files:
            throughputs = await _download_test_files(client, "fake-tls")
            small_ok, small_time = await _download_small_files(client, "fake-tls")
        else:
            throughputs = {}
            small_ok, small_time = True, 0.0
        has_failure = any(v is None for v in throughputs.values())
        return not has_failure and small_ok, throughputs, small_time
    except Exception as e:
        print(f"[fake-tls] FAIL: {type(e).__name__}: {e}")
        return False, {}, 0.0
    finally:
        try:
            await client.disconnect()
        except Exception:
            pass


def main():
    test_session = os.environ.get("TG_TEST_SESSION", "")
    bot_token = os.environ.get("TG_BOT_TOKEN", "")
    session_str = os.environ.get("TG_STRING_SESSION", "")

    if not test_session and not bot_token and not session_str:
        print("ERROR: TG_TEST_SESSION, TG_BOT_TOKEN, or "
              "TG_STRING_SESSION required")
        sys.exit(1)

    secret = os.environ.get("TELEPROXY_SECRET", "")
    if not secret:
        print("ERROR: TELEPROXY_SECRET required")
        sys.exit(1)

    host = os.environ.get("DIRECT_HOST", "localhost")
    obfs2_port = int(os.environ.get("DIRECT_OBFS2_PORT", "8443"))
    tls_port = int(os.environ.get("DIRECT_TLS_PORT", "9443"))
    socks5_port_str = os.environ.get("DIRECT_SOCKS5_PORT", "")
    socks5_stats_port = os.environ.get("DIRECT_SOCKS5_STATS_PORT", "")
    domain = os.environ.get("EE_DOMAIN", "ya.ru")

    # Determine auth mode and select test files accordingly.
    if test_session:
        mode = "test DC session"
        session_str = test_session
        bot_token = ""
        _patch_mtproxy_test_dc()
        test_files = TEST_DC_FILES
        channel_id = TEST_DC_CHANNEL_ID
        min_tp = TEST_DC_MIN_THROUGHPUT_MBPS
    elif bot_token:
        mode = "bot"
        test_files = PROD_TEST_FILES
        channel_id = PROD_CHANNEL_ID
        min_tp = PROD_MIN_THROUGHPUT_MBPS
    else:
        mode = "user session"
        test_files = PROD_TEST_FILES
        channel_id = PROD_CHANNEL_ID
        min_tp = PROD_MIN_THROUGHPUT_MBPS

    # Update the globals used by download helper.
    global TEST_FILES, TEST_CHANNEL_ID, MIN_THROUGHPUT_MBPS
    TEST_FILES = test_files
    TEST_CHANNEL_ID = channel_id
    MIN_THROUGHPUT_MBPS = min_tp

    print(f"=== Direct Mode E2E Tests ({mode}) ===\n")

    # Test 1: obfuscated2 (control — no DRS delays)
    obfs2_ok, obfs2_tp, obfs2_small_time = asyncio.run(
        test_obfs2_all(host, obfs2_port, secret,
                       bot_token=bot_token, session_str=session_str,
                       test_files=test_files)
    )
    print()

    # Test 2: fake-TLS (exercises DRS delays)
    tls_ok, tls_tp, tls_small_time = asyncio.run(
        test_faketls_all(host, tls_port, secret, domain,
                         bot_token=bot_token, session_str=session_str,
                         test_files=test_files)
    )

    # Test 3: obfs2 through SOCKS5 upstream proxy (optional)
    socks5_ok = True
    if socks5_port_str:
        socks5_port = int(socks5_port_str)
        print()
        socks5_ok, socks5_tp, _ = asyncio.run(
            test_obfs2_all(host, socks5_port, secret,
                           bot_token=bot_token, session_str=session_str,
                           test_files=test_files)
        )
        # Relabel output
        for line_tp in socks5_tp:
            print(f"[socks5] {line_tp}: {socks5_tp[line_tp]:.2f} MB/s"
                  if socks5_tp[line_tp] else "")
    else:
        print("\n[socks5] SKIP — DIRECT_SOCKS5_PORT not set")

    # Compare throughputs: fake-TLS must not be dramatically slower than obfs2.
    # If fake-TLS is < 50% of obfs2 for the same file, DRS delays are the cause.
    print("\n=== Throughput Comparison ===")
    comparison_ok = True
    for label in test_files:
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

    # Small file timing comparison: fake-TLS should not be dramatically slower
    # than obfs2 for small files.  The DRS delay bug (v3.5.0) caused fake-TLS
    # to add hundreds of ms of artificial delays when loading small assets
    # like avatars and thumbnails.  With per-burst delays, the overhead is
    # negligible.
    print("\n=== Small File Timing ===")
    small_timing_ok = True
    if obfs2_small_time > 0 and tls_small_time > 0:
        ratio = tls_small_time / obfs2_small_time
        status = "OK" if ratio < 3.0 else "FAIL"
        if status == "FAIL":
            small_timing_ok = False
        print(f"  obfs2={obfs2_small_time:.2f}s, "
              f"fake-tls={tls_small_time:.2f}s, "
              f"ratio={ratio:.1f}x {status}")
    else:
        print("  SKIP — no small file timing data")

    # DRS delay stats: after real file downloads, verify the proxy didn't
    # apply excessive inter-record delays.  With per-burst delays, most
    # records should skip the delay (drs_delays_skipped >> drs_delays_applied).
    tls_stats_port = os.environ.get("DIRECT_TLS_STATS_PORT", "9888")
    print("\n=== DRS Delay Stats ===")
    drs_ok = _check_drs_delay_stats(tls_stats_port)

    # Stats-based health verification on both proxy instances.
    obfs2_stats_port = os.environ.get("DIRECT_OBFS2_STATS_PORT", "8888")

    print("\n=== Proxy Health (stats) ===")
    print("  obfs2 proxy:")
    obfs2_stats_ok, _ = _check_proxy_stats(obfs2_stats_port)
    print("  fake-tls proxy:")
    tls_stats_ok, _ = _check_proxy_stats(tls_stats_port)

    socks5_stats_ok = True
    if socks5_stats_port:
        print("  socks5 proxy:")
        socks5_stats_ok, socks5_stats = _check_proxy_stats(socks5_stats_port)
        for key in ["socks5_enabled", "socks5_connects_attempted",
                     "socks5_connects_succeeded", "socks5_connects_failed"]:
            print(f"    {key} = {socks5_stats.get(key, '?')}")
        s5_succ = int(socks5_stats.get("socks5_connects_succeeded", "0"))
        if socks5_ok and s5_succ == 0:
            print("    WARN: socks5 test passed but no SOCKS5 connects recorded")

    print("\n=== Results ===")
    all_ok = True
    results = [("obfs2", obfs2_ok), ("fake-tls", tls_ok),
               ("tls-vs-obfs2-ratio", comparison_ok),
               ("small-file-timing", small_timing_ok),
               ("drs-delay-ratio", drs_ok),
               ("obfs2-stats", obfs2_stats_ok),
               ("tls-stats", tls_stats_ok)]
    if socks5_port_str:
        results.append(("socks5", socks5_ok))
        results.append(("socks5-stats", socks5_stats_ok))
    for name, ok in results:
        status = "PASS" if ok else "FAIL"
        print(f"  {name}: {status}")
        if not ok:
            all_ok = False

    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
