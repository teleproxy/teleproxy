# Testing Teleproxy

This repository includes a test suite to verify the functionality of the Teleproxy server. The tests run in Docker or directly on the host and check:

1. **HTTP Stats**: Verifies the stats endpoint (port 8888) is accessible.
2. **Prometheus Metrics**: Verifies the `/metrics` endpoint returns valid Prometheus exposition format.
3. **MTProto Port**: Verifies the MTProto port accepts TCP connections.

## Prerequisites

- Docker and Docker Compose (for containerized testing)
- `make` (for running the test command)
- Python 3.9+ (for local script execution without Docker)

## Running Tests

### Using Make (Docker)

Simply run:

```bash
make test
```

This will:
1. Build the Teleproxy Docker image.
2. Build the test runner Docker image.
3. Start the proxy and test runner.
4. Execute the connectivity checks.

A random secret will be generated automatically if `TELEPROXY_SECRET` is not set.

### Running Locally (No Docker)

If you want to run the tests against a local instance:

1. Install Python dependencies:
   ```bash
   pip install -r tests/requirements.txt
   ```
2. Set environment variables:
   ```bash
   export TELEPROXY_HOST=localhost  # or IP of your proxy
   export TELEPROXY_PORT=443        # or your proxy port
   ```
3. Run the script:
   ```bash
   python3 tests/test_proxy.py
   ```

## Manual Connectivity Check

If tests are failing, you can manually verify connectivity to Telegram servers:

```bash
# Check connectivity to Telegram DC 2 (Europe)
nc -zv 149.154.167.50 443
# Expected output: Connection to 149.154.167.50 443 port [tcp/https] succeeded!
```

If this fails, your network (ISP, firewall, or hosting provider) is blocking connections to Telegram.

## Fuzz Testing

The `fuzz/` directory contains [libFuzzer](https://llvm.org/docs/LibFuzzer.html) harnesses for protocol parsers, compiled with AddressSanitizer and UndefinedBehaviorSanitizer.

### Targets

| Harness | Parser | What it tests |
|---------|--------|---------------|
| `fuzz_tls_server_hello` | `tls_check_server_hello()` | Extension parsing, length validation, record counting |
| `fuzz_tls_client_hello` | `tls_parse_sni()` + `tls_parse_client_hello_ciphers()` | SNI extraction, cipher suite GREASE skipping |
| `fuzz_http_request` | `http_parse_data()` | HTTP state machine, header limits, Content-Length overflow |

### Running

Requires **Clang** (for `-fsanitize=fuzzer`):

```bash
# Build fuzz targets
make fuzz CC=clang

# Run all targets for 60 seconds each (default)
make fuzz-run

# Custom duration
make fuzz-run FUZZ_DURATION=300
```

Seed corpus files are in `fuzz/corpus/`. The fuzzers also run automatically in CI on every push and PR.

## Troubleshooting

- **Timeout**: If tests time out, check your network connection. MTProto proxies may be blocked by some ISPs.
- **Port already in use**: The tests use ports 18443 and 18888 by default. Make sure these are available.
