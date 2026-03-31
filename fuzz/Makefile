CC ?= clang
FUZZ_SANITIZERS = -fsanitize=fuzzer,address,undefined
FUZZ_CFLAGS = $(FUZZ_SANITIZERS) -g -O1 -fno-omit-frame-pointer -std=gnu11 -Wall -D_GNU_SOURCE=1 -DFUZZ_TARGET
FUZZ_CINCLUDE = -iquote ../src/common -iquote ../src -iquote ..
FUZZ_DURATION ?= 60
TEST_COMPAT = $(shell [ "$$(uname)" = "Darwin" ] && echo "-DSOCK_NONBLOCK=0 -DSOCK_CLOEXEC=0")
TEST_CFLAGS = -g -O1 -std=gnu11 -Wall -D_GNU_SOURCE=1 $(TEST_COMPAT)

TARGETS = fuzz_tls_server_hello fuzz_tls_client_hello fuzz_http_request
TEST_TARGETS = test_dc_lookup
PARSE_OBJS = net-tls-parse.o net-http-parse.o stubs.o

.PHONY: all clean run test

all: $(TARGETS)

net-tls-parse.o: ../src/net/net-tls-parse.c ../src/net/net-tls-parse.h
	$(CC) $(FUZZ_CFLAGS) $(FUZZ_CINCLUDE) -c -o $@ $<

net-http-parse.o: ../src/net/net-http-parse.c ../src/net/net-http-parse.h ../src/net/net-http-server.h
	$(CC) $(FUZZ_CFLAGS) $(FUZZ_CINCLUDE) -c -o $@ $<

stubs.o: stubs.c
	$(CC) $(FUZZ_CFLAGS) $(FUZZ_CINCLUDE) -c -o $@ $<

fuzz_tls_server_hello: fuzz_tls_server_hello.c net-tls-parse.o stubs.o
	$(CC) $(FUZZ_CFLAGS) $(FUZZ_CINCLUDE) -o $@ $^

fuzz_tls_client_hello: fuzz_tls_client_hello.c net-tls-parse.o stubs.o
	$(CC) $(FUZZ_CFLAGS) $(FUZZ_CINCLUDE) -o $@ $^

fuzz_http_request: fuzz_http_request.c net-http-parse.o stubs.o
	$(CC) $(FUZZ_CFLAGS) $(FUZZ_CINCLUDE) -o $@ $^

run: $(TARGETS)
	@failed=0; \
	for target in $(TARGETS); do \
		echo "=== Running $$target for $(FUZZ_DURATION)s ==="; \
		corpus_dir=corpus/$$(echo $$target | sed 's/^fuzz_//'); \
		./$$target $$corpus_dir -max_total_time=$(FUZZ_DURATION) -print_final_stats=1 || failed=1; \
	done; \
	if [ $$failed -ne 0 ]; then echo "FAIL: some fuzz targets crashed"; exit 1; fi

mtproto-dc-table.o: ../src/mtproto/mtproto-dc-table.c ../src/mtproto/mtproto-dc-table.h
	$(CC) $(TEST_CFLAGS) $(FUZZ_CINCLUDE) -c -o $@ $<

test_dc_lookup: test_dc_lookup.c mtproto-dc-table.o
	$(CC) $(TEST_CFLAGS) $(FUZZ_CINCLUDE) -o $@ $^

test: $(TEST_TARGETS)
	@for t in $(TEST_TARGETS); do echo "=== $$t ==="; ./$$t || exit 1; done

clean:
	rm -f $(TARGETS) $(TEST_TARGETS) $(PARSE_OBJS) mtproto-dc-table.o
