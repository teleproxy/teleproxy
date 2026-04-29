OBJ	=	objs
DEP	=	dep
EXE = ${OBJ}/bin

COMMIT := $(shell git log -1 --pretty=format:"%H")
VERSION := $(shell git describe --tags --match 'v*' --abbrev=0 2>/dev/null | sed 's/^v//' || echo "unknown")
ifneq ($(EXTRA_VERSION),)
VERSION := $(EXTRA_VERSION)
endif

BITNESS_FLAGS =
ifeq ($(m), 32)
BITNESS_FLAGS = -m32
endif
ifeq ($(m), 64)
BITNESS_FLAGS = -m64
endif

# Determine the host architecture
HOST_ARCH := $(shell uname -m)

# Default CFLAGS and LDFLAGS
COMMON_CFLAGS := -O3 -std=gnu11 -Wall -fno-strict-aliasing -fno-strict-overflow -fwrapv -fno-common -DAES=1 -DCOMMIT=\"${COMMIT}\" -DVERSION=\"${VERSION}\" -D_FILE_OFFSET_BITS=64 -Wno-array-bounds -Wno-implicit-function-declaration

# Platform-specific flags
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S), Darwin)
  # macOS: no -lrt (in libc), no -rdynamic (use -Wl,-export_dynamic or omit),
  # epoll-shim provides sys/epoll.h via kqueue, Homebrew OpenSSL is keg-only
  # Use the interpose variant to avoid macro conflicts (close, read, write)
  EPOLL_SHIM_CFLAGS := $(shell pkg-config --cflags epoll-shim-interpose 2>/dev/null)
  EPOLL_SHIM_LDFLAGS := $(shell pkg-config --libs epoll-shim-interpose 2>/dev/null)
  ifeq ($(EPOLL_SHIM_LDFLAGS),)
    $(error macOS build requires epoll-shim: brew install epoll-shim openssl)
  endif
  OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl 2>/dev/null)
  OPENSSL_LDFLAGS := $(shell pkg-config --libs openssl 2>/dev/null)
  COMMON_CFLAGS += -D_GNU_SOURCE=1 $(EPOLL_SHIM_CFLAGS) $(OPENSSL_CFLAGS)
  COMMON_LDFLAGS := -ggdb -lm -lz -lpthread $(EPOLL_SHIM_LDFLAGS) $(OPENSSL_LDFLAGS)
else
  # Linux
  COMMON_CFLAGS += -D_GNU_SOURCE=1
  COMMON_LDFLAGS := -ggdb -rdynamic -lm -lrt -lcrypto -lz -lpthread
endif

# Auto-detect libunwind for stack traces on musl/Alpine (test/CI builds)
LIBUNWIND_CFLAGS := $(shell pkg-config --cflags libunwind 2>/dev/null)
LIBUNWIND_LDFLAGS := $(shell pkg-config --libs libunwind 2>/dev/null)
ifneq ($(LIBUNWIND_LDFLAGS),)
COMMON_CFLAGS += -DHAVE_LIBUNWIND $(LIBUNWIND_CFLAGS)
COMMON_LDFLAGS += $(LIBUNWIND_LDFLAGS)
endif

# Support additional flags (e.g. sanitizers): make EXTRA_CFLAGS="-fsanitize=address"
COMMON_CFLAGS += $(EXTRA_CFLAGS)
COMMON_LDFLAGS += $(EXTRA_LDFLAGS)

# Architecture-specific CFLAGS
ifeq ($(HOST_ARCH), x86_64)
CFLAGS := $(COMMON_CFLAGS) -mpclmul -march=core2 -mfpmath=sse -mssse3 $(BITNESS_FLAGS)
else ifeq ($(HOST_ARCH), aarch64)
CFLAGS := $(COMMON_CFLAGS) $(BITNESS_FLAGS)
else ifeq ($(HOST_ARCH), arm64)
CFLAGS := $(COMMON_CFLAGS) $(BITNESS_FLAGS)
endif

# Architecture-specific LDFLAGS (if needed, here kept same for simplicity)
LDFLAGS := $(COMMON_LDFLAGS)

LIB = ${OBJ}/lib
CINCLUDE = -iquote src/common -iquote src/common/toml -iquote src -iquote .

LIBLIST = ${LIB}/libkdb.a

PROJECTS = src/common src/common/toml src/common/qrcode src/jobs src/mtproto src/net src/crypto src/engine

OBJDIRS := ${OBJ} $(addprefix ${OBJ}/,${PROJECTS}) ${EXE} ${LIB}
DEPDIRS := ${DEP} $(addprefix ${DEP}/,${PROJECTS})
ALLDIRS := ${DEPDIRS} ${OBJDIRS}


.PHONY:	all clean lint tests test test-tls test-multi-secret test-secret-limit test-secret-quota test-rate-limit test-top-ips test-ip-acl test-drs-delays test-cdn-dc test-ipv6-direct test-dc-lookup test-config-reload test-secret-drain test-check test-link test-link-ip test-stats-port test-install-config test-proxy-protocol test-dc-probes test-junk test-csv-label test-external-port test-unique-ips test-table-full docker-image-amd64 docker-run-help-amd64 docker-image-arm64 docker-run-help-arm64 fuzz fuzz-run

EXELIST	:= ${EXE}/teleproxy


OBJECTS	=	\
  ${OBJ}/src/mtproto/mtproto-proxy.o ${OBJ}/src/mtproto/mtproto-proxy-stats.o ${OBJ}/src/mtproto/mtproto-proxy-http.o ${OBJ}/src/mtproto/mtproto-config.o ${OBJ}/src/mtproto/mtproto-dc-table.o ${OBJ}/src/mtproto/mtproto-dc-probes.o ${OBJ}/src/mtproto/mtproto-check.o ${OBJ}/src/mtproto/mtproto-link.o ${OBJ}/src/net/net-tcp-rpc-ext-server.o ${OBJ}/src/net/net-tcp-rpc-ext-drain.o ${OBJ}/src/net/net-tcp-rpc-ext-top-ips.o ${OBJ}/src/net/net-tcp-rpc-ext-uniq-bloom.o ${OBJ}/src/net/net-tcp-rpc-ext-domain.o ${OBJ}/src/net/net-tcp-direct-dc.o

DEPENDENCE_CXX		:=	$(subst ${OBJ}/,${DEP}/,$(patsubst %.o,%.d,${OBJECTS_CXX}))
DEPENDENCE_STRANGE	:=	$(subst ${OBJ}/,${DEP}/,$(patsubst %.o,%.d,${OBJECTS_STRANGE}))
DEPENDENCE_NORM	:=	$(subst ${OBJ}/,${DEP}/,$(patsubst %.o,%.d,${OBJECTS}))

LIB_OBJS_NORMAL := \
	${OBJ}/src/common/crc32c.o \
	${OBJ}/src/common/pid.o \
	${OBJ}/src/common/sha1.o \
	${OBJ}/src/common/sha256.o \
	${OBJ}/src/common/md5.o \
	${OBJ}/src/common/resolver.o \
	${OBJ}/src/common/parse-config.o \
	${OBJ}/src/crypto/aesni256.o \
	${OBJ}/src/jobs/jobs.o ${OBJ}/src/common/mp-queue.o \
	${OBJ}/src/net/net-events.o ${OBJ}/src/net/net-msg.o ${OBJ}/src/net/net-msg-buffers.o \
	${OBJ}/src/net/net-config.o ${OBJ}/src/net/net-crypto-aes.o ${OBJ}/src/net/net-crypto-dh.o ${OBJ}/src/net/net-timers.o \
	${OBJ}/src/net/net-connections.o ${OBJ}/src/net/net-conn-targets.o \
	${OBJ}/src/net/net-rpc-targets.o \
	${OBJ}/src/net/net-tcp-connections.o ${OBJ}/src/net/net-tcp-drs.o ${OBJ}/src/net/net-tcp-rpc-common.o ${OBJ}/src/net/net-tcp-rpc-client.o ${OBJ}/src/net/net-tcp-rpc-server.o \
	${OBJ}/src/net/net-http-server.o ${OBJ}/src/net/net-http-parse.o ${OBJ}/src/net/net-tls-parse.o ${OBJ}/src/net/net-obfs2-parse.o ${OBJ}/src/net/net-ip-acl.o ${OBJ}/src/net/net-proxy-protocol.o \
	${OBJ}/src/common/tl-parse.o ${OBJ}/src/common/common-stats.o \
	${OBJ}/src/engine/engine.o ${OBJ}/src/engine/engine-signals.o \
	${OBJ}/src/engine/engine-net.o \
	${OBJ}/src/engine/engine-rpc.o \
	${OBJ}/src/engine/engine-rpc-common.o \
	${OBJ}/src/net/net-thread.o ${OBJ}/src/net/net-stats.o ${OBJ}/src/common/proc-stat.o \
	${OBJ}/src/common/kprintf.o \
	${OBJ}/src/common/precise-time.o ${OBJ}/src/common/cpuid.o \
	${OBJ}/src/common/server-functions.o ${OBJ}/src/common/crc32.o \
	${OBJ}/src/common/toml/tomlc17.o ${OBJ}/src/common/toml/tomlc17-scan.o \
	${OBJ}/src/common/toml-config.o \
	${OBJ}/src/common/qrcode/qrcodegen.o \

LIB_OBJS := ${LIB_OBJS_NORMAL}

DEPENDENCE_LIB	:=	$(subst ${OBJ}/,${DEP}/,$(patsubst %.o,%.d,${LIB_OBJS}))

DEPENDENCE_ALL		:=	${DEPENDENCE_NORM} ${DEPENDENCE_STRANGE} ${DEPENDENCE_LIB}

OBJECTS_ALL		:=	${OBJECTS} ${LIB_OBJS}

all:	${ALLDIRS} ${EXELIST} 
dirs: ${ALLDIRS}
create_dirs_and_headers: ${ALLDIRS} 

${ALLDIRS}:	
	@test -d $@ || mkdir -p $@

-include ${DEPENDENCE_ALL}

${OBJECTS}: ${OBJ}/%.o: %.c | create_dirs_and_headers
	${CC} ${CFLAGS} ${CINCLUDE} -c -MP -MD -MF ${DEP}/$*.d -MQ ${OBJ}/$*.o -o $@ $<

${LIB_OBJS_NORMAL}: ${OBJ}/%.o: %.c | create_dirs_and_headers
	${CC} ${CFLAGS} -fpic ${CINCLUDE} -c -MP -MD -MF ${DEP}/$*.d -MQ ${OBJ}/$*.o -o $@ $<

${EXELIST}: ${LIBLIST}

${EXE}/teleproxy:	${OBJ}/src/mtproto/mtproto-proxy.o ${OBJ}/src/mtproto/mtproto-proxy-stats.o ${OBJ}/src/mtproto/mtproto-proxy-http.o ${OBJ}/src/mtproto/mtproto-config.o ${OBJ}/src/mtproto/mtproto-dc-table.o ${OBJ}/src/mtproto/mtproto-dc-probes.o ${OBJ}/src/mtproto/mtproto-check.o ${OBJ}/src/mtproto/mtproto-link.o ${OBJ}/src/net/net-tcp-rpc-ext-server.o ${OBJ}/src/net/net-tcp-rpc-ext-drain.o ${OBJ}/src/net/net-tcp-rpc-ext-top-ips.o ${OBJ}/src/net/net-tcp-rpc-ext-uniq-bloom.o ${OBJ}/src/net/net-tcp-rpc-ext-domain.o ${OBJ}/src/net/net-tcp-direct-dc.o
	${CC} -o $@ $^ ${LDFLAGS}

${LIB}/libkdb.a: ${LIB_OBJS}
	rm -f $@ && ar rcs $@ $^

clean:
	rm -rf ${OBJ} ${DEP} ${EXE} || true

lint:
	cppcheck --enable=warning,portability,performance \
	  --error-exitcode=1 \
	  --suppressions-list=.cppcheck-suppressions \
	  --suppress=missingIncludeSystem \
	  --std=c11 -I src/common -I src -I . \
	  -i src/common/qrcode/ \
	  src/common/ src/jobs/ src/mtproto/ src/net/ src/crypto/ src/engine/

force-clean: clean

# Docker-based amd64 build and smoke test
DOCKER ?= docker
DOCKER_PLATFORM ?= linux/amd64
DOCKER_TEST_IMAGE ?= teleproxy:test-amd64

docker-image-amd64:
	${DOCKER} buildx build --platform ${DOCKER_PLATFORM} --load -t ${DOCKER_TEST_IMAGE} .

docker-run-help-amd64: docker-image-amd64
	${DOCKER} run --rm --platform ${DOCKER_PLATFORM} --entrypoint /opt/teleproxy/teleproxy ${DOCKER_TEST_IMAGE} 2>&1 | grep -q "Invoking engine"

docker-image-arm64:
	${DOCKER} buildx build --platform linux/arm64 --load -t teleproxy:test-arm64 .

docker-run-help-arm64: docker-image-arm64
	${DOCKER} run --rm --platform linux/arm64 --entrypoint /opt/teleproxy/teleproxy teleproxy:test-arm64 2>&1 | grep -q "Invoking engine"

tests: docker-run-help-amd64
	@echo "Smoke test passed: amd64 image builds and binary starts (--help)."

test:
	@# Generate secret if not provided
	@if [ -z "$$TELEPROXY_SECRET" ]; then \
		export TELEPROXY_SECRET=$$(head -c 16 /dev/urandom | xxd -ps); \
		echo "Generated TELEPROXY_SECRET: $$TELEPROXY_SECRET"; \
	fi && \
	export TELEPROXY_SECRET=$${TELEPROXY_SECRET:-$$(head -c 16 /dev/urandom | xxd -ps)} && \
	echo "Using secret: $$TELEPROXY_SECRET" && \
	timeout 1200s docker compose -f tests/docker-compose.test.yml up --build --exit-code-from tester || \
		(echo "Test timed out or failed"; docker compose -f tests/docker-compose.test.yml down; exit 1)

test-tls:
	@if [ -z "$$TELEPROXY_SECRET" ]; then \
		export TELEPROXY_SECRET=$$(head -c 16 /dev/urandom | xxd -ps); \
		echo "Generated TELEPROXY_SECRET: $$TELEPROXY_SECRET"; \
	fi && \
	export TELEPROXY_SECRET=$${TELEPROXY_SECRET:-$$(head -c 16 /dev/urandom | xxd -ps)} && \
	echo "Using secret: $$TELEPROXY_SECRET" && \
	timeout 300s docker compose -f tests/docker-compose.tls-test.yml up --build --exit-code-from tester || \
		(echo "TLS test timed out or failed"; \
		docker compose -f tests/docker-compose.tls-test.yml logs teleproxy; \
		docker compose -f tests/docker-compose.tls-test.yml down; exit 1)
	docker compose -f tests/docker-compose.tls-test.yml down

test-multi-secret:
	@export TELEPROXY_SECRET_1=$$(head -c 16 /dev/urandom | xxd -ps) && \
	export TELEPROXY_SECRET_2=$$(head -c 16 /dev/urandom | xxd -ps) && \
	echo "Using secrets: $$TELEPROXY_SECRET_1, $$TELEPROXY_SECRET_2" && \
	timeout 300s docker compose -f tests/docker-compose.multi-secret-test.yml up --build --exit-code-from tester || \
		(echo "Multi-secret test timed out or failed"; \
		docker compose -f tests/docker-compose.multi-secret-test.yml logs teleproxy; \
		docker compose -f tests/docker-compose.multi-secret-test.yml down; exit 1)
	@echo "Checking connection link output in proxy logs..."
	@docker compose -f tests/docker-compose.multi-secret-test.yml logs teleproxy 2>&1 | grep -q "t.me/proxy" || \
		(echo "FAIL: No connection links found in proxy logs"; exit 1)
	docker compose -f tests/docker-compose.multi-secret-test.yml down

test-secret-limit:
	@export TELEPROXY_SECRET_1=$$(head -c 16 /dev/urandom | xxd -ps) && \
	export TELEPROXY_SECRET_2=$$(head -c 16 /dev/urandom | xxd -ps) && \
	echo "Using secrets: $$TELEPROXY_SECRET_1 (unlimited), $$TELEPROXY_SECRET_2 (limit=5)" && \
	timeout 300s docker compose -f tests/docker-compose.secret-limit-test.yml up --build --exit-code-from tester || \
		(echo "Secret limit test timed out or failed"; \
		docker compose -f tests/docker-compose.secret-limit-test.yml logs teleproxy; \
		docker compose -f tests/docker-compose.secret-limit-test.yml down; exit 1)
	docker compose -f tests/docker-compose.secret-limit-test.yml down

test-secret-quota:
	@export TELEPROXY_SECRET_1=$$(head -c 16 /dev/urandom | xxd -ps) && \
	export TELEPROXY_SECRET_2=$$(head -c 16 /dev/urandom | xxd -ps) && \
	echo "Using secrets: $$TELEPROXY_SECRET_1 (active), $$TELEPROXY_SECRET_2 (expired)" && \
	timeout 300s docker compose -f tests/docker-compose.secret-quota-test.yml up --build --exit-code-from tester || \
		(echo "Secret quota test timed out or failed"; \
		docker compose -f tests/docker-compose.secret-quota-test.yml logs teleproxy; \
		docker compose -f tests/docker-compose.secret-quota-test.yml down; exit 1)
	docker compose -f tests/docker-compose.secret-quota-test.yml down

test-rate-limit:
	@export TELEPROXY_SECRET_1=$$(head -c 16 /dev/urandom | xxd -ps) && \
	export TELEPROXY_SECRET_2=$$(head -c 16 /dev/urandom | xxd -ps) && \
	echo "Using secrets: $$TELEPROXY_SECRET_1 (limited), $$TELEPROXY_SECRET_2 (unlimited)" && \
	timeout 300s docker compose -f tests/docker-compose.rate-limit-test.yml up --build --exit-code-from tester || \
		(echo "Rate limit test timed out or failed"; \
		docker compose -f tests/docker-compose.rate-limit-test.yml logs teleproxy; \
		docker compose -f tests/docker-compose.rate-limit-test.yml down; exit 1)
	docker compose -f tests/docker-compose.rate-limit-test.yml down

test-top-ips:
	@export TELEPROXY_SECRET_1=$$(head -c 16 /dev/urandom | xxd -ps) && \
	echo "Using secret: $$TELEPROXY_SECRET_1" && \
	timeout 300s docker compose -f tests/docker-compose.top-ips-test.yml up --build --exit-code-from tester || \
		(echo "Top IPs test timed out or failed"; \
		docker compose -f tests/docker-compose.top-ips-test.yml logs teleproxy; \
		docker compose -f tests/docker-compose.top-ips-test.yml down; exit 1)
	docker compose -f tests/docker-compose.top-ips-test.yml down

test-ip-acl:
	@if [ -z "$$TELEPROXY_SECRET" ]; then \
		export TELEPROXY_SECRET=$$(head -c 16 /dev/urandom | xxd -ps); \
		echo "Generated TELEPROXY_SECRET: $$TELEPROXY_SECRET"; \
	fi && \
	export TELEPROXY_SECRET=$${TELEPROXY_SECRET:-$$(head -c 16 /dev/urandom | xxd -ps)} && \
	echo "Using secret: $$TELEPROXY_SECRET" && \
	docker compose -f tests/docker-compose.ip-acl-test.yml build && \
	docker compose -f tests/docker-compose.ip-acl-test.yml up -d --wait teleproxy && \
	echo "Phase 1: testing blocked connections..." && \
	docker compose -f tests/docker-compose.ip-acl-test.yml run --rm blocked-tester && \
	echo "Phase 2: testing allowed connections..." && \
	docker compose -f tests/docker-compose.ip-acl-test.yml run --rm tester || \
		(echo "IP ACL test failed"; \
		docker compose -f tests/docker-compose.ip-acl-test.yml logs teleproxy; \
		docker compose -f tests/docker-compose.ip-acl-test.yml down -v; exit 1)
	docker compose -f tests/docker-compose.ip-acl-test.yml down -v

test-config-reload:
	@export TELEPROXY_SECRET_1=$$(head -c 16 /dev/urandom | xxd -ps) && \
	export TELEPROXY_SECRET_2=$$(head -c 16 /dev/urandom | xxd -ps) && \
	export TELEPROXY_SECRET_3=$$(head -c 16 /dev/urandom | xxd -ps) && \
	echo "Using secrets: $$TELEPROXY_SECRET_1, $$TELEPROXY_SECRET_2 (config), $$TELEPROXY_SECRET_3 (new)" && \
	timeout 300s docker compose -f tests/docker-compose.config-reload-test.yml up --build --exit-code-from tester || \
		(echo "Config reload test timed out or failed"; \
		docker compose -f tests/docker-compose.config-reload-test.yml logs teleproxy; \
		docker compose -f tests/docker-compose.config-reload-test.yml down -v; exit 1)
	docker compose -f tests/docker-compose.config-reload-test.yml down -v

test-secret-drain:
	@export TELEPROXY_SECRET_1=$$(head -c 16 /dev/urandom | xxd -ps) && \
	export TELEPROXY_SECRET_2=$$(head -c 16 /dev/urandom | xxd -ps) && \
	export PINNED_SECRET= && \
	echo "Using secrets: $$TELEPROXY_SECRET_1 (alpha), $$TELEPROXY_SECRET_2 (beta)" && \
	timeout 300s docker compose -f tests/docker-compose.secret-drain-test.yml up --build --exit-code-from tester || \
		(echo "Secret drain test timed out or failed"; \
		docker compose -f tests/docker-compose.secret-drain-test.yml logs teleproxy; \
		docker compose -f tests/docker-compose.secret-drain-test.yml down -v; exit 1)
	docker compose -f tests/docker-compose.secret-drain-test.yml down -v

test-drs-delays:
	@if [ -z "$$TELEPROXY_SECRET" ]; then \
		export TELEPROXY_SECRET=$$(head -c 16 /dev/urandom | xxd -ps); \
		echo "Generated TELEPROXY_SECRET: $$TELEPROXY_SECRET"; \
	fi && \
	export TELEPROXY_SECRET=$${TELEPROXY_SECRET:-$$(head -c 16 /dev/urandom | xxd -ps)} && \
	echo "Using secret: $$TELEPROXY_SECRET" && \
	timeout 300s docker compose -f tests/docker-compose.drs-delays-test.yml up --build --exit-code-from tester || \
		(echo "DRS delays test timed out or failed"; \
		docker compose -f tests/docker-compose.drs-delays-test.yml logs teleproxy; \
		docker compose -f tests/docker-compose.drs-delays-test.yml down; exit 1)
	docker compose -f tests/docker-compose.drs-delays-test.yml down

test-cdn-dc:
	@export TELEPROXY_SECRET=$$(head -c 16 /dev/urandom | xxd -ps) && \
	echo "Using secret: $$TELEPROXY_SECRET" && \
	timeout 300s docker compose -f tests/docker-compose.cdn-dc-test.yml up --build --exit-code-from tester || \
		(echo "CDN DC test timed out or failed"; \
		docker compose -f tests/docker-compose.cdn-dc-test.yml logs teleproxy; \
		docker compose -f tests/docker-compose.cdn-dc-test.yml down; exit 1)
	docker compose -f tests/docker-compose.cdn-dc-test.yml down

test-ipv6-direct:
	@export TELEPROXY_SECRET=$$(head -c 16 /dev/urandom | xxd -ps) && \
	echo "Using secret: $$TELEPROXY_SECRET" && \
	timeout 300s docker compose -f tests/docker-compose.ipv6-direct-test.yml up --build --exit-code-from tester || \
		(echo "IPv6 direct test timed out or failed"; \
		docker compose -f tests/docker-compose.ipv6-direct-test.yml logs teleproxy; \
		docker compose -f tests/docker-compose.ipv6-direct-test.yml down; exit 1)
	docker compose -f tests/docker-compose.ipv6-direct-test.yml down

test-bind-address:
	@export TELEPROXY_SECRET=$$(head -c 16 /dev/urandom | xxd -ps) && \
	echo "Using secret: $$TELEPROXY_SECRET" && \
	timeout 300s docker compose -f tests/docker-compose.bind-address-test.yml up --build --exit-code-from tester || \
		(echo "Bind address test timed out or failed"; \
		docker compose -f tests/docker-compose.bind-address-test.yml logs teleproxy; \
		docker compose -f tests/docker-compose.bind-address-test.yml down; exit 1)
	docker compose -f tests/docker-compose.bind-address-test.yml down

test-socks5:
	@export TELEPROXY_SECRET=$$(head -c 16 /dev/urandom | xxd -ps) && \
	echo "Using secret: $$TELEPROXY_SECRET" && \
	timeout 300s docker compose -f tests/docker-compose.socks5-test.yml up --build --exit-code-from tester || \
		(echo "SOCKS5 test timed out or failed"; \
		docker compose -f tests/docker-compose.socks5-test.yml logs teleproxy socks5; \
		docker compose -f tests/docker-compose.socks5-test.yml down; exit 1)
	docker compose -f tests/docker-compose.socks5-test.yml down

test-proxy-protocol:
	@export TELEPROXY_SECRET=$$(head -c 16 /dev/urandom | xxd -ps) && \
	echo "Using secret: $$TELEPROXY_SECRET" && \
	timeout 300s docker compose -f tests/docker-compose.proxy-protocol-test.yml up --build --exit-code-from tester || \
		(echo "PROXY protocol test timed out or failed"; \
		docker compose -f tests/docker-compose.proxy-protocol-test.yml logs teleproxy; \
		docker compose -f tests/docker-compose.proxy-protocol-test.yml down; exit 1)
	docker compose -f tests/docker-compose.proxy-protocol-test.yml down

test-dc-probes:
	@export TELEPROXY_SECRET=$$(head -c 16 /dev/urandom | xxd -ps) && \
	echo "Testing DC probes and Prometheus metrics..." && \
	timeout 300s docker compose -f tests/docker-compose.dc-probes-test.yml up --build --exit-code-from tester || \
		(echo "DC probes test failed"; \
		docker compose -f tests/docker-compose.dc-probes-test.yml logs teleproxy; \
		docker compose -f tests/docker-compose.dc-probes-test.yml down; exit 1)
	docker compose -f tests/docker-compose.dc-probes-test.yml down

test-generate-secret: docker-image-amd64
	@echo "Testing generate-secret subcommand..."
	@$(DOCKER) run --rm --platform $(DOCKER_PLATFORM) --entrypoint /bin/sh $(DOCKER_TEST_IMAGE) -c ' \
		BIN=/opt/teleproxy/teleproxy; \
		echo "Test 1: no-domain → 32 hex chars"; \
		out=$$($$BIN generate-secret 2>/dev/null); \
		printf "%s" "$$out" | grep -qE "^[0-9a-f]{32}$$" || { echo "FAIL: $$out"; exit 1; }; \
		echo "  PASS"; \
		echo "Test 2: domain → ee + secret + domain hex"; \
		out=$$($$BIN generate-secret example.com 2>/dev/null); \
		printf "%s" "$$out" | grep -qE "^ee[0-9a-f]{32}6578616d706c652e636f6d$$" || { echo "FAIL: $$out"; exit 1; }; \
		echo "  PASS"; \
		echo "Test 3: randomness (two calls differ)"; \
		s1=$$($$BIN generate-secret 2>/dev/null); \
		s2=$$($$BIN generate-secret 2>/dev/null); \
		[ "$$s1" != "$$s2" ] || { echo "FAIL: identical"; exit 1; }; \
		echo "  PASS"; \
		echo "Test 4: exit code 0"; \
		$$BIN generate-secret >/dev/null 2>&1; \
		[ $$? -eq 0 ] || { echo "FAIL: non-zero exit"; exit 1; }; \
		echo "  PASS"; \
		echo "Test 5: stderr context with domain"; \
		$$BIN generate-secret example.com 2>&1 >/dev/null | grep -q "Secret for -S" || { echo "FAIL: missing stderr"; exit 1; }; \
		echo "  PASS"; \
		echo "Test 6: no stderr without domain"; \
		err=$$($$BIN generate-secret 2>&1 >/dev/null); \
		[ -z "$$err" ] || { echo "FAIL: unexpected stderr: $$err"; exit 1; }; \
		echo "  PASS"; \
		echo "All generate-secret tests passed!" \
	'

test-check:
	timeout 120s docker compose -f tests/docker-compose.check-test.yml up --build --exit-code-from tester || \
		(echo "Check subcommand test failed"; \
		docker compose -f tests/docker-compose.check-test.yml down; exit 1)
	docker compose -f tests/docker-compose.check-test.yml down

test-link:
	timeout 120s docker compose -f tests/docker-compose.link-test.yml up --build --exit-code-from tester || \
		(echo "Link subcommand test failed"; \
		docker compose -f tests/docker-compose.link-test.yml down; exit 1)
	docker compose -f tests/docker-compose.link-test.yml down

test-link-ip:
	@export TELEPROXY_SECRET=$$(head -c 16 /dev/urandom | xxd -ps) && \
	echo "Using secret: $$TELEPROXY_SECRET" && \
	timeout 120s docker compose -f tests/docker-compose.link-ip-test.yml up --build --exit-code-from tester || \
		(echo "Link IP test failed"; \
		docker compose -f tests/docker-compose.link-ip-test.yml down; exit 1)
	docker compose -f tests/docker-compose.link-ip-test.yml down

test-autosecret:
	timeout 120s docker compose -f tests/docker-compose.autosecret-test.yml up --build --exit-code-from tester || \
		(echo "Auto-secret test failed"; \
		docker compose -f tests/docker-compose.autosecret-test.yml down; exit 1)
	docker compose -f tests/docker-compose.autosecret-test.yml down

test-junk:
	@export TELEPROXY_SECRET=$$(head -c 16 /dev/urandom | xxd -ps) && \
	echo "Using secret: $$TELEPROXY_SECRET" && \
	timeout 120s docker compose -f tests/docker-compose.junk-test.yml up --build --exit-code-from tester || \
		(echo "Junk traffic test failed"; \
		docker compose -f tests/docker-compose.junk-test.yml logs teleproxy; \
		docker compose -f tests/docker-compose.junk-test.yml down; exit 1)
	docker compose -f tests/docker-compose.junk-test.yml down

test-csv-label:
	@export TELEPROXY_SECRET_1=$$(head -c 16 /dev/urandom | xxd -ps) && \
	export TELEPROXY_SECRET_2=$$(head -c 16 /dev/urandom | xxd -ps) && \
	echo "Using secrets: $$TELEPROXY_SECRET_1, $$TELEPROXY_SECRET_2" && \
	timeout 120s docker compose -f tests/docker-compose.csv-label-test.yml up --build --exit-code-from tester || \
		(echo "CSV secret-label test failed"; \
		docker compose -f tests/docker-compose.csv-label-test.yml logs teleproxy; \
		docker compose -f tests/docker-compose.csv-label-test.yml down; exit 1)
	docker compose -f tests/docker-compose.csv-label-test.yml down

test-external-port:
	@export TELEPROXY_SECRET=$$(head -c 16 /dev/urandom | xxd -ps) && \
	echo "Using secret: $$TELEPROXY_SECRET" && \
	timeout 120s docker compose -f tests/docker-compose.external-port-test.yml up --build --exit-code-from tester || \
		(echo "External port test failed"; \
		docker compose -f tests/docker-compose.external-port-test.yml logs teleproxy; \
		docker compose -f tests/docker-compose.external-port-test.yml down; exit 1)
	@docker compose -f tests/docker-compose.external-port-test.yml logs teleproxy 2>&1 | grep -q 'port=4443' || \
		(echo "FAIL: 'port=4443' not found in teleproxy stdout"; \
		docker compose -f tests/docker-compose.external-port-test.yml down; exit 1)
	docker compose -f tests/docker-compose.external-port-test.yml down

test-unique-ips:
	@export TELEPROXY_SECRET=$$(head -c 16 /dev/urandom | xxd -ps) && \
	echo "Using secret: $$TELEPROXY_SECRET" && \
	export COMPOSE_FILE=tests/docker-compose.unique-ips-test.yml && \
	docker compose build tester teleproxy && \
	docker compose up -d teleproxy && \
	(docker compose run --rm handshaker-a && \
	 docker compose run --rm handshaker-b && \
	 docker compose run --rm handshaker-c && \
	 docker compose run --rm tester) || \
		(echo "Unique IPs test failed"; \
		docker compose logs teleproxy; \
		docker compose down -v; exit 1)
	docker compose down -v

test-table-full:
	@export TELEPROXY_SECRET=$$(head -c 16 /dev/urandom | xxd -ps) && \
	echo "Using secret: $$TELEPROXY_SECRET" && \
	export COMPOSE_FILE=tests/docker-compose.table-full-test.yml && \
	docker compose build tester teleproxy && \
	docker compose up -d teleproxy && \
	(docker compose up -d handshaker-a handshaker-b handshaker-c handshaker-d handshaker-e handshaker-f && \
	 docker compose wait handshaker-a handshaker-b handshaker-c handshaker-d handshaker-e handshaker-f && \
	 docker compose run --rm tester) || \
		(echo "Table-full regression test failed"; \
		docker compose logs teleproxy; \
		docker compose logs handshaker-a handshaker-b handshaker-c handshaker-d handshaker-e handshaker-f; \
		docker compose down -v; exit 1) && \
	warnings=$$(docker compose logs teleproxy 2>&1 | grep -c 'IP tracking table full' || true) && \
	echo "Saw $$warnings table-full warnings (expected <= 1, throttle window 60s)" && \
	if [ "$$warnings" -gt 1 ]; then \
		echo "FAIL: warning not throttled — got $$warnings, expected <= 1"; \
		docker compose logs teleproxy; \
		docker compose down -v; exit 1; \
	fi && \
	docker compose down -v

test-stats-port:
	@export TELEPROXY_SECRET=$$(head -c 16 /dev/urandom | xxd -ps) && \
	echo "Testing custom STATS_PORT healthcheck..." && \
	timeout 120s docker compose -f tests/docker-compose.stats-port-test.yml up -d --build --wait teleproxy && \
	echo "Custom STATS_PORT healthcheck passed" || \
		(echo "Stats port healthcheck test failed"; \
		docker compose -f tests/docker-compose.stats-port-test.yml logs teleproxy; \
		docker compose -f tests/docker-compose.stats-port-test.yml down; exit 1)
	docker compose -f tests/docker-compose.stats-port-test.yml down

test-install-config:
	@echo "Testing install.sh --generate-config..."
	@echo "Test 1: single secret"
	@out=$$(SECRET=aabbccdd11223344aabbccdd11223344 sh install.sh --generate-config 2>/dev/null) && \
		echo "$$out" | grep -c '^\[\[secret\]\]' | grep -qx 1 || { echo "FAIL: expected 1 [[secret]] block"; exit 1; } && \
		echo "$$out" | grep -q 'key = "aabbccdd11223344aabbccdd11223344"' || { echo "FAIL: wrong key"; exit 1; } && \
		echo "  PASS"
	@echo "Test 2: comma-separated secrets"
	@out=$$(SECRET=aaaa1111bbbb2222cccc3333dddd4444,eeee5555ffff6666aaaa7777bbbb8888 sh install.sh --generate-config 2>/dev/null) && \
		count=$$(echo "$$out" | grep -c '^\[\[secret\]\]') && \
		[ "$$count" -eq 2 ] || { echo "FAIL: expected 2 [[secret]] blocks, got $$count"; exit 1; } && \
		echo "  PASS"
	@echo "Test 3: SECRET_COUNT=3"
	@out=$$(SECRET_COUNT=3 sh install.sh --generate-config 2>/dev/null) && \
		count=$$(echo "$$out" | grep -c '^\[\[secret\]\]') && \
		[ "$$count" -eq 3 ] || { echo "FAIL: expected 3 blocks, got $$count"; exit 1; } && \
		echo "$$out" | grep -q 'label = "secret_1"' || { echo "FAIL: missing label secret_1"; exit 1; } && \
		echo "$$out" | grep -q 'label = "secret_2"' || { echo "FAIL: missing label secret_2"; exit 1; } && \
		echo "$$out" | grep -q 'label = "secret_3"' || { echo "FAIL: missing label secret_3"; exit 1; } && \
		echo "  PASS"
	@echo "Test 4: numbered with label"
	@out=$$(SECRET_1=aabbccdd11223344aabbccdd11223344 SECRET_LABEL_1=family sh install.sh --generate-config 2>/dev/null) && \
		echo "$$out" | grep -q 'label = "family"' || { echo "FAIL: missing label family"; exit 1; } && \
		echo "  PASS"
	@echo "Test 5: numbered with limit"
	@out=$$(SECRET_1=aabbccdd11223344aabbccdd11223344 SECRET_LIMIT_1=500 sh install.sh --generate-config 2>/dev/null) && \
		echo "$$out" | grep -q 'limit = 500' || { echo "FAIL: missing limit 500"; exit 1; } && \
		echo "  PASS"
	@echo "Test 6: no secret auto-generates one"
	@out=$$(sh install.sh --generate-config 2>/dev/null) && \
		count=$$(echo "$$out" | grep -c '^\[\[secret\]\]') && \
		[ "$$count" -eq 1 ] || { echo "FAIL: expected 1 block, got $$count"; exit 1; } && \
		echo "$$out" | grep -qE 'key = "[0-9a-f]{32}"' || { echo "FAIL: key not 32 hex"; exit 1; } && \
		echo "  PASS"
	@echo "Test 7: SECRET_COUNT=0 errors"
	@SECRET_COUNT=0 sh install.sh --generate-config >/dev/null 2>&1 && { echo "FAIL: should have errored"; exit 1; } || echo "  PASS"
	@echo "Test 8: SECRET_COUNT=abc errors"
	@SECRET_COUNT=abc sh install.sh --generate-config >/dev/null 2>&1 && { echo "FAIL: should have errored"; exit 1; } || echo "  PASS"
	@echo "Test 9: SECRET + SECRET_COUNT warns"
	@out=$$(SECRET=aabbccdd11223344aabbccdd11223344 SECRET_COUNT=3 sh install.sh --generate-config 2>&1) && \
		echo "$$out" | grep -q "SECRET_COUNT ignored" || { echo "FAIL: missing warning"; exit 1; } && \
		echo "  PASS"
	@echo "Test 10: EE_DOMAIN in config"
	@out=$$(SECRET=aabbccdd11223344aabbccdd11223344 EE_DOMAIN=google.com sh install.sh --generate-config 2>/dev/null) && \
		echo "$$out" | grep -q 'domain = "google.com"' || { echo "FAIL: missing domain"; exit 1; } && \
		echo "  PASS"
	@echo "All install-config tests passed!"

test-install-pipe:
	@echo "Testing install.sh via pipe (simulates curl ... | sh)..."
	@echo "Pipe test 1: single secret"
	@out=$$(cat install.sh | SECRET=aabbccdd11223344aabbccdd11223344 sh -s -- --generate-config 2>/dev/null) && \
		echo "$$out" | grep -c '^\[\[secret\]\]' | grep -qx 1 || { echo "FAIL: expected 1 [[secret]] block"; exit 1; } && \
		echo "$$out" | grep -q 'key = "aabbccdd11223344aabbccdd11223344"' || { echo "FAIL: wrong key"; exit 1; } && \
		echo "  PASS"
	@echo "Pipe test 2: SECRET_COUNT=3"
	@out=$$(cat install.sh | SECRET_COUNT=3 sh -s -- --generate-config 2>/dev/null) && \
		count=$$(echo "$$out" | grep -c '^\[\[secret\]\]') && \
		[ "$$count" -eq 3 ] || { echo "FAIL: expected 3 blocks, got $$count"; exit 1; } && \
		echo "$$out" | grep -q 'label = "secret_1"' || { echo "FAIL: missing label secret_1"; exit 1; } && \
		echo "$$out" | grep -q 'label = "secret_3"' || { echo "FAIL: missing label secret_3"; exit 1; } && \
		echo "  PASS"
	@echo "Pipe test 3: EE_DOMAIN"
	@out=$$(cat install.sh | SECRET=aabbccdd11223344aabbccdd11223344 EE_DOMAIN=google.com sh -s -- --generate-config 2>/dev/null) && \
		echo "$$out" | grep -q 'domain = "google.com"' || { echo "FAIL: missing domain"; exit 1; } && \
		echo "  PASS"
	@echo "Pipe test 4: numbered with label and limit"
	@out=$$(cat install.sh | SECRET_1=aabbccdd11223344aabbccdd11223344 SECRET_LABEL_1=family SECRET_LIMIT_1=500 sh -s -- --generate-config 2>/dev/null) && \
		echo "$$out" | grep -q 'label = "family"' || { echo "FAIL: missing label family"; exit 1; } && \
		echo "$$out" | grep -q 'limit = 500' || { echo "FAIL: missing limit 500"; exit 1; } && \
		echo "  PASS"
	@echo "All install-pipe tests passed!"

test-dc-lookup:
	$(MAKE) -C fuzz test

FUZZ_DURATION ?= 60

fuzz:
	$(MAKE) -C fuzz

fuzz-run:
	$(MAKE) -C fuzz run FUZZ_DURATION=$(FUZZ_DURATION)
