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


.PHONY:	all clean lint tests test test-tls test-multi-secret test-secret-limit test-ip-acl test-drs-delays test-cdn-dc test-ipv6-direct test-dc-lookup test-config-reload test-check test-link docker-image-amd64 docker-run-help-amd64 docker-image-arm64 docker-run-help-arm64 fuzz fuzz-run

EXELIST	:= ${EXE}/teleproxy


OBJECTS	=	\
  ${OBJ}/src/mtproto/mtproto-proxy.o ${OBJ}/src/mtproto/mtproto-config.o ${OBJ}/src/mtproto/mtproto-dc-table.o ${OBJ}/src/mtproto/mtproto-check.o ${OBJ}/src/mtproto/mtproto-link.o ${OBJ}/src/net/net-tcp-rpc-ext-server.o

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
	${OBJ}/src/net/net-connections.o \
	${OBJ}/src/net/net-rpc-targets.o \
	${OBJ}/src/net/net-tcp-connections.o ${OBJ}/src/net/net-tcp-drs.o ${OBJ}/src/net/net-tcp-rpc-common.o ${OBJ}/src/net/net-tcp-rpc-client.o ${OBJ}/src/net/net-tcp-rpc-server.o \
	${OBJ}/src/net/net-http-server.o ${OBJ}/src/net/net-http-parse.o ${OBJ}/src/net/net-tls-parse.o ${OBJ}/src/net/net-obfs2-parse.o ${OBJ}/src/net/net-ip-acl.o \
	${OBJ}/src/common/tl-parse.o ${OBJ}/src/common/common-stats.o \
	${OBJ}/src/engine/engine.o ${OBJ}/src/engine/engine-signals.o \
	${OBJ}/src/engine/engine-net.o \
	${OBJ}/src/engine/engine-rpc.o \
	${OBJ}/src/engine/engine-rpc-common.o \
	${OBJ}/src/net/net-thread.o ${OBJ}/src/net/net-stats.o ${OBJ}/src/common/proc-stat.o \
	${OBJ}/src/common/kprintf.o \
	${OBJ}/src/common/precise-time.o ${OBJ}/src/common/cpuid.o \
	${OBJ}/src/common/server-functions.o ${OBJ}/src/common/crc32.o \
	${OBJ}/src/common/toml/tomlc17.o ${OBJ}/src/common/toml-config.o \
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

${EXE}/teleproxy:	${OBJ}/src/mtproto/mtproto-proxy.o ${OBJ}/src/mtproto/mtproto-config.o ${OBJ}/src/mtproto/mtproto-dc-table.o ${OBJ}/src/mtproto/mtproto-check.o ${OBJ}/src/mtproto/mtproto-link.o ${OBJ}/src/net/net-tcp-rpc-ext-server.o
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

test-dc-lookup:
	$(MAKE) -C fuzz test

FUZZ_DURATION ?= 60

fuzz:
	$(MAKE) -C fuzz

fuzz-run:
	$(MAKE) -C fuzz run FUZZ_DURATION=$(FUZZ_DURATION)
