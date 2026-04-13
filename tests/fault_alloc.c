/*
 * Fault injection for alloc_msg_buffer testing.
 *
 * LD_PRELOAD this to make malloc() return NULL for allocations of
 * MSG_BUFFERS_CHUNK_SIZE after a configurable number of successes.
 * This reliably triggers the assert(0) in net_server_socket_reader
 * and other allocation-failure code paths without needing extreme load.
 *
 * Environment variables:
 *   FAULT_ALLOC_FAIL_AFTER=N  — allow N chunk allocations, then fail
 *
 * Build:
 *   cc -shared -fPIC -o fault_alloc.so fault_alloc.c -ldl
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdlib.h>
#include <stdio.h>

/* Must match MSG_BUFFERS_CHUNK_SIZE in net-msg-buffers.h */
#define CHUNK_SIZE ((1L << 21) - 64)

static int fail_after = 0;
static int chunk_count = 0;
static void *(*real_malloc)(size_t) = NULL;

__attribute__((constructor))
static void fault_alloc_init(void) {
    real_malloc = dlsym(RTLD_NEXT, "malloc");
    const char *val = getenv("FAULT_ALLOC_FAIL_AFTER");
    if (val) {
        fail_after = atoi(val);
        fprintf(stderr, "fault_alloc: will fail chunk allocations after %d\n",
                fail_after);
    }
}

void *malloc(size_t size) {
    if (!real_malloc) {
        /* Before constructor runs — use a static buffer for tiny allocs */
        static char bootstrap[4096];
        static size_t offset = 0;
        if (offset + size <= sizeof(bootstrap)) {
            void *p = bootstrap + offset;
            offset += (size + 15) & ~15;
            return p;
        }
        return NULL;
    }

    if (fail_after > 0 && size == CHUNK_SIZE) {
        chunk_count++;
        if (chunk_count > fail_after) {
            fprintf(stderr, "fault_alloc: failing chunk alloc #%d (limit %d)\n",
                    chunk_count, fail_after);
            return NULL;
        }
    }

    return real_malloc(size);
}
