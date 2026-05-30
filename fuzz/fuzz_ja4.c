/* Fuzz harness for ja4_compute().
   Tests JA4 ClientHello parser against arbitrary attacker-controlled bytes:
   bounds, extension iteration, sigalgs/ALPN sub-parsers, output formatting. */

#include <stddef.h>
#include <stdint.h>

#include "net/net-ja4.h"

int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size) {
  if (size > 65536) {
    return 0;
  }

  char hash[JA4_HASH_BUF];
  ja4_compute (data, (int)size, hash);

  return 0;
}
