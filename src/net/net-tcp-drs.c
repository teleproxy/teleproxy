/*
    Dynamic Record Sizing (DRS) and inter-record delays for TLS transport.

    Real HTTPS servers (Cloudflare, Go stdlib, Caddy) use graduated TLS
    record sizes that mimic TCP slow-start:
      - First ~40 records:  MTU-sized  (~1450 bytes)
      - Next  ~20 records:  ramped     (~4096 bytes)
      - Remaining records:  maximum    (~16144 bytes)

    The counter resets after 1 second of inactivity, matching the pattern
    observed in production web servers.

    Inter-record delays use a Weibull distribution to model the "burst then
    tail" timing pattern of real content delivery.

    Reference: mtg proxy (9seconds/mtg), mtglib/internal/doppel/.

    Copyright 2026 Teleproxy contributors
*/

#include <assert.h>
#include <math.h>

#include "net/net-tcp-drs.h"
#include "net/net-crypto-aes.h"
#include "net/net-msg.h"
#include "common/precise-time.h"
#include "common/kprintf.h"
#include "jobs/jobs.h"

/* DRS thresholds (record indices) */
#define DRS_PHASE1_END   40   /* slow-start: MTU-sized records */
#define DRS_PHASE2_END   60   /* ramp: intermediate records */

/* DRS base record sizes (bytes) */
#define DRS_SIZE_START   1450   /* fits in one TCP segment */
#define DRS_SIZE_ACCEL   4096   /* intermediate ramp */
#define DRS_SIZE_MAX    16144   /* 16384 - TLS record overhead */

/* Inactivity timeout before resetting DRS record sizing (seconds) */
#define DRS_RESET_AFTER  1.0

/* Extended inactivity timeout before resetting DRS delay counter (seconds).
   Short idle gaps (1-10s between sticker loads) don't restart delays.
   Extended idle (>30s) re-enables delays for fresh DPI camouflage. */
#define DRS_DELAY_RESET_AFTER  30.0

/* Noise range: +-100 bytes */
#define DRS_NOISE_RANGE  201
#define DRS_NOISE_OFFSET 100

/* Skip inter-record delay if more than one max-size record remains.
   Bulk transfers (large files) keep the buffer above this threshold,
   so delays only fire near the tail — matching real HTTPS servers
   that burst content at TCP speed and vary timing only between responses. */
#define DRS_BURST_THRESHOLD  DRS_SIZE_MAX

/* Delays fire only for the first N records of each burst (after DRS
   sizing reset).  Real HTTPS servers burst cached/buffered content at
   wire speed — timing gaps appear only between responses, not between
   records within a response.  Setting this to 1 means one delay per
   burst, modelling the server-side processing pause before each new
   response. */
#define DRS_DELAY_RECORDS  1

/* Default Weibull parameters (from mtg's ok.ru measurements) */
#define DRS_DEFAULT_K      0.378
#define DRS_DEFAULT_LAMBDA 1.732   /* milliseconds */

/* --- Global state for inter-record delays --- */

int drs_delays_enabled = 0;
long long drs_delays_applied = 0;
long long drs_delays_skipped = 0;

static const double current_k = DRS_DEFAULT_K;
static const double current_lambda = DRS_DEFAULT_LAMBDA;

/* --- Weibull sampler --- */

/* Sample a delay from the Weibull distribution.
   Inverse CDF: X = lambda * (-ln(1-U))^(1/k), U ~ Uniform(0,1).
   Returns delay in seconds. */
static double drs_sample_delay (void) /* {{{ */ {
  double u = drand48_j ();
  if (u <= 0.0) { u = 1e-10; }
  if (u >= 1.0) { u = 1.0 - 1e-10; }
  double delay_ms = current_lambda * pow (-log (1.0 - u), 1.0 / current_k);
  return delay_ms * 0.001;  /* convert ms → seconds */
}
/* }}} */

double drs_delay_get_k (void) { return current_k; }
double drs_delay_get_lambda (void) { return current_lambda; }

/* --- Record sizing --- */

int drs_record_size (int record_index) /* {{{ */ {
  int base;
  if (record_index < DRS_PHASE1_END) {
    base = DRS_SIZE_START;
  } else if (record_index < DRS_PHASE2_END) {
    base = DRS_SIZE_ACCEL;
  } else {
    base = DRS_SIZE_MAX;
  }
  int noise = (int)(lrand48_j () % DRS_NOISE_RANGE) - DRS_NOISE_OFFSET;
  int size = base + noise;
  if (size < 64) {
    size = 64;
  }
  return size;
}
/* }}} */

/* --- Encrypt output with DRS and optional inter-record delays --- */

int cpu_tcp_aes_crypto_ctr128_encrypt_output_drs (connection_job_t C) /* {{{ */ {
  assert_net_cpu_thread ();
  struct connection_info *c = CONN_INFO (C);

  struct aes_crypto *T = c->crypto;
  assert (c->crypto);

  struct drs_state *drs = DRS_STATE (C);

  /* If a delay timer is pending, do not process more data yet.
     The alarm handler will clear delay_pending and re-trigger the writer. */
  if ((c->flags & C_IS_TLS) && drs->delay_pending) {
    return 0;
  }

  while (c->out.total_bytes) {
    int len = c->out.total_bytes;
    if (c->flags & C_IS_TLS) {
      assert (c->left_tls_packet_length >= 0);

      /* Reset record sizing after short inactivity */
      if (precise_now - drs->last_record_time > DRS_RESET_AFTER) {
        drs->record_index = 0;
        drs->delay_pending = 0;
      }
      /* Reset delay counter after extended inactivity */
      if (precise_now - drs->last_record_time > DRS_DELAY_RESET_AFTER) {
        drs->total_records = 0;
      }

      int max_len = drs_record_size (drs->record_index);
      if (max_len < len) {
        len = max_len;
      }

      unsigned char header[5] = {0x17, 0x03, 0x03, len >> 8, len & 255};
      rwm_push_data (&c->out_p, header, 5);
      vkprintf (2, "Send TLS-packet of length %d (DRS phase %s, record #%d)\n",
                len,
                drs->record_index < DRS_PHASE1_END ? "start" :
                drs->record_index < DRS_PHASE2_END ? "accel" : "max",
                drs->record_index);

      drs->record_index++;
      drs->total_records++;
      drs->last_record_time = precise_now;
    }

    if (rwm_encrypt_decrypt_to (&c->out, &c->out_p, len, T->write_aeskey, 1) != len) {
      fail_connection (C, -1);
      return -1;
    }

    /* Inter-record delay: fires only for the first DRS_DELAY_RECORDS records
       after a sizing reset.  Skipped during bulk transfers (buffer > burst
       threshold), sustained transfers (total >= phase-2 end), and after
       the initial burst records.  Models inter-response server processing
       pause, not per-record latency. */
    if (drs_delays_enabled && (c->flags & C_IS_TLS) && c->out.total_bytes > 0) {
      if (c->out.total_bytes > DRS_BURST_THRESHOLD || drs->total_records >= DRS_PHASE2_END || drs->record_index > DRS_DELAY_RECORDS) {
        drs_delays_skipped++;
        continue;
      }
      double delay = drs_sample_delay ();
      drs->delay_pending = 1;
      drs_delays_applied++;
      job_timer_insert (C, precise_now + delay);
      vkprintf (2, "DRS delay: %.3f ms before next record (%d bytes remain)\n", delay * 1000.0, c->out.total_bytes);
      return 0;  /* remaining data will be processed when the timer fires */
    }
  }

  return 0;
}
/* }}} */
