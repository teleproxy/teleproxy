/*
    DC latency probes — periodic TCP handshake measurement to Telegram DCs.

    Teleproxy is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.
*/

#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "common/platform.h"
#include "common/common-stats.h"
#include "kprintf.h"
#include "precise-time.h"
#include "mtproto/mtproto-dc-table.h"
#include "mtproto/mtproto-dc-probes.h"

#define DC_PROBE_COUNT     5
#define HISTOGRAM_BUCKETS  11
#define PROBE_TIMEOUT_SEC  10.0

static const double bucket_bounds[HISTOGRAM_BUCKETS] = {
  0.005, 0.010, 0.025, 0.050, 0.100,
  0.250, 0.500, 1.0, 2.5, 5.0, 10.0
};

struct dc_histogram {
  long long bucket[HISTOGRAM_BUCKETS];  /* non-cumulative per-bucket counts */
  long long count;
  double sum;
  double last;
  long long failures;
};

struct dc_probe_state {
  int fd;            /* -1 when no probe in flight */
  double start_time; /* get_utime_monotonic() at connect() */
};

static int probe_interval;          /* 0 = disabled */
static int last_probe_start;        /* `now` value when last batch started */
static int probes_pending;
static struct dc_probe_state probes[DC_PROBE_COUNT];
static struct dc_histogram histograms[DC_PROBE_COUNT];

static void record_latency (int idx, double latency) {
  struct dc_histogram *h = &histograms[idx];
  h->count++;
  h->sum += latency;
  h->last = latency;
  for (int b = 0; b < HISTOGRAM_BUCKETS; b++) {
    if (latency <= bucket_bounds[b]) {
      h->bucket[b]++;
      return;
    }
  }
  /* latency exceeds all buckets — counted in h->count (+Inf) only */
}

static void start_probe (int idx) {
  int dc_id = idx + 1;
  const struct dc_entry *dc = direct_dc_lookup (dc_id);
  if (!dc || dc->addr_count == 0 || dc->addrs[0].ipv4 == 0) {
    histograms[idx].failures++;
    return;
  }

  int fd = socket (AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    histograms[idx].failures++;
    return;
  }
  platform_socket_post_create (fd);

  struct sockaddr_in addr;
  memset (&addr, 0, sizeof (addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = dc->addrs[0].ipv4;
  addr.sin_port = htons (dc->addrs[0].port);

  probes[idx].start_time = get_utime_monotonic ();

  int ret = connect (fd, (struct sockaddr *)&addr, sizeof (addr));
  if (ret == 0) {
    /* Connected immediately */
    double latency = get_utime_monotonic () - probes[idx].start_time;
    record_latency (idx, latency);
    vkprintf (1, "DC probe: DC %d connected immediately (%.1fms)\n", dc_id, latency * 1000);
    close (fd);
    probes[idx].fd = -1;
    return;
  }
  if (errno != EINPROGRESS) {
    vkprintf (1, "DC probe: DC %d connect failed: %m\n", dc_id);
    histograms[idx].failures++;
    close (fd);
    probes[idx].fd = -1;
    return;
  }

  vkprintf (2, "DC probe: DC %d connect in progress (fd=%d)\n", dc_id, fd);
  probes[idx].fd = fd;
  probes_pending++;
}

void dc_probes_init (int interval_seconds) {
  probe_interval = interval_seconds;
  last_probe_start = 0;
  probes_pending = 0;
  memset (histograms, 0, sizeof (histograms));
  for (int i = 0; i < DC_PROBE_COUNT; i++) {
    probes[i].fd = -1;
  }
}

void dc_probes_cron (void) {
  if (probe_interval <= 0) {
    return;
  }
  if (last_probe_start && now - last_probe_start < probe_interval) {
    return;
  }
  last_probe_start = now;

  for (int i = 0; i < DC_PROBE_COUNT; i++) {
    if (probes[i].fd >= 0) {
      /* Previous probe still in flight — count as timeout */
      close (probes[i].fd);
      probes[i].fd = -1;
      probes_pending--;
      histograms[i].failures++;
    }
    start_probe (i);
  }
}

void dc_probes_check (void) {
  if (probes_pending <= 0) {
    return;
  }

  double now_mono = get_utime_monotonic ();

  for (int i = 0; i < DC_PROBE_COUNT; i++) {
    if (probes[i].fd < 0) {
      continue;
    }

    /* Timeout check */
    if (now_mono - probes[i].start_time > PROBE_TIMEOUT_SEC) {
      close (probes[i].fd);
      probes[i].fd = -1;
      probes_pending--;
      histograms[i].failures++;
      continue;
    }

    struct pollfd pfd = { .fd = probes[i].fd, .events = POLLOUT };
    int r = poll (&pfd, 1, 0);
    if (r <= 0) {
      continue;
    }

    double latency = get_utime_monotonic () - probes[i].start_time;

    int err = 0;
    socklen_t errlen = sizeof (err);
    getsockopt (probes[i].fd, SOL_SOCKET, SO_ERROR, &err, &errlen);

    close (probes[i].fd);
    probes[i].fd = -1;
    probes_pending--;

    if (err) {
      vkprintf (1, "DC probe: DC %d connect error: %s\n", i + 1, strerror (err));
      histograms[i].failures++;
    } else {
      vkprintf (1, "DC probe: DC %d latency %.1fms\n", i + 1, latency * 1000);
      record_latency (i, latency);
    }
  }
}

void dc_probes_write_prometheus (stats_buffer_t *sb) {
  if (probe_interval <= 0) {
    return;
  }

  sb_printf (sb,
    "# HELP teleproxy_dc_latency_seconds TCP handshake latency to Telegram DCs.\n"
    "# TYPE teleproxy_dc_latency_seconds histogram\n");

  for (int i = 0; i < DC_PROBE_COUNT; i++) {
    int dc = i + 1;
    struct dc_histogram *h = &histograms[i];
    long long cumulative = 0;
    for (int b = 0; b < HISTOGRAM_BUCKETS; b++) {
      cumulative += h->bucket[b];
      sb_printf (sb,
        "teleproxy_dc_latency_seconds_bucket{dc=\"%d\",le=\"%.3f\"} %lld\n",
        dc, bucket_bounds[b], cumulative);
    }
    sb_printf (sb,
      "teleproxy_dc_latency_seconds_bucket{dc=\"%d\",le=\"+Inf\"} %lld\n"
      "teleproxy_dc_latency_seconds_sum{dc=\"%d\"} %.6f\n"
      "teleproxy_dc_latency_seconds_count{dc=\"%d\"} %lld\n",
      dc, h->count,
      dc, h->sum,
      dc, h->count);
  }

  sb_printf (sb,
    "# HELP teleproxy_dc_probe_failures_total Failed DC probe attempts.\n"
    "# TYPE teleproxy_dc_probe_failures_total counter\n");
  for (int i = 0; i < DC_PROBE_COUNT; i++) {
    sb_printf (sb,
      "teleproxy_dc_probe_failures_total{dc=\"%d\"} %lld\n",
      i + 1, histograms[i].failures);
  }

  sb_printf (sb,
    "# HELP teleproxy_dc_latency_last_seconds Most recent probe latency per DC.\n"
    "# TYPE teleproxy_dc_latency_last_seconds gauge\n");
  for (int i = 0; i < DC_PROBE_COUNT; i++) {
    sb_printf (sb,
      "teleproxy_dc_latency_last_seconds{dc=\"%d\"} %.6f\n",
      i + 1, histograms[i].last);
  }
}

void dc_probes_write_text_stats (stats_buffer_t *sb) {
  if (probe_interval <= 0) {
    return;
  }

  sb_printf (sb, "dc_probe_interval\t%d\n", probe_interval);
  for (int i = 0; i < DC_PROBE_COUNT; i++) {
    int dc = i + 1;
    struct dc_histogram *h = &histograms[i];
    sb_printf (sb,
      "dc%d_probe_latency_last\t%.6f\n"
      "dc%d_probe_latency_avg\t%.6f\n"
      "dc%d_probe_count\t%lld\n"
      "dc%d_probe_failures\t%lld\n",
      dc, h->last,
      dc, h->count ? h->sum / h->count : 0.0,
      dc, h->count,
      dc, h->failures);
  }
}
