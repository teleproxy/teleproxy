/*
    Diagnostic / self-check subcommand for Teleproxy.

    Validates configuration and tests connectivity before accepting
    clients.  Runs independently of the engine lifecycle.

    Usage:
      teleproxy check --config config.toml
      teleproxy check --direct -S <secret> [-D <domain>] [--dc-override DC:HOST:PORT]
*/

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <openssl/rand.h>

#include "common/platform.h"
#include "common/toml-config.h"
#include "mtproto/mtproto-dc-table.h"
#include "net/net-tls-parse.h"

/* ── SOCKS5 upstream (blocking, for check command) ───────────────── */

static int make_nonblocking_socket (int af, int type);

static struct {
  int enabled;
  struct sockaddr_in addr;
  char user[256];
  char pass[256];
} check_socks5;

/* Parse socks5://[user:pass@]host:port into check_socks5.
   Returns 0 on success, -1 on error. */
static int check_socks5_parse (const char *url) {
  memset (&check_socks5, 0, sizeof (check_socks5));

  const char *p = url;
  if (strncmp (p, "socks5h://", 10) == 0) {
    p += 10;
  } else if (strncmp (p, "socks5://", 9) == 0) {
    p += 9;
  } else {
    return -1;
  }

  const char *at = strchr (p, '@');
  if (at) {
    const char *colon = memchr (p, ':', at - p);
    if (!colon || colon == p) { return -1; }
    int ulen = (int)(colon - p);
    int plen = (int)(at - colon - 1);
    if (ulen <= 0 || ulen > 255 || plen < 0 || plen > 255) { return -1; }
    memcpy (check_socks5.user, p, ulen);
    check_socks5.user[ulen] = '\0';
    if (plen > 0) { memcpy (check_socks5.pass, colon + 1, plen); }
    check_socks5.pass[plen] = '\0';
    p = at + 1;
  }

  const char *colon = strrchr (p, ':');
  if (!colon || colon == p) { return -1; }
  int port = atoi (colon + 1);
  if (port <= 0 || port > 65535) { return -1; }

  char host[256];
  int hlen = (int)(colon - p);
  if (hlen <= 0 || hlen >= (int)sizeof (host)) { return -1; }
  memcpy (host, p, hlen);
  host[hlen] = '\0';

  struct addrinfo hints = {.ai_family = AF_INET, .ai_socktype = SOCK_STREAM};
  struct addrinfo *ai;
  if (getaddrinfo (host, NULL, &hints, &ai) != 0) { return -1; }

  check_socks5.addr.sin_family = AF_INET;
  check_socks5.addr.sin_port = htons (port);
  check_socks5.addr.sin_addr = ((struct sockaddr_in *)ai->ai_addr)->sin_addr;
  freeaddrinfo (ai);
  check_socks5.enabled = 1;
  return 0;
}

/* Blocking send with timeout.  Returns 0 on success, -1 on error. */
static int blocking_sendall (int fd, const void *buf, int len, int timeout_ms) {
  const unsigned char *p = buf;
  int remaining = len;
  while (remaining > 0) {
    fd_set wfds;
    FD_ZERO (&wfds);
    FD_SET (fd, &wfds);
    struct timeval tv = {.tv_sec = timeout_ms / 1000,
                         .tv_usec = (timeout_ms % 1000) * 1000};
    int r = select (fd + 1, NULL, &wfds, NULL, &tv);
    if (r <= 0) { return -1; }
    ssize_t n = write (fd, p, remaining);
    if (n <= 0) { return -1; }
    p += n;
    remaining -= (int)n;
  }
  return 0;
}

/* Blocking recv with timeout.  Returns 0 on success, -1 on error. */
static int blocking_recvall (int fd, void *buf, int len, int timeout_ms) {
  unsigned char *p = buf;
  int remaining = len;
  while (remaining > 0) {
    fd_set rfds;
    FD_ZERO (&rfds);
    FD_SET (fd, &rfds);
    struct timeval tv = {.tv_sec = timeout_ms / 1000,
                         .tv_usec = (timeout_ms % 1000) * 1000};
    int r = select (fd + 1, &rfds, NULL, NULL, &tv);
    if (r <= 0) { return -1; }
    ssize_t n = read (fd, p, remaining);
    if (n <= 0) { return -1; }
    p += n;
    remaining -= (int)n;
  }
  return 0;
}

/* Connect to target DC through SOCKS5 proxy.
   Returns elapsed ms on success, -1 on failure (errbuf filled). */
static int timed_socks5_connect (const struct sockaddr *target_sa,
                                 socklen_t target_sa_len __attribute__((unused)),
                                 int target_af __attribute__((unused)),
                                 int timeout_ms,
                                 char *errbuf, int errlen) {
  struct timeval before;
  gettimeofday (&before, NULL);

  /* Connect to the SOCKS5 proxy itself */
  int fd = make_nonblocking_socket (AF_INET, SOCK_STREAM);
  if (fd < 0) {
    snprintf (errbuf, errlen, "socks5: socket: %s", strerror (errno));
    return -1;
  }

  int ret = connect (fd, (struct sockaddr *)&check_socks5.addr,
                     sizeof (check_socks5.addr));
  if (ret != 0 && errno == EINPROGRESS) {
    fd_set wfds;
    FD_ZERO (&wfds);
    FD_SET (fd, &wfds);
    struct timeval tv = {.tv_sec = timeout_ms / 1000,
                         .tv_usec = (timeout_ms % 1000) * 1000};
    ret = select (fd + 1, NULL, &wfds, NULL, &tv);
    if (ret <= 0) { close (fd); snprintf (errbuf, errlen, "socks5: connect timeout"); return -1; }
    int err = 0; socklen_t elen = sizeof (err);
    getsockopt (fd, SOL_SOCKET, SO_ERROR, &err, &elen);
    if (err) { close (fd); snprintf (errbuf, errlen, "socks5: connect: %s", strerror (err)); return -1; }
  } else if (ret != 0) {
    int saved = errno; close (fd);
    snprintf (errbuf, errlen, "socks5: connect: %s", strerror (saved));
    return -1;
  }

  /* SOCKS5 greeting */
  int has_auth = check_socks5.user[0] != '\0';
  if (has_auth) {
    unsigned char greet[] = {0x05, 0x02, 0x00, 0x02};
    if (blocking_sendall (fd, greet, 4, timeout_ms) < 0) {
      close (fd); snprintf (errbuf, errlen, "socks5: greeting send failed"); return -1;
    }
  } else {
    unsigned char greet[] = {0x05, 0x01, 0x00};
    if (blocking_sendall (fd, greet, 3, timeout_ms) < 0) {
      close (fd); snprintf (errbuf, errlen, "socks5: greeting send failed"); return -1;
    }
  }

  unsigned char resp[2];
  if (blocking_recvall (fd, resp, 2, timeout_ms) < 0) {
    close (fd); snprintf (errbuf, errlen, "socks5: greeting recv failed"); return -1;
  }
  if (resp[0] != 0x05) {
    close (fd); snprintf (errbuf, errlen, "socks5: bad version %d", resp[0]); return -1;
  }

  if (resp[1] == 0x02) {
    /* Username/password auth (RFC 1929) */
    if (!has_auth) {
      close (fd); snprintf (errbuf, errlen, "socks5: server requires auth"); return -1;
    }
    int ulen = (int)strlen (check_socks5.user);
    int plen = (int)strlen (check_socks5.pass);
    unsigned char auth[515];
    auth[0] = 0x01;
    auth[1] = (unsigned char)ulen;
    memcpy (auth + 2, check_socks5.user, ulen);
    auth[2 + ulen] = (unsigned char)plen;
    memcpy (auth + 3 + ulen, check_socks5.pass, plen);
    if (blocking_sendall (fd, auth, 3 + ulen + plen, timeout_ms) < 0) {
      close (fd); snprintf (errbuf, errlen, "socks5: auth send failed"); return -1;
    }
    unsigned char aresp[2];
    if (blocking_recvall (fd, aresp, 2, timeout_ms) < 0) {
      close (fd); snprintf (errbuf, errlen, "socks5: auth recv failed"); return -1;
    }
    if (aresp[1] != 0x00) {
      close (fd); snprintf (errbuf, errlen, "socks5: auth rejected"); return -1;
    }
  } else if (resp[1] != 0x00) {
    close (fd); snprintf (errbuf, errlen, "socks5: no acceptable auth (0x%02x)", resp[1]); return -1;
  }

  /* SOCKS5 CONNECT */
  const struct sockaddr_in *sa4 = (const struct sockaddr_in *)target_sa;
  unsigned char conn[10];
  conn[0] = 0x05;  /* version */
  conn[1] = 0x01;  /* CONNECT */
  conn[2] = 0x00;  /* reserved */
  conn[3] = 0x01;  /* ATYP: IPv4 */
  memcpy (conn + 4, &sa4->sin_addr, 4);
  conn[8] = (unsigned char)(ntohs (sa4->sin_port) >> 8);
  conn[9] = (unsigned char)(ntohs (sa4->sin_port) & 0xff);
  if (blocking_sendall (fd, conn, 10, timeout_ms) < 0) {
    close (fd); snprintf (errbuf, errlen, "socks5: CONNECT send failed"); return -1;
  }

  /* Read CONNECT response: 4 header + variable addr + 2 port */
  unsigned char cresp[10];
  if (blocking_recvall (fd, cresp, 10, timeout_ms) < 0) {
    close (fd); snprintf (errbuf, errlen, "socks5: CONNECT recv failed"); return -1;
  }
  if (cresp[1] != 0x00) {
    close (fd); snprintf (errbuf, errlen, "socks5: CONNECT failed (0x%02x)", cresp[1]); return -1;
  }

  struct timeval after;
  gettimeofday (&after, NULL);
  int ms = (int)((after.tv_sec - before.tv_sec) * 1000 +
                 (after.tv_usec - before.tv_usec) / 1000);
  close (fd);
  return ms;
}

/* ── result tracking ──────────────────────────────────────────────── */

enum check_status { CHECK_PASS, CHECK_WARN, CHECK_FAIL, CHECK_SKIP };

struct check_result {
  enum check_status status;
  char label[128];
  char detail[256];
};

#define MAX_CHECK_RESULTS 48

struct check_context {
  int is_direct;
  int secret_count;
  int domain_count;
  char domains[TOML_CONFIG_MAX_DOMAINS][256];
  int domain_ports[TOML_CONFIG_MAX_DOMAINS];
  char domain_ips[TOML_CONFIG_MAX_DOMAINS][INET6_ADDRSTRLEN];

  struct check_result results[MAX_CHECK_RESULTS];
  int result_count;
  int pass_count;
  int fail_count;
  int warn_count;
  int skip_count;
};

static void check_record (struct check_context *ctx, enum check_status status,
                          const char *label, const char *fmt, ...) {
  if (ctx->result_count >= MAX_CHECK_RESULTS) {
    return;
  }
  struct check_result *r = &ctx->results[ctx->result_count++];
  r->status = status;
  snprintf (r->label, sizeof (r->label), "%s", label);

  va_list ap;
  va_start (ap, fmt);
  vsnprintf (r->detail, sizeof (r->detail), fmt, ap);
  va_end (ap);

  switch (status) {
  case CHECK_PASS: ctx->pass_count++; break;
  case CHECK_WARN: ctx->warn_count++; break;
  case CHECK_FAIL: ctx->fail_count++; break;
  case CHECK_SKIP: ctx->skip_count++; break;
  }
}

/* ── helpers ──────────────────────────────────────────────────────── */

static int make_nonblocking_socket (int af, int type) {
  int fd = socket (af, type | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  if (fd >= 0) {
    platform_socket_post_create (fd);
  }
  return fd;
}

/* Timed TCP connect.  Returns elapsed ms on success, -1 on failure.
   On failure, errbuf is filled with the reason. */
static int timed_tcp_connect (const struct sockaddr *sa, socklen_t sa_len,
                              int af, int timeout_ms,
                              char *errbuf, int errlen) {
  int fd = make_nonblocking_socket (af, SOCK_STREAM);
  if (fd < 0) {
    snprintf (errbuf, errlen, "socket: %s", strerror (errno));
    return -1;
  }

  struct timeval before;
  gettimeofday (&before, NULL);

  int ret = connect (fd, sa, sa_len);
  if (ret == 0) {
    /* immediate connect */
  } else if (errno == EINPROGRESS) {
    fd_set wfds;
    FD_ZERO (&wfds);
    FD_SET (fd, &wfds);
    struct timeval tv = {.tv_sec = timeout_ms / 1000,
                         .tv_usec = (timeout_ms % 1000) * 1000};

    ret = select (fd + 1, NULL, &wfds, NULL, &tv);
    if (ret <= 0) {
      close (fd);
      snprintf (errbuf, errlen, "timeout");
      return -1;
    }

    int err = 0;
    socklen_t errlen2 = sizeof (err);
    getsockopt (fd, SOL_SOCKET, SO_ERROR, &err, &errlen2);
    if (err) {
      close (fd);
      snprintf (errbuf, errlen, "%s", strerror (err));
      return -1;
    }
  } else {
    int saved = errno;
    close (fd);
    snprintf (errbuf, errlen, "%s", strerror (saved));
    return -1;
  }

  struct timeval after;
  gettimeofday (&after, NULL);
  int ms = (int)((after.tv_sec - before.tv_sec) * 1000 +
                 (after.tv_usec - before.tv_usec) / 1000);

  close (fd);
  return ms;
}

/* ── check: configuration ─────────────────────────────────────────── */

static void check_config (struct check_context *ctx) {
  const char *mode = ctx->is_direct ? "direct" : "relay";
  if (ctx->secret_count == 0) {
    check_record (ctx, CHECK_WARN, "Configuration",
                  "mode: %s, 0 secrets, %d domain%s (no secrets configured)",
                  mode, ctx->domain_count,
                  ctx->domain_count == 1 ? "" : "s");
  } else {
    check_record (ctx, CHECK_PASS, "Configuration",
                  "mode: %s, %d secret%s, %d domain%s",
                  mode,
                  ctx->secret_count, ctx->secret_count == 1 ? "" : "s",
                  ctx->domain_count, ctx->domain_count == 1 ? "" : "s");
  }
  if (check_socks5.enabled) {
    char ip[INET_ADDRSTRLEN];
    inet_ntop (AF_INET, &check_socks5.addr.sin_addr, ip, sizeof (ip));
    check_record (ctx, CHECK_PASS, "SOCKS5 Proxy",
                  "%s:%d%s", ip, ntohs (check_socks5.addr.sin_port),
                  check_socks5.user[0] ? " (auth)" : "");
  }
}

/* ── check: DC connectivity ───────────────────────────────────────── */

static void check_dc (struct check_context *ctx, int dc_id) {
  const struct dc_entry *dc = direct_dc_lookup (dc_id);
  if (!dc || dc->addr_count == 0) {
    char label[32];
    snprintf (label, sizeof (label), "DC %d", dc_id);
    check_record (ctx, CHECK_FAIL, label, "unknown DC");
    return;
  }

  const struct dc_addr *addr = &dc->addrs[0];
  static const unsigned char zero_ipv6[16] = {};

  char ip_str[INET6_ADDRSTRLEN] = "?";
  struct sockaddr_storage ss;
  socklen_t ss_len;
  int af;

  if (addr->ipv4 != 0) {
    af = AF_INET;
    struct sockaddr_in *sa4 = (struct sockaddr_in *)&ss;
    memset (sa4, 0, sizeof (*sa4));
    sa4->sin_family = AF_INET;
    sa4->sin_port = htons (addr->port);
    sa4->sin_addr.s_addr = addr->ipv4;
    ss_len = sizeof (*sa4);
    inet_ntop (AF_INET, &sa4->sin_addr, ip_str, sizeof (ip_str));
  } else if (memcmp (addr->ipv6, zero_ipv6, 16) != 0) {
    af = AF_INET6;
    struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&ss;
    memset (sa6, 0, sizeof (*sa6));
    sa6->sin6_family = AF_INET6;
    sa6->sin6_port = htons (addr->port);
    memcpy (&sa6->sin6_addr, addr->ipv6, 16);
    ss_len = sizeof (*sa6);
    inet_ntop (AF_INET6, &sa6->sin6_addr, ip_str, sizeof (ip_str));
  } else {
    char label[32];
    snprintf (label, sizeof (label), "DC %d", dc_id);
    check_record (ctx, CHECK_FAIL, label, "no address available");
    return;
  }

  char label[64];
  snprintf (label, sizeof (label), "DC %d (%s)", dc_id, ip_str);

  char errbuf[128];
  int ms;
  if (check_socks5.enabled) {
    ms = timed_socks5_connect ((struct sockaddr *)&ss, ss_len, af, 5000,
                               errbuf, sizeof (errbuf));
  } else {
    ms = timed_tcp_connect ((struct sockaddr *)&ss, ss_len, af, 5000,
                            errbuf, sizeof (errbuf));
  }
  if (ms < 0) {
    check_record (ctx, CHECK_FAIL, label, "%s", errbuf);
  } else {
    check_record (ctx, CHECK_PASS, label, "%dms%s", ms,
                  check_socks5.enabled ? " (via socks5)" : "");
  }
}

/* ── check: NTP clock drift ───────────────────────────────────────── */

#define NTP_UNIX_EPOCH_DIFF 2208988800UL

static void check_ntp (struct check_context *ctx) {
  struct addrinfo hints = {0}, *res = NULL;
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  if (getaddrinfo ("pool.ntp.org", "123", &hints, &res) != 0 || !res) {
    check_record (ctx, CHECK_WARN, "Clock sync",
                  "cannot resolve pool.ntp.org");
    return;
  }

  int fd = socket (res->ai_family, SOCK_DGRAM, IPPROTO_UDP);
  if (fd < 0) {
    freeaddrinfo (res);
    check_record (ctx, CHECK_WARN, "Clock sync",
                  "socket: %s", strerror (errno));
    return;
  }

  struct timeval tv = {.tv_sec = 3};
  setsockopt (fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof (tv));
  setsockopt (fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof (tv));

  /* NTP v4 request: 48 bytes, li_vn_mode = 0x23 */
  unsigned char pkt[48] = {0};
  pkt[0] = 0x23;

  if (sendto (fd, pkt, sizeof (pkt), 0, res->ai_addr,
              res->ai_addrlen) < 0) {
    close (fd);
    freeaddrinfo (res);
    check_record (ctx, CHECK_WARN, "Clock sync",
                  "NTP send failed: %s", strerror (errno));
    return;
  }
  freeaddrinfo (res);

  unsigned char reply[48];
  ssize_t n = recv (fd, reply, sizeof (reply), 0);
  close (fd);

  if (n < (ssize_t)sizeof (reply)) {
    check_record (ctx, CHECK_WARN, "Clock sync", "NTP timeout or short reply");
    return;
  }

  /* transmit timestamp: seconds at offset 40, network byte order */
  unsigned int ntp_secs = ((unsigned)reply[40] << 24) |
                          ((unsigned)reply[41] << 16) |
                          ((unsigned)reply[42] << 8) |
                          (unsigned)reply[43];
  if (ntp_secs < NTP_UNIX_EPOCH_DIFF) {
    check_record (ctx, CHECK_WARN, "Clock sync", "invalid NTP response");
    return;
  }

  time_t ntp_time = (time_t)(ntp_secs - NTP_UNIX_EPOCH_DIFF);
  time_t local_time = time (NULL);
  double drift = difftime (local_time, ntp_time);
  double abs_drift = drift < 0 ? -drift : drift;

  if (abs_drift > 120.0) {
    check_record (ctx, CHECK_FAIL, "Clock sync",
                  "drift %.1fs exceeds 120s anti-replay window", abs_drift);
  } else if (abs_drift > 5.0) {
    check_record (ctx, CHECK_WARN, "Clock sync",
                  "drift %.1fs (limit 120s)", abs_drift);
  } else {
    check_record (ctx, CHECK_PASS, "Clock sync",
                  "drift %.1fs, limit 120s", abs_drift);
  }
}

/* ── check: TLS domain probe ─────────────────────────────────────── */

/* Build a minimal TLS 1.3 ClientHello for domain probing.
   Matches the proxy's 517-byte fingerprint but uses random bytes
   for the key_share instead of real X25519.
   Saves the session_id (32 bytes) for ServerHello validation. */
#define CHECK_TLS_REQUEST_LENGTH 517

static unsigned char *check_build_client_hello (const char *domain,
                                                unsigned char session_id[32]) {
  unsigned char *buf = calloc (1, CHECK_TLS_REQUEST_LENGTH);
  if (!buf) return NULL;
  int pos = 0;
  int domain_len = (int)strlen (domain);

  /* GREASE values */
  unsigned char greases[7];
  RAND_bytes (greases, sizeof (greases));
  for (int i = 0; i < 7; i++) {
    greases[i] = (unsigned char)((greases[i] & 0xF0) | 0x0A);
  }
  if (greases[1] == greases[0]) greases[1] ^= 0x10;
  if (greases[3] == greases[2]) greases[3] ^= 0x10;
  if (greases[5] == greases[4]) greases[5] ^= 0x10;

#define W(data, len) do { memcpy (buf + pos, data, len); pos += (len); } while (0)
#define WB(b) do { buf[pos++] = (unsigned char)(b); } while (0)
#define W2(v) do { buf[pos++] = (unsigned char)((v) >> 8); buf[pos++] = (unsigned char)((v) & 0xFF); } while (0)
#define WRAND(n) do { RAND_bytes (buf + pos, n); pos += (n); } while (0)
#define WGREASE(i) do { buf[pos++] = greases[i]; buf[pos++] = greases[i]; } while (0)

  /* Record header: TLS 1.0 */
  W ("\x16\x03\x01\x02\x00", 5);

  /* Handshake: ClientHello */
  W ("\x01\x00\x01\xfc\x03\x03", 6);

  /* Client random (32 bytes) */
  WRAND (32);

  /* Session ID (32 bytes) — saved for ServerHello validation */
  WB (0x20);
  RAND_bytes (buf + pos, 32);
  memcpy (session_id, buf + pos, 32);
  pos += 32;

  /* Cipher suites (0x22 = 34 bytes: 2 GREASE + 32 real) */
  W2 (0x0022);
  WGREASE (0);
  /* 32 bytes: TLS 1.3 suites + legacy suites, then compression + extensions length */
  W ("\x13\x01\x13\x02\x13\x03\xc0\x2b\xc0\x2f\xc0\x2c\xc0\x30"
     "\xcc\xa9\xcc\xa8\xc0\x13\xc0\x14\x00\x9c\x00\x9d\x00\x2f"
     "\x00\x35\x00\x0a"
     "\x01\x00"          /* compression: 1 method, null */
     "\x01\x91", 36);    /* extensions length: 401 */

  /* GREASE extension */
  WGREASE (2);
  W ("\x00\x00", 2);

  /* SNI extension */
  W ("\x00\x00", 2);
  W2 (domain_len + 5);
  W2 (domain_len + 3);
  WB (0x00);
  W2 (domain_len);
  W (domain, domain_len);

  /* ec_point_formats + supported_groups + ... (fixed block) */
  W ("\x00\x17\x00\x00\xff\x01\x00\x01\x00\x00\x0a\x00\x0a\x00\x08", 15);
  WGREASE (4);
  W ("\x00\x1d\x00\x17\x00\x18"
     "\x00\x0b\x00\x02\x01\x00"
     "\x00\x23\x00\x00"
     "\x00\x10\x00\x0e\x00\x0c\x02\x68\x32\x08\x68\x74\x74\x70\x2f\x31\x2e\x31"
     "\x00\x05\x00\x05\x01\x00\x00\x00\x00"
     "\x00\x0d\x00\x14\x00\x12\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01\x02\x01"
     "\x00\x12\x00\x00"
     "\x00\x33\x00\x2b\x00\x29", 77);
  WGREASE (4);
  W ("\x00\x01\x00\x00\x1d\x00\x20", 7);

  /* key_share: 32 random bytes (not real X25519, just for probing) */
  WRAND (32);

  W ("\x00\x2d\x00\x02\x01\x01"
     "\x00\x2b\x00\x0b\x0a", 11);
  WGREASE (6);
  W ("\x03\x04\x03\x03\x03\x02\x03\x01"
     "\x00\x1b\x00\x03\x02\x00\x02", 15);
  WGREASE (3);
  W ("\x00\x01\x00\x00\x15", 5);

  /* Padding to 517 bytes */
  int pad_len = CHECK_TLS_REQUEST_LENGTH - 2 - pos;
  if (pad_len >= 0) {
    W2 (pad_len);
    /* rest is already zero from calloc */
    pos = CHECK_TLS_REQUEST_LENGTH;
  }

#undef W
#undef WB
#undef W2
#undef WRAND
#undef WGREASE

  return buf;
}

static void check_tls_domain (struct check_context *ctx, int idx) {
  const char *domain = ctx->domains[idx];
  int port = ctx->domain_ports[idx];

  char label[80];
  snprintf (label, sizeof (label), "TLS %s", domain);

  /* Resolve */
  struct addrinfo hints = {0}, *res = NULL;
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  char port_str[8];
  snprintf (port_str, sizeof (port_str), "%d", port);

  if (getaddrinfo (domain, port_str, &hints, &res) != 0 || !res) {
    check_record (ctx, CHECK_FAIL, label,
                  "cannot resolve %s", domain);
    return;
  }

  /* Save resolved IP for SNI check */
  if (res->ai_family == AF_INET) {
    struct sockaddr_in *sa4 = (struct sockaddr_in *)res->ai_addr;
    inet_ntop (AF_INET, &sa4->sin_addr, ctx->domain_ips[idx],
               sizeof (ctx->domain_ips[idx]));
  } else if (res->ai_family == AF_INET6) {
    struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)res->ai_addr;
    inet_ntop (AF_INET6, &sa6->sin6_addr, ctx->domain_ips[idx],
               sizeof (ctx->domain_ips[idx]));
  }

  /* TCP connect */
  int fd = make_nonblocking_socket (res->ai_family, SOCK_STREAM);
  if (fd < 0) {
    freeaddrinfo (res);
    check_record (ctx, CHECK_FAIL, label,
                  "socket: %s", strerror (errno));
    return;
  }

  int ret = connect (fd, res->ai_addr, res->ai_addrlen);
  freeaddrinfo (res);

  if (ret != 0 && errno != EINPROGRESS) {
    close (fd);
    check_record (ctx, CHECK_FAIL, label,
                  "connect: %s", strerror (errno));
    return;
  }

  if (errno == EINPROGRESS) {
    fd_set wfds;
    FD_ZERO (&wfds);
    FD_SET (fd, &wfds);
    struct timeval tv = {.tv_sec = 5};
    ret = select (fd + 1, NULL, &wfds, NULL, &tv);
    if (ret <= 0) {
      close (fd);
      check_record (ctx, CHECK_FAIL, label, "connect timeout");
      return;
    }
    int err = 0;
    socklen_t elen = sizeof (err);
    getsockopt (fd, SOL_SOCKET, SO_ERROR, &err, &elen);
    if (err) {
      close (fd);
      check_record (ctx, CHECK_FAIL, label,
                    "connect: %s", strerror (err));
      return;
    }
  }

  /* Make blocking for the TLS exchange with a timeout */
  int flags = fcntl (fd, F_GETFL);
  fcntl (fd, F_SETFL, flags & ~O_NONBLOCK);
  struct timeval rw_tv = {.tv_sec = 5};
  setsockopt (fd, SOL_SOCKET, SO_RCVTIMEO, &rw_tv, sizeof (rw_tv));
  setsockopt (fd, SOL_SOCKET, SO_SNDTIMEO, &rw_tv, sizeof (rw_tv));

  /* Build and send ClientHello */
  unsigned char session_id[32];
  unsigned char *hello = check_build_client_hello (domain, session_id);
  if (!hello) {
    close (fd);
    check_record (ctx, CHECK_FAIL, label, "out of memory");
    return;
  }

  if (write (fd, hello, CHECK_TLS_REQUEST_LENGTH) != CHECK_TLS_REQUEST_LENGTH) {
    free (hello);
    close (fd);
    check_record (ctx, CHECK_FAIL, label,
                  "send ClientHello: %s", strerror (errno));
    return;
  }
  free (hello);

  /* Read ServerHello: 5-byte TLS record header first */
  unsigned char hdr[5];
  ssize_t n = read (fd, hdr, 5);
  if (n != 5) {
    close (fd);
    check_record (ctx, CHECK_FAIL, label, "no TLS response");
    return;
  }

  if (memcmp (hdr, "\x16\x03\x03", 3) != 0) {
    close (fd);
    check_record (ctx, CHECK_FAIL, label,
                  "not TLS 1.2+: \\x%02x\\x%02x\\x%02x",
                  hdr[0], hdr[1], hdr[2]);
    return;
  }

  int record_len = (hdr[3] << 8) | hdr[4];
  if (record_len <= 0 || record_len > 16384) {
    close (fd);
    check_record (ctx, CHECK_FAIL, label,
                  "bad record length: %d", record_len);
    return;
  }

  /* Read full ServerHello + ChangeCipherSpec + first encrypted record */
  int total_len = 5 + record_len + 6 + 5; /* hdr + SH + CCS(6) + AppData hdr(5) */
  unsigned char *resp = malloc (total_len + 4096);
  if (!resp) {
    close (fd);
    check_record (ctx, CHECK_FAIL, label, "out of memory");
    return;
  }
  memcpy (resp, hdr, 5);
  int read_pos = 5;

  /* Read the rest in a loop */
  while (read_pos < total_len) {
    n = read (fd, resp + read_pos, total_len - read_pos);
    if (n <= 0) {
      break;
    }
    read_pos += (int)n;
  }

  if (read_pos < total_len) {
    /* Try reading what we have — might be enough to check CCS + app data header */
    /* If the record ended exactly here, that's also OK — we'll validate below */
  }

  /* Check for ChangeCipherSpec + first AppData header at end of ServerHello record */
  int sh_end = 5 + record_len;
  if (read_pos >= sh_end + 11) {
    /* Read the encrypted application data length to get full response */
    if (memcmp (resp + sh_end, "\x14\x03\x03\x00\x01\x01\x17\x03\x03", 9) == 0) {
      int enc_len = (resp[sh_end + 9] << 8) | resp[sh_end + 10];
      int full_len = sh_end + 11 + enc_len;
      if (full_len > read_pos) {
        unsigned char *new_resp = realloc (resp, full_len);
        if (new_resp) {
          resp = new_resp;
          while (read_pos < full_len) {
            n = read (fd, resp + read_pos, full_len - read_pos);
            if (n <= 0) break;
            read_pos += (int)n;
          }
        }
      }
    }
  }

  close (fd);

  /* Validate with tls_check_server_hello */
  int is_reversed = 0;
  int enc_sizes[MAX_ENCRYPTED_RECORDS] = {};
  int enc_count = 0;
  int ok = tls_check_server_hello (resp, read_pos, session_id,
                                   &is_reversed, enc_sizes, &enc_count);
  free (resp);

  if (ok) {
    check_record (ctx, CHECK_PASS, label,
                  "%s, TLS 1.3", ctx->domain_ips[idx]);
  } else {
    check_record (ctx, CHECK_FAIL, label,
                  "%s responded but TLS 1.3 validation failed",
                  ctx->domain_ips[idx]);
  }
}

/* ── check: SNI / DNS match ───────────────────────────────────────── */

/* Try to get public IP via HTTP to checkip.amazonaws.com.
   Returns 0 on success, -1 on failure. */
static int get_public_ip (char *out_ip, int out_len) {
  struct addrinfo hints = {0}, *res = NULL;
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  if (getaddrinfo ("checkip.amazonaws.com", "80", &hints, &res) != 0 || !res) {
    return -1;
  }

  int fd = socket (AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    freeaddrinfo (res);
    return -1;
  }

  struct timeval tv = {.tv_sec = 5};
  setsockopt (fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof (tv));
  setsockopt (fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof (tv));

  if (connect (fd, res->ai_addr, res->ai_addrlen) < 0) {
    close (fd);
    freeaddrinfo (res);
    return -1;
  }
  freeaddrinfo (res);

  const char *req = "GET / HTTP/1.0\r\nHost: checkip.amazonaws.com\r\n"
                    "Connection: close\r\n\r\n";
  if (write (fd, req, strlen (req)) < 0) {
    close (fd);
    return -1;
  }

  char buf[512];
  int total = 0;
  while (total < (int)sizeof (buf) - 1) {
    ssize_t n = read (fd, buf + total, sizeof (buf) - 1 - total);
    if (n <= 0) break;
    total += (int)n;
  }
  buf[total] = 0;
  close (fd);

  /* Find body after \r\n\r\n */
  char *body = strstr (buf, "\r\n\r\n");
  if (!body) return -1;
  body += 4;

  /* Trim whitespace */
  while (*body == ' ' || *body == '\t') body++;
  int len = (int)strlen (body);
  while (len > 0 && (body[len - 1] == '\n' || body[len - 1] == '\r' ||
                      body[len - 1] == ' ')) {
    body[--len] = 0;
  }

  if (len == 0 || len >= out_len) return -1;

  /* Validate it looks like an IP */
  struct in_addr tmp;
  if (inet_pton (AF_INET, body, &tmp) != 1) return -1;

  snprintf (out_ip, out_len, "%s", body);
  return 0;
}

static void check_sni_match (struct check_context *ctx, int idx) {
  const char *domain = ctx->domains[idx];
  const char *resolved_ip = ctx->domain_ips[idx];

  if (!resolved_ip[0]) {
    return; /* DNS resolution already failed in TLS check */
  }

  char label[80];
  snprintf (label, sizeof (label), "SNI %s", domain);

  /* Get local IPs via getifaddrs */
  struct ifaddrs *ifa_list = NULL, *ifa;
  if (getifaddrs (&ifa_list) == 0) {
    for (ifa = ifa_list; ifa; ifa = ifa->ifa_next) {
      if (!ifa->ifa_addr) continue;
      char local_ip[INET6_ADDRSTRLEN] = {};
      if (ifa->ifa_addr->sa_family == AF_INET) {
        struct sockaddr_in *sa4 = (struct sockaddr_in *)ifa->ifa_addr;
        inet_ntop (AF_INET, &sa4->sin_addr, local_ip, sizeof (local_ip));
      } else if (ifa->ifa_addr->sa_family == AF_INET6) {
        struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)ifa->ifa_addr;
        inet_ntop (AF_INET6, &sa6->sin6_addr, local_ip, sizeof (local_ip));
      }
      if (local_ip[0] && strcmp (local_ip, resolved_ip) == 0) {
        freeifaddrs (ifa_list);
        check_record (ctx, CHECK_PASS, label,
                      "%s matches local interface", resolved_ip);
        return;
      }
    }
    freeifaddrs (ifa_list);
  }

  /* No local interface match — try public IP detection */
  char public_ip[64] = {};
  if (get_public_ip (public_ip, sizeof (public_ip)) == 0) {
    if (strcmp (public_ip, resolved_ip) == 0) {
      check_record (ctx, CHECK_PASS, label,
                    "%s matches public IP", resolved_ip);
      return;
    }
    check_record (ctx, CHECK_WARN, label,
                  "%s resolves to %s, proxy is %s",
                  domain, resolved_ip, public_ip);
    return;
  }

  /* Cannot determine public IP */
  check_record (ctx, CHECK_WARN, label,
                "%s resolves to %s; could not detect proxy IP to compare",
                domain, resolved_ip);
}

/* ── output ───────────────────────────────────────────────────────── */

#define LABEL_WIDTH 30

static void print_results (const struct check_context *ctx) {
  printf ("\nteleproxy check\n\n");

  for (int i = 0; i < ctx->result_count; i++) {
    const struct check_result *r = &ctx->results[i];
    int label_len = (int)strlen (r->label);
    int dots = LABEL_WIDTH - label_len;
    if (dots < 2) dots = 2;

    printf ("  %s ", r->label);
    for (int d = 0; d < dots; d++) putchar ('.');

    const char *tag;
    switch (r->status) {
    case CHECK_PASS: tag = " OK"; break;
    case CHECK_FAIL: tag = " FAIL"; break;
    case CHECK_WARN: tag = " WARN"; break;
    case CHECK_SKIP: tag = " SKIP"; break;
    default:         tag = " ???"; break;
    }
    printf ("%s", tag);

    if (r->detail[0]) {
      if (r->status == CHECK_PASS || r->status == CHECK_SKIP) {
        printf (" (%s)", r->detail);
      } else {
        printf ("\n    %s", r->detail);
      }
    }
    printf ("\n");
  }

  printf ("\n%d passed, %d failed, %d warning%s\n",
          ctx->pass_count, ctx->fail_count, ctx->warn_count,
          ctx->warn_count == 1 ? "" : "s");
}

/* ── main entry point ─────────────────────────────────────────────── */

static void check_usage (void) {
  fprintf (stderr,
    "usage: teleproxy check --config FILE [--direct] [-S SECRET] [-D DOMAIN]\n"
    "       teleproxy check --direct -S SECRET [-D DOMAIN] [--dc-override DC:HOST:PORT]\n"
    "\n"
    "Validate configuration and test connectivity.\n"
    "\n"
    "Options:\n"
    "  --config FILE          TOML configuration file\n"
    "  --direct               Direct mode (connect to Telegram DCs)\n"
    "  -S, --secret SECRET    32-char hex secret (repeatable)\n"
    "  -D, --domain DOMAIN    TLS domain[:port] (repeatable)\n"
    "  --dc-override DC:H:P   Override DC address (repeatable)\n"
    "  --socks5 URL           Route DC probes through SOCKS5 proxy\n"
    "                         (socks5://[user:pass@]host:port)\n"
  );
}

static int parse_domain (const char *arg, char *out_domain, int dlen,
                         int *out_port) {
  *out_port = 443;
  const char *colon = strrchr (arg, ':');
  if (colon && colon != arg) {
    /* Check if it's host:port (not [ipv6]:port) */
    int maybe_port = atoi (colon + 1);
    if (maybe_port > 0 && maybe_port <= 65535) {
      int hlen = (int)(colon - arg);
      if (hlen >= dlen) return -1;
      memcpy (out_domain, arg, hlen);
      out_domain[hlen] = 0;
      *out_port = maybe_port;
      return 0;
    }
  }
  snprintf (out_domain, dlen, "%s", arg);
  return 0;
}

int cmd_check (int argc, char *argv[]) {
  struct check_context ctx;
  memset (&ctx, 0, sizeof (ctx));

  const char *config_path = NULL;
  int cli_secrets = 0;
  struct toml_config toml_cfg;
  memset (&toml_cfg, 0, sizeof (toml_cfg));
  toml_cfg.workers = -1;
  toml_cfg.direct = -1;
  toml_cfg.http_stats = -1;
  toml_cfg.random_padding_only = -1;
  toml_cfg.ipv6 = -1;

  const char *socks5_url = NULL;

  static struct option long_opts[] = {
    {"config",      required_argument, 0, 'c'},
    {"direct",      no_argument,       0, 'd'},
    {"secret",      required_argument, 0, 'S'},
    {"domain",      required_argument, 0, 'D'},
    {"dc-override", required_argument, 0, 'O'},
    {"socks5",      required_argument, 0, 'X'},
    {"help",        no_argument,       0, 'h'},
    {0, 0, 0, 0}
  };

  optind = 1;
  int opt;
  while ((opt = getopt_long (argc, argv, "S:D:h", long_opts, NULL)) != -1) {
    switch (opt) {
    case 'c':
      config_path = optarg;
      break;
    case 'd':
      ctx.is_direct = 1;
      break;
    case 'S': {
      /* Validate: must be exactly 32 hex chars */
      int slen = (int)strlen (optarg);
      if (slen != 32) {
        fprintf (stderr, "error: secret must be exactly 32 hex characters (got %d)\n", slen);
        return 2;
      }
      for (int i = 0; i < 32; i++) {
        char c = optarg[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F'))) {
          fprintf (stderr, "error: secret contains non-hex character '%c'\n", c);
          return 2;
        }
      }
      cli_secrets++;
      break;
    }
    case 'D':
      if (ctx.domain_count >= TOML_CONFIG_MAX_DOMAINS) {
        fprintf (stderr, "error: too many domains (max %d)\n",
                 TOML_CONFIG_MAX_DOMAINS);
        return 2;
      }
      if (parse_domain (optarg, ctx.domains[ctx.domain_count],
                        sizeof (ctx.domains[0]),
                        &ctx.domain_ports[ctx.domain_count]) < 0) {
        fprintf (stderr, "error: invalid domain '%s'\n", optarg);
        return 2;
      }
      ctx.domain_count++;
      break;
    case 'O': {
      /* Parse dc_id:host:port */
      int dc_id;
      char host[256];
      int dport;
      if (sscanf (optarg, "%d:%255[^:]:%d", &dc_id, host, &dport) != 3) {
        fprintf (stderr, "error: invalid --dc-override '%s' (expected DC:HOST:PORT)\n", optarg);
        return 2;
      }
      if (dc_id < 1 || dc_id > 5) {
        fprintf (stderr, "error: DC ID must be 1-5 (got %d)\n", dc_id);
        return 2;
      }
      if (dport < 1 || dport > 65535) {
        fprintf (stderr, "error: port must be 1-65535 (got %d)\n", dport);
        return 2;
      }
      if (direct_dc_override (dc_id, host, dport) < 0) {
        fprintf (stderr, "error: invalid host in --dc-override '%s'\n", optarg);
        return 2;
      }
      break;
    }
    case 'X':
      socks5_url = optarg;
      break;
    case 'h':
      check_usage ();
      return 0;
    default:
      check_usage ();
      return 2;
    }
  }

  /* Load TOML config if provided */
  if (config_path) {
    char errbuf[512];
    if (toml_config_load (config_path, &toml_cfg, errbuf, sizeof (errbuf)) < 0) {
      fprintf (stderr, "error: %s\n", errbuf);
      return 2;
    }

    /* Apply TOML values (CLI overrides) */
    if (!ctx.is_direct && toml_cfg.direct == 1) {
      ctx.is_direct = 1;
    }
    if (cli_secrets == 0) {
      ctx.secret_count = toml_cfg.secret_count;
    }
    if (ctx.domain_count == 0) {
      for (int i = 0; i < toml_cfg.domain_count; i++) {
        const char *spec = toml_cfg.domains[i].backend[0]
                           ? toml_cfg.domains[i].backend
                           : toml_cfg.domains[i].name;
        parse_domain (spec, ctx.domains[ctx.domain_count],
                      sizeof (ctx.domains[0]),
                      &ctx.domain_ports[ctx.domain_count]);
        ctx.domain_count++;
      }
    }
    for (int i = 0; i < toml_cfg.dc_override_count; i++) {
      direct_dc_override (toml_cfg.dc_overrides[i].dc_id,
                          toml_cfg.dc_overrides[i].host,
                          toml_cfg.dc_overrides[i].port);
    }
    /* SOCKS5: CLI overrides TOML */
    if (!socks5_url && toml_cfg.socks5[0]) {
      socks5_url = toml_cfg.socks5;
    }
  }

  if (socks5_url) {
    if (check_socks5_parse (socks5_url) < 0) {
      fprintf (stderr, "error: invalid --socks5 URL '%s'\n", socks5_url);
      return 2;
    }
  }

  /* CLI -S secrets add to count */
  ctx.secret_count += cli_secrets;

  /* Must have either --config or --direct */
  if (!config_path && !ctx.is_direct) {
    fprintf (stderr, "error: specify --config FILE or --direct\n\n");
    check_usage ();
    return 2;
  }

  /* ── run checks ── */

  check_config (&ctx);

  for (int dc = 1; dc <= 5; dc++) {
    check_dc (&ctx, dc);
  }

  check_ntp (&ctx);

  if (ctx.domain_count > 0) {
    for (int i = 0; i < ctx.domain_count; i++) {
      check_tls_domain (&ctx, i);
    }
    for (int i = 0; i < ctx.domain_count; i++) {
      if (ctx.domain_ips[i][0]) {
        check_sni_match (&ctx, i);
      }
    }
  }

  print_results (&ctx);

  return (ctx.fail_count > 0) ? 1 : 0;
}
