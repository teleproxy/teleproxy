/*
    Connection link subcommand for Teleproxy.

    Prints a ready-to-share proxy URL and renders a scannable QR code
    in the terminal using UTF-8 half-block characters.

    Usage:
      teleproxy link --server HOST --port PORT --secret SECRET [--label LABEL]
*/

#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "qrcode/qrcodegen.h"

/* ── UTF-8 half-block QR renderer ───────────────────────────────── */

/*
 * Renders a QR code to stdout using Unicode half-block characters.
 * Each output row encodes two module rows, doubling vertical density.
 *
 * Uses inverted colors: dark modules are spaces (terminal background),
 * light modules are blocks.  This matches the convention used by
 * qrencode -t ANSIUTF8 and produces better contrast on dark terminals.
 *
 * quiet_zone: number of light-module border cells on each side.
 */
static void qr_print_utf8 (const uint8_t qrcode[], int quiet_zone) {
  int size = qrcodegen_getSize (qrcode);
  int full = size + 2 * quiet_zone;

  /* Process two rows at a time */
  for (int y = -quiet_zone; y < size + quiet_zone; y += 2) {
    for (int x = -quiet_zone; x < size + quiet_zone; x++) {
      bool top = (y >= 0 && y < size && x >= 0 && x < size)
                     ? qrcodegen_getModule (qrcode, x, y)
                     : false;
      bool bot = (y + 1 >= 0 && y + 1 < size && x >= 0 && x < size)
                     ? qrcodegen_getModule (qrcode, x, y + 1)
                     : false;

      /*
       * Inverted: module=true means dark in QR spec, but we render
       * dark as space (terminal bg) and light as block.
       */
      if (!top && !bot) {
        fputs ("\xe2\x96\x88", stdout);  /* FULL BLOCK: both light */
      } else if (!top && bot) {
        fputs ("\xe2\x96\x80", stdout);  /* UPPER HALF: top light, bot dark */
      } else if (top && !bot) {
        fputs ("\xe2\x96\x84", stdout);  /* LOWER HALF: top dark, bot light */
      } else {
        fputc (' ', stdout);             /* both dark */
      }
    }
    fputc ('\n', stdout);
  }

  /* Pad last row if total height is odd */
  if (full % 2 != 0) {
    /* Already handled: the loop increments by 2, and the y+1 check
       handles the out-of-bounds bottom row as "light" (quiet zone). */
  }
}

/* ── subcommand entry point ─────────────────────────────────────── */

static void link_usage (void) {
  fprintf (stderr,
           "Usage: teleproxy link --server HOST --port PORT --secret SECRET "
           "[--label LABEL]\n");
}

int cmd_link (int argc, char *argv[]) {
  const char *server = NULL;
  const char *port = NULL;
  const char *secret = NULL;
  const char *label = NULL;

  static struct option long_opts[] = {
      {"server", required_argument, NULL, 's'},
      {"port", required_argument, NULL, 'p'},
      {"secret", required_argument, NULL, 'S'},
      {"label", required_argument, NULL, 'l'},
      {NULL, 0, NULL, 0}};

  optind = 1;  /* reset getopt state */
  int c;
  while ((c = getopt_long (argc, argv, "s:p:S:l:", long_opts, NULL)) != -1) {
    switch (c) {
    case 's':
      server = optarg;
      break;
    case 'p':
      port = optarg;
      break;
    case 'S':
      secret = optarg;
      break;
    case 'l':
      label = optarg;
      break;
    default:
      link_usage ();
      return 2;
    }
  }

  if (!server || !port || !secret) {
    link_usage ();
    return 2;
  }

  /* Build the t.me proxy URL */
  char url[2048];
  snprintf (url, sizeof (url),
            "https://t.me/proxy?server=%s&port=%s&secret=%s", server, port,
            secret);

  /* Print text link (with optional label suffix) */
  if (label) {
    printf ("%s [%s]\n", url, label);
  } else {
    printf ("%s\n", url);
  }

  /* Encode and render QR */
  uint8_t qrcode[qrcodegen_BUFFER_LEN_MAX];
  uint8_t temp[qrcodegen_BUFFER_LEN_MAX];

  if (!qrcodegen_encodeText (url, temp, qrcode, qrcodegen_Ecc_LOW,
                             qrcodegen_VERSION_MIN, qrcodegen_VERSION_MAX,
                             qrcodegen_Mask_AUTO, true)) {
    fprintf (stderr, "QR encoding failed for URL: %s\n", url);
    return 1;
  }

  qr_print_utf8 (qrcode, 2);

  return 0;
}
