/*
    This file is part of Mtproto-proxy Library.

    Mtproto-proxy Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    Mtproto-proxy Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with Mtproto-proxy Library.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2009-2012 Vkontakte Ltd
              2009-2012 Nikolai Durov
              2009-2012 Andrey Lopatin
                   2012 Anton Maydell

    Copyright 2014 Telegram Messenger Inc
              2014 Anton Maydell
*/

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/file.h>
#include <unistd.h>

#include "kprintf.h"
#include "precise-time.h"

int verbosity;
const char *logname;

void reopen_logs_ext (int slave_mode) {
  int fd;
  fflush (stdout);
  fflush (stderr);
  if ((fd = open ("/dev/null", O_RDWR, 0)) != -1) {
    dup2 (fd, 0);
    dup2 (fd, 1);
    dup2 (fd, 2);
    if (fd > 2) {
      close (fd);
    }
  }
  if (logname && (fd = open (logname, O_WRONLY|O_APPEND|O_CREAT, 0640)) != -1) {
    dup2 (fd, 1);
    dup2 (fd, 2);
    if (fd > 2) {
      close (fd);
    }
  }
  if (!slave_mode) {
    vkprintf (1, "logs reopened.\n");
  }
}

int hexdump (const void *start, const void *end) {
  char s[256];
  const char *ptr = start;
  while (ptr < (char *) end) {
    int len = (const char *) end - ptr, i;
    if (len > 16) { 
      len = 16;
    }
    int p = 0;
    p += sprintf (s + p, "%08x", (int) (ptr - (char *) start));
    for (i = 0; i < 16; i++) {
      s[p ++] = ' ';
      if (i == 8) {
        s[p ++] = ' ';
      }
      if (i < len) {
        p += sprintf (s + p, "%02x", (unsigned char) ptr[i]);
      } else {
        p += sprintf (s + p, "  ");
      }
    }
    s[p ++] = '\n';
    write (2, s, p);
    ptr += 16;
  }
  return end - start;
}

static inline void kwrite_print_int (char **s, const char *name, int name_len, int i) {
  if (i < 0) {
    i = INT_MAX;
  }

  *--*s = ' ';
  *--*s = ']';

  do {
    *--*s = i % 10 + '0';
    i /= 10;
  } while (i > 0);

  *--*s = ' ';

  while (--name_len >= 0) {
    *--*s = name[name_len];
  }

  *--*s = '[';
}

int kwrite (int fd, const void *buf, int count) {
  int old_errno = errno;

#define S_BUF_SIZE 100
#define S_DATA_SIZE 256
  char s[S_BUF_SIZE + S_DATA_SIZE], *s_begin = s + S_BUF_SIZE;

  kwrite_print_int (&s_begin, "time", 4, time (NULL));
  kwrite_print_int (&s_begin, "pid" , 3, getpid ());

  assert (s_begin >= s);

  int s_count = s + S_BUF_SIZE - s_begin;
  if (count <= S_DATA_SIZE) {
    int i;
    for (i = 0; i < count; i++) {
      s[i + S_BUF_SIZE] = ((char *)buf)[i];
    }
    s_count += count;
    count = 0;
  }

  int result = s_count + count;
  while (s_count > 0) {
    errno = 0;
    int res = (int)write (fd, s_begin, (size_t)s_count);
    if (errno && errno != EINTR) {
      errno = old_errno;
      return res;
    }
    if (!res) {
      break;
    }
    if (res >= 0) {
      s_begin += res;
      s_count -= res;
    }
  }

  while (count > 0) {
    errno = 0;
    int res = (int)write (fd, buf, (size_t)count);
    if (errno && errno != EINTR) {
      errno = old_errno;
      return res;
    }
    if (!res) {
      break;
    }
    if (res >= 0) {
      buf += res;
      count -= res;
    }
  }

  errno = old_errno;
  return result;
#undef S_BUF_SIZE
#undef S_DATA_SIZE
}

void kprintf (const char *format, ...) {
  const int old_errno = errno;
  struct tm t;
  struct timeval tv;
  char mp_kprintf_buf[PIPE_BUF];

  if (gettimeofday (&tv, NULL) || !localtime_r (&tv.tv_sec, &t)) {
    memset (&t, 0, sizeof (t));
  }

  int n = snprintf (mp_kprintf_buf, sizeof (mp_kprintf_buf), "[%d][%4d-%02d-%02d %02d:%02d:%02d.%06d local] ", getpid (), t.tm_year + 1900, t.tm_mon + 1, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec, (int) tv.tv_usec);
  if (n < sizeof (mp_kprintf_buf) - 1) {
    errno = old_errno;
    va_list ap;
    va_start (ap, format);
    n += vsnprintf (mp_kprintf_buf + n, sizeof (mp_kprintf_buf) - n, format, ap);
    va_end (ap);
  }
  if (n >= sizeof (mp_kprintf_buf)) {
    n = sizeof (mp_kprintf_buf) - 1;
    if (mp_kprintf_buf[n-1] != '\n') {
      mp_kprintf_buf[n++] = '\n';
    }
  }
  while (write (2, mp_kprintf_buf, n) < 0 && errno == EINTR);
  //while (flock (2, LOCK_UN) < 0 && errno == EINTR);
  errno = old_errno;
}
