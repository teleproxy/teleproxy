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

    Copyright 2014 Telegram Messenger Inc
              2014 Vitaly Valtman
*/

#pragma once

extern char *config_file, *cfg_start, *cfg_end, *cfg_cur;
extern int config_bytes, cfg_lno, cfg_lex;

int cfg_skipspc (void);
int cfg_skspc (void);
int cfg_getword (void);
void syntax (const char *msg, ...);
int expect_lexem (int lexem);
void reset_config (void);
int load_config (const char *file, int fd);
void md5_hex_config (char *out);
struct hostent *cfg_gethost (void);
struct hostent *cfg_gethost_ex (int verb);
long long cfg_getint (void);
long long cfg_getint_signed_zero (void);

#define Expect(l) { int t = expect_lexem (l); if (t < 0) { return t; } }
#define Syntax(...) { syntax (__VA_ARGS__); return -1; }
