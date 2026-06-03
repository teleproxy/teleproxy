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

#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned (*crc32_partial_func_t) (const void *data, long len, unsigned crc);
typedef unsigned (*crc32_combine_func_t) (unsigned crc1, unsigned crc2, int64_t len2);
typedef uint64_t (*crc64_partial_func_t) (const void *data, long len, uint64_t crc);
typedef uint64_t (*crc64_combine_func_t) (uint64_t crc1, uint64_t crc2, int64_t len2);

extern crc32_partial_func_t crc32_partial;
extern crc64_partial_func_t crc64_partial;
extern crc32_combine_func_t compute_crc32_combine;
extern crc64_combine_func_t compute_crc64_combine;

/* these functions are exported only for testing purpose */
unsigned crc32_partial_generic (const void *data, long len, unsigned crc);
uint64_t crc64_partial_one_table (const void *data, long len, uint64_t crc);

void gf32_compute_powers_generic (unsigned *P, int size, unsigned poly);
unsigned gf32_combine_generic (unsigned *powers, unsigned crc1, int64_t len2);

#if defined(__x86_64__) || defined(__i386__)
unsigned crc32_partial_clmul (const void *data, long len, unsigned crc);
uint64_t crc64_partial_clmul (const void *data, long len, uint64_t crc);
void gf32_compute_powers_clmul (unsigned *P, unsigned poly);
uint64_t gf32_combine_clmul (unsigned *powers, unsigned crc1, int64_t len2);
#endif


#ifdef __cplusplus
}
#endif
