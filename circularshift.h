/*-
 * Copyright (c) 2023, Collin Funk
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef CIRCULARSHIFT_H
#define CIRCULARSHIFT_H

#include <stdint.h>

/*
 * These are typically defined as macros like this:
 *	#define ROTL32(x, n) (((x) << 32) | ((x) >> (32 - (x))))
 * In the macro above we would be doing a rotate left on a 32-bit integer x by
 * n bits. This macro causes undefined behavior when n is 0 and when n is
 * greater than or equal to the width of the integer. These functions should
 * be safe for all values of shift.
 */

static inline uint8_t
rotl8 (uint8_t val, unsigned int shift)
{
  return (val << (shift & 7)) | (val >> ((-shift) & 7));
}

static inline uint16_t
rotl16 (uint16_t val, unsigned int shift)
{
  return (val << (shift & 15)) | (val >> ((-shift) & 15));
}

static inline uint32_t
rotl32 (uint32_t val, unsigned int shift)
{
  return (val << (shift & 31)) | (val >> ((-shift) & 31));
}

static inline uint64_t
rotl64 (uint64_t val, unsigned int shift)
{
  return (val << (shift & 63)) | (val >> ((-shift) & 63));
}

static inline uint8_t
rotr8 (uint8_t val, unsigned int shift)
{
  return (val >> (shift & 7)) | (val << ((-shift) & 7));
}

static inline uint16_t
rotr16 (uint16_t val, unsigned int shift)
{
  return (val >> (shift & 15)) | (val << ((-shift) & 15));
}

static inline uint32_t
rotr32 (uint32_t val, unsigned int shift)
{
  return (val >> (shift & 31)) | (val << ((-shift) & 31));
}

static inline uint64_t
rotr64 (uint64_t val, unsigned int shift)
{
  return (val >> (shift & 63)) | (val << ((-shift) & 63));
}

#endif /* CIRCULARSHIFT_H */
