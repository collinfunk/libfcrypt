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

#ifndef BSWAP_H
#define BSWAP_H

#include <stdint.h>

#undef bswap16
#undef bswap32
#undef bswap64
#undef cpu_to_le16
#undef cpu_to_le32
#undef cpu_to_le64
#undef le16_to_cpu
#undef le32_to_cpu
#undef le64_to_cpu
#undef cpu_to_be16
#undef cpu_to_be32
#undef cpu_to_be64
#undef be16_to_cpu
#undef be32_to_cpu
#undef be64_to_cpu

/* Delete __built_in check for compilers that don't support it. */
#ifndef __has_builtin
#define __has_builtin(x) 0
#endif /* __has_builtin */

#if __has_builtin(__builtin_bswap16)
#define bswap16(x) __builtin_bswap16 ((x))
#else
#define bswap16(x)                                                            \
  ((uint16_t)((((uint16_t)(x)&0x00ff) << 8) | (((uint16_t)(x)&0xff00) >> 8)))

#endif

#if __has_builtin(__builtin_bswap32)
#define bswap32(x) __builtin_bswap32 ((x))
#else
#define bswap32(x)                                                            \
  ((uint32_t)((((uint32_t)(x)&0x000000ff) << 24)                              \
              | (((uint32_t)(x)&0x0000ff00) << 8)                             \
              | (((uint32_t)(x)&0x00ff0000) >> 8)                             \
              | (((uint32_t)(x)&0xff000000) >> 24)))
#endif

#if __has_builtin(__builtin_bswap64)
#define bswap64(x) __builtin_bswap64 ((x))
#else
#define bswap64(x)                                                            \
  ((uint64_t)((((uint64_t)(x)&0x00000000000000ff) << 56)                      \
              | (((uint64_t)(x)&0x000000000000ff00) << 40)                    \
              | (((uint64_t)(x)&0x0000000000ff0000) << 24)                    \
              | (((uint64_t)(x)&0x00000000ff000000) << 8)                     \
              | (((uint64_t)(x)&0x000000ff00000000) >> 8)                     \
              | (((uint64_t)(x)&0x0000ff0000000000) >> 24)                    \
              | (((uint64_t)(x)&0x00ff000000000000) >> 40)                    \
              | (((uint64_t)(x)&0xff00000000000000) >> 56)))
#endif

/* Should change this so it doesn't rely on Clang or GCC. */
#ifndef __BYTE_ORDER__
#error "__BYTE_ORDER__ is not defined."
#endif

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__

#define cpu_to_le16(x) ((uint16_t)(x))
#define cpu_to_le32(x) ((uint32_t)(x))
#define cpu_to_le64(x) ((uint64_t)(x))

#define cpu_to_be16(x) bswap16 ((x))
#define cpu_to_be32(x) bswap32 ((x))
#define cpu_to_be64(x) bswap64 ((x))

#define le16_to_cpu(x) ((uint16_t)(x))
#define le32_to_cpu(x) ((uint32_t)(x))
#define le64_to_cpu(x) ((uint64_t)(x))

#define be16_to_cpu(x) bswap16 ((x))
#define be32_to_cpu(x) bswap32 ((x))
#define be64_to_cpu(x) bswap64 ((x))

#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__

#define cpu_to_le16(x) bswap16 ((x))
#define cpu_to_le32(x) bswap32 ((x))
#define cpu_to_le64(x) bswap64 ((x))

#define cpu_to_be16(x) ((uint16_t)(x))
#define cpu_to_be32(x) ((uint32_t)(x))
#define cpu_to_be64(x) ((uint64_t)(x))

#define le16_to_cpu(x) bswap16 ((x))
#define le32_to_cpu(x) bswap32 ((x))
#define le64_to_cpu(x) bswap64 ((x))

#define be16_to_cpu(x) ((uint16_t)(x))
#define be32_to_cpu(x) ((uint32_t)(x))
#define be64_to_cpu(x) ((uint64_t)(x))

#else
#error "Unknown byte-order"
#endif

static inline uint16_t
buff_get_be16 (const void *inputptr)
{
  uint8_t const *ptr = (uint8_t const *)inputptr;

  return ((uint16_t)ptr[0] << 8) | ((uint16_t)ptr[1]);
}

static inline uint32_t
buff_get_be32 (const void *inputptr)
{
  uint8_t const *ptr = (uint8_t const *)inputptr;

  return ((uint32_t)ptr[0] << 24) | ((uint32_t)ptr[1] << 16)
         | ((uint32_t)ptr[2] << 8) | ((uint32_t)ptr[3]);
}

static inline uint64_t
buff_get_be64 (const void *inputptr)
{
  uint8_t const *ptr = (uint8_t const *)inputptr;

  return ((uint64_t)ptr[0] << 56) | ((uint64_t)ptr[1] << 48)
         | ((uint64_t)ptr[2] << 40) | ((uint64_t)ptr[3] << 32)
         | ((uint64_t)ptr[4] << 24) | ((uint64_t)ptr[5] << 16)
         | ((uint64_t)ptr[6] << 8) | ((uint64_t)ptr[7]);
}

static inline uint16_t
buff_get_le16 (const void *inputptr)
{
  uint8_t const *ptr = (uint8_t const *)inputptr;

  return ((uint16_t)ptr[1] << 8) | ((uint16_t)ptr[0]);
}

static inline uint32_t
buff_get_le32 (const void *inputptr)
{
  uint8_t const *ptr = (uint8_t const *)inputptr;

  return ((uint32_t)ptr[3] << 24) | ((uint32_t)ptr[2] << 16)
         | ((uint32_t)ptr[1] << 8) | ((uint32_t)ptr[0]);
}

static inline uint64_t
buff_get_le64 (const void *inputptr)
{
  uint8_t const *ptr = (uint8_t const *)inputptr;

  return ((uint64_t)ptr[7] << 56) | ((uint64_t)ptr[6] << 48)
         | ((uint64_t)ptr[5] << 40) | ((uint64_t)ptr[4] << 32)
         | ((uint64_t)ptr[3] << 24) | ((uint64_t)ptr[2] << 16)
         | ((uint64_t)ptr[1] << 8) | ((uint64_t)ptr[0]);
}

static inline void
buff_put_be16 (void *inputptr, uint16_t val)
{
  uint8_t *ptr = (uint8_t *)inputptr;

  ptr[0] = (val >> 8) & 0xff;
  ptr[1] = val & 0xff;
}

static inline void
buff_put_be32 (void *inputptr, uint32_t val)
{
  uint8_t *ptr = (uint8_t *)inputptr;

  ptr[0] = (val >> 24) & 0xff;
  ptr[1] = (val >> 16) & 0xff;
  ptr[2] = (val >> 8) & 0xff;
  ptr[3] = val & 0xff;
}

static inline void
buff_put_be64 (void *inputptr, uint64_t val)
{
  uint8_t *ptr = (uint8_t *)inputptr;

  ptr[0] = (val >> 56) & 0xff;
  ptr[1] = (val >> 48) & 0xff;
  ptr[2] = (val >> 40) & 0xff;
  ptr[3] = (val >> 32) & 0xff;
  ptr[4] = (val >> 24) & 0xff;
  ptr[5] = (val >> 16) & 0xff;
  ptr[6] = (val >> 8) & 0xff;
  ptr[7] = val & 0xff;
}

static inline void
buff_put_le16 (void *inputptr, uint16_t val)
{
  uint8_t *ptr = (uint8_t *)inputptr;

  ptr[0] = val & 0xff;
  ptr[1] = (val >> 8) & 0xff;
}

static inline void
buff_put_le32 (void *inputptr, uint32_t val)
{
  uint8_t *ptr = (uint8_t *)inputptr;

  ptr[0] = val & 0xff;
  ptr[1] = (val >> 8) & 0xff;
  ptr[2] = (val >> 16) & 0xff;
  ptr[3] = (val >> 24) & 0xff;
}

static inline void
buff_put_le64 (void *inputptr, uint64_t val)
{
  uint8_t *ptr = (uint8_t *)inputptr;

  ptr[0] = val & 0xff;
  ptr[1] = (val >> 8) & 0xff;
  ptr[2] = (val >> 16) & 0xff;
  ptr[3] = (val >> 24) & 0xff;
  ptr[4] = (val >> 32) & 0xff;
  ptr[5] = (val >> 40) & 0xff;
  ptr[6] = (val >> 48) & 0xff;
  ptr[7] = (val >> 56) & 0xff;
}

#endif /* BSWAP_H */
