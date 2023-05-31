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

/*
 * HAS-160 is a hash function designed for use in Korea. It is very similar
 * to SHA-1. This specification for the algorithm can be found on the
 * Telecommunications Technology Association's website.
 * Standards Number: TTAS.KO-12.0011/R1
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "bswap.h"
#include "circularshift.h"
#include "fcrypt_memzero.h"
#include "has160.h"

/*
 * Constants used by HAS-160.
 * K1 = 0 then K2-K4 is SHA-1's K1-K3.
 */
/* #define K1 0x00000000 */
#define K2 0x5a827999
#define K3 0x6ed9eba1
#define K4 0x8f1bbcdc

/*
 * Logical functions used by HAS-160.
 * The same as SHA-1 except for F3.
 */
#define F1(b, c, d) (((b) & (c)) | ((~(b)) & (d)))
#define F2(b, c, d) ((b) ^ (c) ^ (d))
#define F3(b, c, d) ((c) ^ ((b) | (~(d))))
#define F4(b, c, d) ((b) ^ (c) ^ (d))

#define STEP1(a, b, c, d, e, x, s)                                            \
  do                                                                          \
    {                                                                         \
      (e) += rotl32 ((a), (s)) + F1 ((b), (c), (d)) + (x);                    \
      (b) = rotl32 ((b), 10);                                                 \
    }                                                                         \
  while (0)

#define STEP2(a, b, c, d, e, x, s)                                            \
  do                                                                          \
    {                                                                         \
      (e) += rotl32 ((a), (s)) + F2 ((b), (c), (d)) + (x) + K2;               \
      (b) = rotl32 ((b), 17);                                                 \
    }                                                                         \
  while (0)

#define STEP3(a, b, c, d, e, x, s)                                            \
  do                                                                          \
    {                                                                         \
      (e) += rotl32 ((a), (s)) + F3 ((b), (c), (d)) + (x) + K3;               \
      (b) = rotl32 ((b), 25);                                                 \
    }                                                                         \
  while (0)

#define STEP4(a, b, c, d, e, x, s)                                            \
  do                                                                          \
    {                                                                         \
      (e) += rotl32 ((a), (s)) + F4 ((b), (c), (d)) + (x) + K4;               \
      (b) = rotl32 ((b), 30);                                                 \
    }                                                                         \
  while (0)

void
has160_init (struct has160_ctx *ctx)
{
  /* Same as SHA-1 */
  ctx->state[0] = 0x67452301;
  ctx->state[1] = 0xefcdab89;
  ctx->state[2] = 0x98badcfe;
  ctx->state[3] = 0x10325476;
  ctx->state[4] = 0xc3d2e1f0;
  ctx->count = 0;
}

void
has160_transform (uint32_t *state, const uint8_t *block)
{
  uint32_t a, b, c, d, e, i;
  uint32_t x[20];

  for (i = 0; i < 16; ++i)
    x[i] = buff_get_le32 (block + i * 4);

  a = state[0];
  b = state[1];
  c = state[2];
  d = state[3];
  e = state[4];

  x[16] = x[0] ^ x[1] ^ x[2] ^ x[3];
  x[17] = x[4] ^ x[5] ^ x[6] ^ x[7];
  x[18] = x[8] ^ x[9] ^ x[10] ^ x[11];
  x[19] = x[12] ^ x[13] ^ x[14] ^ x[15];
  STEP1 (a, b, c, d, e, x[18], 5);
  STEP1 (e, a, b, c, d, x[0], 11);
  STEP1 (d, e, a, b, c, x[1], 7);
  STEP1 (c, d, e, a, b, x[2], 15);
  STEP1 (b, c, d, e, a, x[3], 6);
  STEP1 (a, b, c, d, e, x[19], 13);
  STEP1 (e, a, b, c, d, x[4], 8);
  STEP1 (d, e, a, b, c, x[5], 14);
  STEP1 (c, d, e, a, b, x[6], 7);
  STEP1 (b, c, d, e, a, x[7], 12);
  STEP1 (a, b, c, d, e, x[16], 9);
  STEP1 (e, a, b, c, d, x[8], 11);
  STEP1 (d, e, a, b, c, x[9], 8);
  STEP1 (c, d, e, a, b, x[10], 15);
  STEP1 (b, c, d, e, a, x[11], 6);
  STEP1 (a, b, c, d, e, x[17], 12);
  STEP1 (e, a, b, c, d, x[12], 9);
  STEP1 (d, e, a, b, c, x[13], 14);
  STEP1 (c, d, e, a, b, x[14], 5);
  STEP1 (b, c, d, e, a, x[15], 13);

  x[16] = x[3] ^ x[6] ^ x[9] ^ x[12];
  x[17] = x[15] ^ x[2] ^ x[5] ^ x[8];
  x[18] = x[11] ^ x[14] ^ x[1] ^ x[4];
  x[19] = x[7] ^ x[10] ^ x[13] ^ x[0];
  STEP2 (a, b, c, d, e, x[18], 5);
  STEP2 (e, a, b, c, d, x[3], 11);
  STEP2 (d, e, a, b, c, x[6], 7);
  STEP2 (c, d, e, a, b, x[9], 15);
  STEP2 (b, c, d, e, a, x[12], 6);
  STEP2 (a, b, c, d, e, x[19], 13);
  STEP2 (e, a, b, c, d, x[15], 8);
  STEP2 (d, e, a, b, c, x[2], 14);
  STEP2 (c, d, e, a, b, x[5], 7);
  STEP2 (b, c, d, e, a, x[8], 12);
  STEP2 (a, b, c, d, e, x[16], 9);
  STEP2 (e, a, b, c, d, x[11], 11);
  STEP2 (d, e, a, b, c, x[14], 8);
  STEP2 (c, d, e, a, b, x[1], 15);
  STEP2 (b, c, d, e, a, x[4], 6);
  STEP2 (a, b, c, d, e, x[17], 12);
  STEP2 (e, a, b, c, d, x[7], 9);
  STEP2 (d, e, a, b, c, x[10], 14);
  STEP2 (c, d, e, a, b, x[13], 5);
  STEP2 (b, c, d, e, a, x[0], 13);

  x[16] = x[12] ^ x[5] ^ x[14] ^ x[7];
  x[17] = x[0] ^ x[9] ^ x[2] ^ x[11];
  x[18] = x[4] ^ x[13] ^ x[6] ^ x[15];
  x[19] = x[8] ^ x[1] ^ x[10] ^ x[3];
  STEP3 (a, b, c, d, e, x[18], 5);
  STEP3 (e, a, b, c, d, x[12], 11);
  STEP3 (d, e, a, b, c, x[5], 7);
  STEP3 (c, d, e, a, b, x[14], 15);
  STEP3 (b, c, d, e, a, x[7], 6);
  STEP3 (a, b, c, d, e, x[19], 13);
  STEP3 (e, a, b, c, d, x[0], 8);
  STEP3 (d, e, a, b, c, x[9], 14);
  STEP3 (c, d, e, a, b, x[2], 7);
  STEP3 (b, c, d, e, a, x[11], 12);
  STEP3 (a, b, c, d, e, x[16], 9);
  STEP3 (e, a, b, c, d, x[4], 11);
  STEP3 (d, e, a, b, c, x[13], 8);
  STEP3 (c, d, e, a, b, x[6], 15);
  STEP3 (b, c, d, e, a, x[15], 6);
  STEP3 (a, b, c, d, e, x[17], 12);
  STEP3 (e, a, b, c, d, x[8], 9);
  STEP3 (d, e, a, b, c, x[1], 14);
  STEP3 (c, d, e, a, b, x[10], 5);
  STEP3 (b, c, d, e, a, x[3], 13);

  x[16] = x[7] ^ x[2] ^ x[13] ^ x[8];
  x[17] = x[3] ^ x[14] ^ x[9] ^ x[4];
  x[18] = x[15] ^ x[10] ^ x[5] ^ x[0];
  x[19] = x[11] ^ x[6] ^ x[1] ^ x[12];
  STEP4 (a, b, c, d, e, x[18], 5);
  STEP4 (e, a, b, c, d, x[7], 11);
  STEP4 (d, e, a, b, c, x[2], 7);
  STEP4 (c, d, e, a, b, x[13], 15);
  STEP4 (b, c, d, e, a, x[8], 6);
  STEP4 (a, b, c, d, e, x[19], 13);
  STEP4 (e, a, b, c, d, x[3], 8);
  STEP4 (d, e, a, b, c, x[14], 14);
  STEP4 (c, d, e, a, b, x[9], 7);
  STEP4 (b, c, d, e, a, x[4], 12);
  STEP4 (a, b, c, d, e, x[16], 9);
  STEP4 (e, a, b, c, d, x[15], 11);
  STEP4 (d, e, a, b, c, x[10], 8);
  STEP4 (c, d, e, a, b, x[5], 15);
  STEP4 (b, c, d, e, a, x[0], 6);
  STEP4 (a, b, c, d, e, x[17], 12);
  STEP4 (e, a, b, c, d, x[11], 9);
  STEP4 (d, e, a, b, c, x[6], 14);
  STEP4 (c, d, e, a, b, x[1], 5);
  STEP4 (b, c, d, e, a, x[12], 13);

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;
}

void
has160_update (struct has160_ctx *ctx, const void *inputptr, size_t inputlen)
{
  size_t filled, need;
  const uint8_t *input = inputptr;

  /* Nothing to do */
  if (inputlen == 0)
    return;

  filled = (size_t)((ctx->count >> 3) & (HAS160_BLOCK_SIZE - 1));
  ctx->count += (inputlen << 3);

  if (filled != 0)
    {
      need = HAS160_BLOCK_SIZE - filled;
      /* Not enough input to fill a block. */
      if (inputlen < need)
        {
          memcpy (&ctx->buffer[filled], input, inputlen);
          return;
        }

      /* Handle the buffer first. */
      memcpy (&ctx->buffer[filled], input, need);
      has160_transform (ctx->state, ctx->buffer);
      inputlen -= need;
      input += need;
    }

  /* Handle all complete blocks. */
  while (inputlen >= HAS160_BLOCK_SIZE)
    {
      has160_transform (ctx->state, input);
      inputlen -= HAS160_BLOCK_SIZE;
      input += HAS160_BLOCK_SIZE;
    }

  /* Save any remaining input. */
  if (inputlen != 0)
    memcpy (ctx->buffer, input, inputlen);
}

void
has160_final (uint8_t *digest, struct has160_ctx *ctx)
{
  uint32_t i;
  size_t padoffset = (size_t)((ctx->count >> 3) & (HAS160_BLOCK_SIZE - 1));

  ctx->buffer[padoffset++] = 0x80;

  /* Enough room for count. */
  if (padoffset <= 56)
    memset (&ctx->buffer[padoffset], 0, 56 - padoffset);
  else
    {
      /* Not enough room for count. */
      memset (&ctx->buffer[padoffset], 0, HAS160_BLOCK_SIZE - padoffset);
      has160_transform (ctx->state, ctx->buffer);
      memset (ctx->buffer, 0, 56);
    }

  buff_put_le64 (ctx->buffer + 56, ctx->count);
  has160_transform (ctx->state, ctx->buffer);

  for (i = 0; i < 5; ++i)
    buff_put_le32 (digest + i * 4, ctx->state[i]);
  fcrypt_memzero (ctx, sizeof (*ctx));
}
