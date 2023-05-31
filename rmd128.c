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

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "bswap.h"
#include "circularshift.h"
#include "fcrypt_memzero.h"
#include "rmd128.h"

/* Functions used by RIPEMD-128. */
#define F1(b, c, d) ((b) ^ (c) ^ (d))
#define F2(b, c, d) (((b) & (c)) | ((~(b)) & (d)))
#define F3(b, c, d) (((b) | (~(c))) ^ (d))
#define F4(b, c, d) (((b) & (d)) | ((c) & (~(d))))

/* Constants used by RIPEMD-128. */
/* #define K1  0x00000000 */
#define K2 0x5a827999
#define K3 0x6ed9eba1
#define K4 0x8f1bbcdc
#define KP1 0x50a28be6
#define KP2 0x5c4dd124
#define KP3 0x6d703ef3
/* #define KP5 0x00000000 */

#define RMD128_STEP(f, a, b, c, d, x, s)                                      \
  do                                                                          \
    {                                                                         \
      (a) += f ((b), (c), (d)) + (x);                                         \
      (a) = rotl32 ((a), (s));                                                \
    }                                                                         \
  while (0)

void
rmd128_init (struct rmd128_ctx *ctx)
{
  ctx->state[0] = 0x67452301;
  ctx->state[1] = 0xefcdab89;
  ctx->state[2] = 0x98badcfe;
  ctx->state[3] = 0x10325476;
  ctx->count = 0;
}

void
rmd128_transform (uint32_t *state, const uint8_t *block)
{
  uint32_t a, b, c, d, i;
  uint32_t aa, bb, cc, dd;
  uint32_t w[16];

  for (i = 0; i < 16; ++i)
    w[i] = buff_get_le32 (block + i * 4);

  a = aa = state[0];
  b = bb = state[1];
  c = cc = state[2];
  d = dd = state[3];

  RMD128_STEP (F1, a, b, c, d, w[0], 11);
  RMD128_STEP (F1, d, a, b, c, w[1], 14);
  RMD128_STEP (F1, c, d, a, b, w[2], 15);
  RMD128_STEP (F1, b, c, d, a, w[3], 12);
  RMD128_STEP (F1, a, b, c, d, w[4], 5);
  RMD128_STEP (F1, d, a, b, c, w[5], 8);
  RMD128_STEP (F1, c, d, a, b, w[6], 7);
  RMD128_STEP (F1, b, c, d, a, w[7], 9);
  RMD128_STEP (F1, a, b, c, d, w[8], 11);
  RMD128_STEP (F1, d, a, b, c, w[9], 13);
  RMD128_STEP (F1, c, d, a, b, w[10], 14);
  RMD128_STEP (F1, b, c, d, a, w[11], 15);
  RMD128_STEP (F1, a, b, c, d, w[12], 6);
  RMD128_STEP (F1, d, a, b, c, w[13], 7);
  RMD128_STEP (F1, c, d, a, b, w[14], 9);
  RMD128_STEP (F1, b, c, d, a, w[15], 8);

  RMD128_STEP (F2, a, b, c, d, w[7] + K2, 7);
  RMD128_STEP (F2, d, a, b, c, w[4] + K2, 6);
  RMD128_STEP (F2, c, d, a, b, w[13] + K2, 8);
  RMD128_STEP (F2, b, c, d, a, w[1] + K2, 13);
  RMD128_STEP (F2, a, b, c, d, w[10] + K2, 11);
  RMD128_STEP (F2, d, a, b, c, w[6] + K2, 9);
  RMD128_STEP (F2, c, d, a, b, w[15] + K2, 7);
  RMD128_STEP (F2, b, c, d, a, w[3] + K2, 15);
  RMD128_STEP (F2, a, b, c, d, w[12] + K2, 7);
  RMD128_STEP (F2, d, a, b, c, w[0] + K2, 12);
  RMD128_STEP (F2, c, d, a, b, w[9] + K2, 15);
  RMD128_STEP (F2, b, c, d, a, w[5] + K2, 9);
  RMD128_STEP (F2, a, b, c, d, w[2] + K2, 11);
  RMD128_STEP (F2, d, a, b, c, w[14] + K2, 7);
  RMD128_STEP (F2, c, d, a, b, w[11] + K2, 13);
  RMD128_STEP (F2, b, c, d, a, w[8] + K2, 12);

  RMD128_STEP (F3, a, b, c, d, w[3] + K3, 11);
  RMD128_STEP (F3, d, a, b, c, w[10] + K3, 13);
  RMD128_STEP (F3, c, d, a, b, w[14] + K3, 6);
  RMD128_STEP (F3, b, c, d, a, w[4] + K3, 7);
  RMD128_STEP (F3, a, b, c, d, w[9] + K3, 14);
  RMD128_STEP (F3, d, a, b, c, w[15] + K3, 9);
  RMD128_STEP (F3, c, d, a, b, w[8] + K3, 13);
  RMD128_STEP (F3, b, c, d, a, w[1] + K3, 15);
  RMD128_STEP (F3, a, b, c, d, w[2] + K3, 14);
  RMD128_STEP (F3, d, a, b, c, w[7] + K3, 8);
  RMD128_STEP (F3, c, d, a, b, w[0] + K3, 13);
  RMD128_STEP (F3, b, c, d, a, w[6] + K3, 6);
  RMD128_STEP (F3, a, b, c, d, w[13] + K3, 5);
  RMD128_STEP (F3, d, a, b, c, w[11] + K3, 12);
  RMD128_STEP (F3, c, d, a, b, w[5] + K3, 7);
  RMD128_STEP (F3, b, c, d, a, w[12] + K3, 5);

  RMD128_STEP (F4, a, b, c, d, w[1] + K4, 11);
  RMD128_STEP (F4, d, a, b, c, w[9] + K4, 12);
  RMD128_STEP (F4, c, d, a, b, w[11] + K4, 14);
  RMD128_STEP (F4, b, c, d, a, w[10] + K4, 15);
  RMD128_STEP (F4, a, b, c, d, w[0] + K4, 14);
  RMD128_STEP (F4, d, a, b, c, w[8] + K4, 15);
  RMD128_STEP (F4, c, d, a, b, w[12] + K4, 9);
  RMD128_STEP (F4, b, c, d, a, w[4] + K4, 8);
  RMD128_STEP (F4, a, b, c, d, w[13] + K4, 9);
  RMD128_STEP (F4, d, a, b, c, w[3] + K4, 14);
  RMD128_STEP (F4, c, d, a, b, w[7] + K4, 5);
  RMD128_STEP (F4, b, c, d, a, w[15] + K4, 6);
  RMD128_STEP (F4, a, b, c, d, w[14] + K4, 8);
  RMD128_STEP (F4, d, a, b, c, w[5] + K4, 6);
  RMD128_STEP (F4, c, d, a, b, w[6] + K4, 5);
  RMD128_STEP (F4, b, c, d, a, w[2] + K4, 12);

  RMD128_STEP (F4, aa, bb, cc, dd, w[5] + KP1, 8);
  RMD128_STEP (F4, dd, aa, bb, cc, w[14] + KP1, 9);
  RMD128_STEP (F4, cc, dd, aa, bb, w[7] + KP1, 9);
  RMD128_STEP (F4, bb, cc, dd, aa, w[0] + KP1, 11);
  RMD128_STEP (F4, aa, bb, cc, dd, w[9] + KP1, 13);
  RMD128_STEP (F4, dd, aa, bb, cc, w[2] + KP1, 15);
  RMD128_STEP (F4, cc, dd, aa, bb, w[11] + KP1, 15);
  RMD128_STEP (F4, bb, cc, dd, aa, w[4] + KP1, 5);
  RMD128_STEP (F4, aa, bb, cc, dd, w[13] + KP1, 7);
  RMD128_STEP (F4, dd, aa, bb, cc, w[6] + KP1, 7);
  RMD128_STEP (F4, cc, dd, aa, bb, w[15] + KP1, 8);
  RMD128_STEP (F4, bb, cc, dd, aa, w[8] + KP1, 11);
  RMD128_STEP (F4, aa, bb, cc, dd, w[1] + KP1, 14);
  RMD128_STEP (F4, dd, aa, bb, cc, w[10] + KP1, 14);
  RMD128_STEP (F4, cc, dd, aa, bb, w[3] + KP1, 12);
  RMD128_STEP (F4, bb, cc, dd, aa, w[12] + KP1, 6);

  RMD128_STEP (F3, aa, bb, cc, dd, w[6] + KP2, 9);
  RMD128_STEP (F3, dd, aa, bb, cc, w[11] + KP2, 13);
  RMD128_STEP (F3, cc, dd, aa, bb, w[3] + KP2, 15);
  RMD128_STEP (F3, bb, cc, dd, aa, w[7] + KP2, 7);
  RMD128_STEP (F3, aa, bb, cc, dd, w[0] + KP2, 12);
  RMD128_STEP (F3, dd, aa, bb, cc, w[13] + KP2, 8);
  RMD128_STEP (F3, cc, dd, aa, bb, w[5] + KP2, 9);
  RMD128_STEP (F3, bb, cc, dd, aa, w[10] + KP2, 11);
  RMD128_STEP (F3, aa, bb, cc, dd, w[14] + KP2, 7);
  RMD128_STEP (F3, dd, aa, bb, cc, w[15] + KP2, 7);
  RMD128_STEP (F3, cc, dd, aa, bb, w[8] + KP2, 12);
  RMD128_STEP (F3, bb, cc, dd, aa, w[12] + KP2, 7);
  RMD128_STEP (F3, aa, bb, cc, dd, w[4] + KP2, 6);
  RMD128_STEP (F3, dd, aa, bb, cc, w[9] + KP2, 15);
  RMD128_STEP (F3, cc, dd, aa, bb, w[1] + KP2, 13);
  RMD128_STEP (F3, bb, cc, dd, aa, w[2] + KP2, 11);

  RMD128_STEP (F2, aa, bb, cc, dd, w[15] + KP3, 9);
  RMD128_STEP (F2, dd, aa, bb, cc, w[5] + KP3, 7);
  RMD128_STEP (F2, cc, dd, aa, bb, w[1] + KP3, 15);
  RMD128_STEP (F2, bb, cc, dd, aa, w[3] + KP3, 11);
  RMD128_STEP (F2, aa, bb, cc, dd, w[7] + KP3, 8);
  RMD128_STEP (F2, dd, aa, bb, cc, w[14] + KP3, 6);
  RMD128_STEP (F2, cc, dd, aa, bb, w[6] + KP3, 6);
  RMD128_STEP (F2, bb, cc, dd, aa, w[9] + KP3, 14);
  RMD128_STEP (F2, aa, bb, cc, dd, w[11] + KP3, 12);
  RMD128_STEP (F2, dd, aa, bb, cc, w[8] + KP3, 13);
  RMD128_STEP (F2, cc, dd, aa, bb, w[12] + KP3, 5);
  RMD128_STEP (F2, bb, cc, dd, aa, w[2] + KP3, 14);
  RMD128_STEP (F2, aa, bb, cc, dd, w[10] + KP3, 13);
  RMD128_STEP (F2, dd, aa, bb, cc, w[0] + KP3, 13);
  RMD128_STEP (F2, cc, dd, aa, bb, w[4] + KP3, 7);
  RMD128_STEP (F2, bb, cc, dd, aa, w[13] + KP3, 5);

  RMD128_STEP (F1, aa, bb, cc, dd, w[8], 15);
  RMD128_STEP (F1, dd, aa, bb, cc, w[6], 5);
  RMD128_STEP (F1, cc, dd, aa, bb, w[4], 8);
  RMD128_STEP (F1, bb, cc, dd, aa, w[1], 11);
  RMD128_STEP (F1, aa, bb, cc, dd, w[3], 14);
  RMD128_STEP (F1, dd, aa, bb, cc, w[11], 14);
  RMD128_STEP (F1, cc, dd, aa, bb, w[15], 6);
  RMD128_STEP (F1, bb, cc, dd, aa, w[0], 14);
  RMD128_STEP (F1, aa, bb, cc, dd, w[5], 6);
  RMD128_STEP (F1, dd, aa, bb, cc, w[12], 9);
  RMD128_STEP (F1, cc, dd, aa, bb, w[2], 12);
  RMD128_STEP (F1, bb, cc, dd, aa, w[13], 9);
  RMD128_STEP (F1, aa, bb, cc, dd, w[9], 12);
  RMD128_STEP (F1, dd, aa, bb, cc, w[7], 5);
  RMD128_STEP (F1, cc, dd, aa, bb, w[10], 15);
  RMD128_STEP (F1, bb, cc, dd, aa, w[14], 8);

  dd += c + state[1];
  state[1] = state[2] + d + aa;
  state[2] = state[3] + a + bb;
  state[3] = state[0] + b + cc;
  state[0] = dd;
}

void
rmd128_update (struct rmd128_ctx *ctx, const void *inputptr, size_t inputlen)
{
  size_t filled, need;
  const uint8_t *input = inputptr;

  if (inputlen == 0)
    return;

  filled = (size_t)((ctx->count >> 3) & (RMD128_BLOCK_SIZE - 1));
  need = RMD128_BLOCK_SIZE - filled;
  ctx->count += (uint64_t)(inputlen << 3);

  /* Input too short to fill a complete block. */
  if (inputlen < need)
    {
      memcpy (&ctx->buffer[filled], input, inputlen);
      return;
    }

  /* Check if we need to finish the buffer in ctx. */
  if (filled != 0)
    {
      memcpy (&ctx->buffer[filled], input, need);
      rmd128_transform (ctx->state, ctx->buffer);
      inputlen -= need;
      input += need;
    }

  /* Handle as many blocks as possible. */
  while (inputlen >= RMD128_BLOCK_SIZE)
    {
      rmd128_transform (ctx->state, input);
      inputlen -= RMD128_BLOCK_SIZE;
      input += RMD128_BLOCK_SIZE;
    }

  /* Save any remaining bytes. */
  if (inputlen != 0)
    memcpy (ctx->buffer, input, inputlen);
}

void
rmd128_final (uint8_t *digest, struct rmd128_ctx *ctx)
{
  size_t padoffset;
  uint32_t i;

  padoffset = (size_t)((ctx->count >> 3) & (RMD128_BLOCK_SIZE - 1));
  ctx->buffer[padoffset++] = 0x80;

  /* Enough room for count. */
  if (padoffset <= 56)
    memset (&ctx->buffer[padoffset], 0, 56 - padoffset);
  else
    {
      /* Not enough room for count. */
      memset (&ctx->buffer[padoffset], 0, RMD128_BLOCK_SIZE - padoffset);
      rmd128_transform (ctx->state, ctx->buffer);
      memset (ctx->buffer, 0, 56);
    }

  /* Append the count and handle the block. */
  buff_put_le64 (ctx->buffer + 56, ctx->count);
  rmd128_transform (ctx->state, ctx->buffer);

  for (i = 0; i < 4; ++i)
    buff_put_le32 (digest + i * 4, ctx->state[i]);
  fcrypt_memzero (ctx, sizeof (*ctx));
}
