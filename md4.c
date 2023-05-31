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
#include "md4.h"

/* Functions used by MD4. */
#define F1(b, c, d) (((b) & (c)) | ((~(b)) & (d)))
#define F2(b, c, d) (((b) & (c)) | ((b) & (d)) | ((c) & (d)))
#define F3(b, c, d) ((b) ^ (c) ^ (d))

#define MD4_STEP(f, a, b, c, d, x, s)                                         \
  do                                                                          \
    {                                                                         \
      (a) += f ((b), (c), (d)) + (x);                                         \
      (a) = rotl32 ((a), (s));                                                \
    }                                                                         \
  while (0)

void
md4_init (struct md4_ctx *ctx)
{
  ctx->state[0] = 0x67452301;
  ctx->state[1] = 0xefcdab89;
  ctx->state[2] = 0x98badcfe;
  ctx->state[3] = 0x10325476;
  ctx->count = 0;
}

void
md4_transform (uint32_t *state, const uint8_t *block)
{
  uint32_t a, b, c, d, i;
  uint32_t w[16];

  for (i = 0; i < 16; ++i)
    w[i] = buff_get_le32 (block + i * 4);

  a = state[0];
  b = state[1];
  c = state[2];
  d = state[3];

  MD4_STEP (F1, a, b, c, d, w[0], 3);
  MD4_STEP (F1, d, a, b, c, w[1], 7);
  MD4_STEP (F1, c, d, a, b, w[2], 11);
  MD4_STEP (F1, b, c, d, a, w[3], 19);
  MD4_STEP (F1, a, b, c, d, w[4], 3);
  MD4_STEP (F1, d, a, b, c, w[5], 7);
  MD4_STEP (F1, c, d, a, b, w[6], 11);
  MD4_STEP (F1, b, c, d, a, w[7], 19);
  MD4_STEP (F1, a, b, c, d, w[8], 3);
  MD4_STEP (F1, d, a, b, c, w[9], 7);
  MD4_STEP (F1, c, d, a, b, w[10], 11);
  MD4_STEP (F1, b, c, d, a, w[11], 19);
  MD4_STEP (F1, a, b, c, d, w[12], 3);
  MD4_STEP (F1, d, a, b, c, w[13], 7);
  MD4_STEP (F1, c, d, a, b, w[14], 11);
  MD4_STEP (F1, b, c, d, a, w[15], 19);

  MD4_STEP (F2, a, b, c, d, w[0] + 0x5a827999, 3);
  MD4_STEP (F2, d, a, b, c, w[4] + 0x5a827999, 5);
  MD4_STEP (F2, c, d, a, b, w[8] + 0x5a827999, 9);
  MD4_STEP (F2, b, c, d, a, w[12] + 0x5a827999, 13);
  MD4_STEP (F2, a, b, c, d, w[1] + 0x5a827999, 3);
  MD4_STEP (F2, d, a, b, c, w[5] + 0x5a827999, 5);
  MD4_STEP (F2, c, d, a, b, w[9] + 0x5a827999, 9);
  MD4_STEP (F2, b, c, d, a, w[13] + 0x5a827999, 13);
  MD4_STEP (F2, a, b, c, d, w[2] + 0x5a827999, 3);
  MD4_STEP (F2, d, a, b, c, w[6] + 0x5a827999, 5);
  MD4_STEP (F2, c, d, a, b, w[10] + 0x5a827999, 9);
  MD4_STEP (F2, b, c, d, a, w[14] + 0x5a827999, 13);
  MD4_STEP (F2, a, b, c, d, w[3] + 0x5a827999, 3);
  MD4_STEP (F2, d, a, b, c, w[7] + 0x5a827999, 5);
  MD4_STEP (F2, c, d, a, b, w[11] + 0x5a827999, 9);
  MD4_STEP (F2, b, c, d, a, w[15] + 0x5a827999, 13);

  MD4_STEP (F3, a, b, c, d, w[0] + 0x6ed9eba1, 3);
  MD4_STEP (F3, d, a, b, c, w[8] + 0x6ed9eba1, 9);
  MD4_STEP (F3, c, d, a, b, w[4] + 0x6ed9eba1, 11);
  MD4_STEP (F3, b, c, d, a, w[12] + 0x6ed9eba1, 15);
  MD4_STEP (F3, a, b, c, d, w[2] + 0x6ed9eba1, 3);
  MD4_STEP (F3, d, a, b, c, w[10] + 0x6ed9eba1, 9);
  MD4_STEP (F3, c, d, a, b, w[6] + 0x6ed9eba1, 11);
  MD4_STEP (F3, b, c, d, a, w[14] + 0x6ed9eba1, 15);
  MD4_STEP (F3, a, b, c, d, w[1] + 0x6ed9eba1, 3);
  MD4_STEP (F3, d, a, b, c, w[9] + 0x6ed9eba1, 9);
  MD4_STEP (F3, c, d, a, b, w[5] + 0x6ed9eba1, 11);
  MD4_STEP (F3, b, c, d, a, w[13] + 0x6ed9eba1, 15);
  MD4_STEP (F3, a, b, c, d, w[3] + 0x6ed9eba1, 3);
  MD4_STEP (F3, d, a, b, c, w[11] + 0x6ed9eba1, 9);
  MD4_STEP (F3, c, d, a, b, w[7] + 0x6ed9eba1, 11);
  MD4_STEP (F3, b, c, d, a, w[15] + 0x6ed9eba1, 15);

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
}

void
md4_update (struct md4_ctx *ctx, const void *inputptr, size_t inputlen)
{
  size_t filled, need;
  const uint8_t *input = inputptr;

  if (inputlen == 0)
    return;

  filled = (size_t)((ctx->count >> 3) & (MD4_BLOCK_SIZE - 1));
  need = MD4_BLOCK_SIZE - filled;
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
      md4_transform (ctx->state, ctx->buffer);
      inputlen -= need;
      input += need;
    }

  /* Handle as many blocks as possible. */
  while (inputlen >= MD4_BLOCK_SIZE)
    {
      md4_transform (ctx->state, input);
      inputlen -= MD4_BLOCK_SIZE;
      input += MD4_BLOCK_SIZE;
    }

  /* Save any remaining bytes. */
  if (inputlen != 0)
    memcpy (ctx->buffer, input, inputlen);
}

void
md4_final (uint8_t *digest, struct md4_ctx *ctx)
{
  size_t padoffset;
  uint32_t i;

  padoffset = (size_t)((ctx->count >> 3) & (MD4_BLOCK_SIZE - 1));
  ctx->buffer[padoffset++] = 0x80;

  /* Enough room for count. */
  if (padoffset <= 56)
    memset (&ctx->buffer[padoffset], 0, 56 - padoffset);
  else
    {
      /* Not enough room for count. */
      memset (&ctx->buffer[padoffset], 0, MD4_BLOCK_SIZE - padoffset);
      md4_transform (ctx->state, ctx->buffer);
      memset (ctx->buffer, 0, 56);
    }

  /* Append the count and handle the block. */
  buff_put_le64 (ctx->buffer + 56, ctx->count);
  md4_transform (ctx->state, ctx->buffer);

  for (i = 0; i < 4; ++i)
    buff_put_le32 (digest + i * 4, ctx->state[i]);
  memset (ctx, 0, sizeof (*ctx));
}
