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
#include "md5.h"

/* Functions used by MD5. */
#define F1(b, c, d) (((b) & (c)) | ((~(b)) & (d)))
#define F2(b, c, d) (((b) & (d)) | ((~(d)) & (c)))
#define F3(b, c, d) ((b) ^ (c) ^ (d))
#define F4(b, c, d) ((c) ^ ((b) | (~(d))))

#define MD5_STEP(f, a, b, c, d, x, s)                                         \
  do                                                                          \
    {                                                                         \
      (a) += f ((b), (c), (d)) + (x);                                         \
      (a) = rotl32 ((a), (s));                                                \
      (a) += (b);                                                             \
    }                                                                         \
  while (0)

void
md5_init (struct md5_ctx *ctx)
{
  ctx->state[0] = 0x67452301;
  ctx->state[1] = 0xefcdab89;
  ctx->state[2] = 0x98badcfe;
  ctx->state[3] = 0x10325476;
  ctx->count = 0;
}

/*
 * Constants calculated using:
 * for (i = 1; i < 65; ++i)
 *	k[i - 1] = (uint32_t)(4294967296.0 * fabs(sin(i)));
 */
void
md5_transform (uint32_t *state, const uint8_t *block)
{
  uint32_t a, b, c, d, i;
  uint32_t w[16];

  for (i = 0; i < 16; ++i)
    w[i] = buff_get_le32 (block + i * 4);

  a = state[0];
  b = state[1];
  c = state[2];
  d = state[3];

  MD5_STEP (F1, a, b, c, d, w[0] + 0xd76aa478, 7);
  MD5_STEP (F1, d, a, b, c, w[1] + 0xe8c7b756, 12);
  MD5_STEP (F1, c, d, a, b, w[2] + 0x242070db, 17);
  MD5_STEP (F1, b, c, d, a, w[3] + 0xc1bdceee, 22);
  MD5_STEP (F1, a, b, c, d, w[4] + 0xf57c0faf, 7);
  MD5_STEP (F1, d, a, b, c, w[5] + 0x4787c62a, 12);
  MD5_STEP (F1, c, d, a, b, w[6] + 0xa8304613, 17);
  MD5_STEP (F1, b, c, d, a, w[7] + 0xfd469501, 22);
  MD5_STEP (F1, a, b, c, d, w[8] + 0x698098d8, 7);
  MD5_STEP (F1, d, a, b, c, w[9] + 0x8b44f7af, 12);
  MD5_STEP (F1, c, d, a, b, w[10] + 0xffff5bb1, 17);
  MD5_STEP (F1, b, c, d, a, w[11] + 0x895cd7be, 22);
  MD5_STEP (F1, a, b, c, d, w[12] + 0x6b901122, 7);
  MD5_STEP (F1, d, a, b, c, w[13] + 0xfd987193, 12);
  MD5_STEP (F1, c, d, a, b, w[14] + 0xa679438e, 17);
  MD5_STEP (F1, b, c, d, a, w[15] + 0x49b40821, 22);

  MD5_STEP (F2, a, b, c, d, w[1] + 0xf61e2562, 5);
  MD5_STEP (F2, d, a, b, c, w[6] + 0xc040b340, 9);
  MD5_STEP (F2, c, d, a, b, w[11] + 0x265e5a51, 14);
  MD5_STEP (F2, b, c, d, a, w[0] + 0xe9b6c7aa, 20);
  MD5_STEP (F2, a, b, c, d, w[5] + 0xd62f105d, 5);
  MD5_STEP (F2, d, a, b, c, w[10] + 0x02441453, 9);
  MD5_STEP (F2, c, d, a, b, w[15] + 0xd8a1e681, 14);
  MD5_STEP (F2, b, c, d, a, w[4] + 0xe7d3fbc8, 20);
  MD5_STEP (F2, a, b, c, d, w[9] + 0x21e1cde6, 5);
  MD5_STEP (F2, d, a, b, c, w[14] + 0xc33707d6, 9);
  MD5_STEP (F2, c, d, a, b, w[3] + 0xf4d50d87, 14);
  MD5_STEP (F2, b, c, d, a, w[8] + 0x455a14ed, 20);
  MD5_STEP (F2, a, b, c, d, w[13] + 0xa9e3e905, 5);
  MD5_STEP (F2, d, a, b, c, w[2] + 0xfcefa3f8, 9);
  MD5_STEP (F2, c, d, a, b, w[7] + 0x676f02d9, 14);
  MD5_STEP (F2, b, c, d, a, w[12] + 0x8d2a4c8a, 20);

  MD5_STEP (F3, a, b, c, d, w[5] + 0xfffa3942, 4);
  MD5_STEP (F3, d, a, b, c, w[8] + 0x8771f681, 11);
  MD5_STEP (F3, c, d, a, b, w[11] + 0x6d9d6122, 16);
  MD5_STEP (F3, b, c, d, a, w[14] + 0xfde5380c, 23);
  MD5_STEP (F3, a, b, c, d, w[1] + 0xa4beea44, 4);
  MD5_STEP (F3, d, a, b, c, w[4] + 0x4bdecfa9, 11);
  MD5_STEP (F3, c, d, a, b, w[7] + 0xf6bb4b60, 16);
  MD5_STEP (F3, b, c, d, a, w[10] + 0xbebfbc70, 23);
  MD5_STEP (F3, a, b, c, d, w[13] + 0x289b7ec6, 4);
  MD5_STEP (F3, d, a, b, c, w[0] + 0xeaa127fa, 11);
  MD5_STEP (F3, c, d, a, b, w[3] + 0xd4ef3085, 16);
  MD5_STEP (F3, b, c, d, a, w[6] + 0x04881d05, 23);
  MD5_STEP (F3, a, b, c, d, w[9] + 0xd9d4d039, 4);
  MD5_STEP (F3, d, a, b, c, w[12] + 0xe6db99e5, 11);
  MD5_STEP (F3, c, d, a, b, w[15] + 0x1fa27cf8, 16);
  MD5_STEP (F3, b, c, d, a, w[2] + 0xc4ac5665, 23);

  MD5_STEP (F4, a, b, c, d, w[0] + 0xf4292244, 6);
  MD5_STEP (F4, d, a, b, c, w[7] + 0x432aff97, 10);
  MD5_STEP (F4, c, d, a, b, w[14] + 0xab9423a7, 15);
  MD5_STEP (F4, b, c, d, a, w[5] + 0xfc93a039, 21);
  MD5_STEP (F4, a, b, c, d, w[12] + 0x655b59c3, 6);
  MD5_STEP (F4, d, a, b, c, w[3] + 0x8f0ccc92, 10);
  MD5_STEP (F4, c, d, a, b, w[10] + 0xffeff47d, 15);
  MD5_STEP (F4, b, c, d, a, w[1] + 0x85845dd1, 21);
  MD5_STEP (F4, a, b, c, d, w[8] + 0x6fa87e4f, 6);
  MD5_STEP (F4, d, a, b, c, w[15] + 0xfe2ce6e0, 10);
  MD5_STEP (F4, c, d, a, b, w[6] + 0xa3014314, 15);
  MD5_STEP (F4, b, c, d, a, w[13] + 0x4e0811a1, 21);
  MD5_STEP (F4, a, b, c, d, w[4] + 0xf7537e82, 6);
  MD5_STEP (F4, d, a, b, c, w[11] + 0xbd3af235, 10);
  MD5_STEP (F4, c, d, a, b, w[2] + 0x2ad7d2bb, 15);
  MD5_STEP (F4, b, c, d, a, w[9] + 0xeb86d391, 21);

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
}

void
md5_update (struct md5_ctx *ctx, const void *inputptr, size_t inputlen)
{
  size_t filled, need;
  const uint8_t *input = inputptr;

  if (inputlen == 0)
    return;

  filled = (size_t)((ctx->count >> 3) & (MD5_BLOCK_SIZE - 1));
  need = MD5_BLOCK_SIZE - filled;
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
      md5_transform (ctx->state, ctx->buffer);
      inputlen -= need;
      input += need;
    }

  /* Handle as many blocks as possible. */
  while (inputlen >= MD5_BLOCK_SIZE)
    {
      md5_transform (ctx->state, input);
      inputlen -= MD5_BLOCK_SIZE;
      input += MD5_BLOCK_SIZE;
    }

  /* Save any remaining bytes. */
  if (inputlen != 0)
    memcpy (ctx->buffer, input, inputlen);
}

void
md5_final (uint8_t *digest, struct md5_ctx *ctx)
{
  size_t padoffset;
  uint32_t i;

  padoffset = (size_t)((ctx->count >> 3) & (MD5_BLOCK_SIZE - 1));
  ctx->buffer[padoffset++] = 0x80;

  /* Enough room for count. */
  if (padoffset <= 56)
    memset (&ctx->buffer[padoffset], 0, 56 - padoffset);
  else
    {
      /* Not enough room for count. */
      memset (&ctx->buffer[padoffset], 0, MD5_BLOCK_SIZE - padoffset);
      md5_transform (ctx->state, ctx->buffer);
      memset (ctx->buffer, 0, 56);
    }

  /* Append the count and handle the block. */
  buff_put_le64 (ctx->buffer + 56, ctx->count);
  md5_transform (ctx->state, ctx->buffer);

  for (i = 0; i < 4; ++i)
    buff_put_le32 (digest + i * 4, ctx->state[i]);
  memset (ctx, 0, sizeof (*ctx));
}
