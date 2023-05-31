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
#include "sha512.h"

/* Functions used by SHA-384 and SHA-512. */
#define Ch(b, c, d) (((b) & (c)) ^ ((~(b)) & (d)))
#define Maj(b, c, d) (((b) & (c)) ^ ((b) & (d)) ^ ((c) & (d)))
#define Sigma0(x) (rotr64 ((x), 28) ^ rotr64 ((x), 34) ^ rotr64 ((x), 39))
#define Sigma1(x) (rotr64 ((x), 14) ^ rotr64 ((x), 18) ^ rotr64 ((x), 41))
#define sigma0(x) (rotr64 ((x), 1) ^ rotr64 ((x), 8) ^ ((x) >> 7))
#define sigma1(x) (rotr64 ((x), 19) ^ rotr64 ((x), 61) ^ ((x) >> 6))

/* Constant values used by SHA-384 and SHA-512. */
#define K(x) (sha512_ktable[(x)])
static const uint64_t sha512_ktable[80]
    = { 0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f,
        0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019,
        0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242,
        0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
        0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
        0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275,
        0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
        0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f,
        0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
        0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc,
        0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
        0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6,
        0x92722c851482353b, 0xa2bfe8a14cf10364, 0xa81a664bbc423001,
        0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
        0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99,
        0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
        0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc,
        0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
        0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915,
        0xc67178f2e372532b, 0xca273eceea26619c, 0xd186b8c721c0c207,
        0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba,
        0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
        0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
        0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
        0x5fcb6fab3ad6faec, 0x6c44198c4a475817 };

void
sha512_init (struct sha512_ctx *ctx)
{
  ctx->state[0] = 0x6a09e667f3bcc908;
  ctx->state[1] = 0xbb67ae8584caa73b;
  ctx->state[2] = 0x3c6ef372fe94f82b;
  ctx->state[3] = 0xa54ff53a5f1d36f1;
  ctx->state[4] = 0x510e527fade682d1;
  ctx->state[5] = 0x9b05688c2b3e6c1f;
  ctx->state[6] = 0x1f83d9abfb41bd6b;
  ctx->state[7] = 0x5be0cd19137e2179;
  ctx->count[0] = 0;
  ctx->count[1] = 0;
}

void
sha512_transform (uint64_t *state, const uint8_t *block)
{
  uint64_t a, b, c, d, e, f, g, h, t1, t2;
  uint64_t w[80];
  uint32_t i;

  for (i = 0; i < 16; ++i)
    w[i] = buff_get_be64 (block + i * 8);
  for (i = 16; i < 80; ++i)
    w[i] = sigma1 (w[i - 2]) + w[i - 7] + sigma0 (w[i - 15]) + w[i - 16];

  a = state[0];
  b = state[1];
  c = state[2];
  d = state[3];
  e = state[4];
  f = state[5];
  g = state[6];
  h = state[7];

  for (i = 0; i < 80; ++i)
    {
      t1 = h + Sigma1 (e) + Ch (e, f, g) + K (i) + w[i];
      t2 = Sigma0 (a) + Maj (a, b, c);
      h = g;
      g = f;
      f = e;
      e = d + t1;
      d = c;
      c = b;
      b = a;
      a = t1 + t2;
    }

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;
  state[5] += f;
  state[6] += g;
  state[7] += h;
}

void
sha512_update (struct sha512_ctx *ctx, const void *inputptr, size_t inputlen)
{
  size_t filled, need;
  uint64_t increment;
  const uint8_t *input = inputptr;

  if (inputlen == 0)
    return;

  filled = (size_t)((ctx->count[0] >> 3) & (SHA512_BLOCK_SIZE - 1));
  need = SHA512_BLOCK_SIZE - filled;
  increment = (uint64_t)(inputlen << 3);
  ctx->count[0] += increment;
  if (ctx->count[0] < increment)
    ctx->count[1]++;

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
      sha512_transform (ctx->state, ctx->buffer);
      inputlen -= need;
      input += need;
    }

  /* Handle as many blocks as possible. */
  while (inputlen >= SHA512_BLOCK_SIZE)
    {
      sha512_transform (ctx->state, input);
      inputlen -= SHA512_BLOCK_SIZE;
      input += SHA512_BLOCK_SIZE;
    }

  /* Save any remaining bytes. */
  if (inputlen != 0)
    memcpy (ctx->buffer, input, inputlen);
}

/*
 * Internal function used by both SHA-384 and SHA-512. Pads the buffer to
 * 896 bits (112 bytes) so that the 128-bit length can be appended to the end.
 */
static void
sha512_pad (struct sha512_ctx *ctx)
{
  size_t padoffset;

  padoffset = (size_t)((ctx->count[0] >> 3) & (SHA512_BLOCK_SIZE - 1));
  ctx->buffer[padoffset++] = 0x80;

  /* Enough room for count. */
  if (padoffset <= 112)
    memset (&ctx->buffer[padoffset], 0, 112 - padoffset);
  else
    {
      /* Not enough room for count. */
      memset (&ctx->buffer[padoffset], 0, SHA512_BLOCK_SIZE - padoffset);
      sha512_transform (ctx->state, ctx->buffer);
      memset (ctx->buffer, 0, 112);
    }

  /* Append the count and handle the block. */
  buff_put_be64 (ctx->buffer + 112, ctx->count[1]);
  buff_put_be64 (ctx->buffer + 120, ctx->count[0]);
  sha512_transform (ctx->state, ctx->buffer);
}

void
sha512_final (uint8_t *digest, struct sha512_ctx *ctx)
{
  uint32_t i;

  sha512_pad (ctx);

  for (i = 0; i < 8; ++i)
    buff_put_be64 (digest + i * 8, ctx->state[i]);
  memset (ctx, 0, sizeof (*ctx));
}

void
sha384_init (struct sha512_ctx *ctx)
{
  ctx->state[0] = 0xcbbb9d5dc1059ed8;
  ctx->state[1] = 0x629a292a367cd507;
  ctx->state[2] = 0x9159015a3070dd17;
  ctx->state[3] = 0x152fecd8f70e5939;
  ctx->state[4] = 0x67332667ffc00b31;
  ctx->state[5] = 0x8eb44a8768581511;
  ctx->state[6] = 0xdb0c2e0d64f98fa7;
  ctx->state[7] = 0x47b5481dbefa4fa4;
  ctx->count[0] = 0;
  ctx->count[1] = 0;
}

void
sha384_transform (uint64_t *state, const uint8_t *block)
{
  /* Same as SHA-512. */
  sha512_transform (state, block);
}

void
sha384_update (struct sha512_ctx *ctx, const void *inputptr, size_t inputlen)
{
  /* Same as SHA-512. */
  sha512_update (ctx, inputptr, inputlen);
}

void
sha384_final (uint8_t *digest, struct sha512_ctx *ctx)
{
  uint32_t i;

  sha512_pad (ctx);

  for (i = 0; i < 6; ++i)
    buff_put_be64 (digest + i * 8, ctx->state[i]);
  memset (ctx, 0, sizeof (*ctx));
}
