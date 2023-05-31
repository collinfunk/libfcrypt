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
#include "siphash.h"

#define SIPHASH_ROUND(v)                                                      \
  do                                                                          \
    {                                                                         \
      (v)[0] += (v)[1];                                                       \
      (v)[1] = rotl64 ((v)[1], 13);                                           \
      (v)[1] ^= (v)[0];                                                       \
      (v)[0] = rotl64 ((v)[0], 32);                                           \
      (v)[2] += (v)[3];                                                       \
      (v)[3] = rotl64 ((v)[3], 16);                                           \
      (v)[3] ^= (v)[2];                                                       \
      (v)[0] += (v)[3];                                                       \
      (v)[3] = rotl64 ((v)[3], 21);                                           \
      (v)[3] ^= (v)[0];                                                       \
      (v)[2] += (v)[1];                                                       \
      (v)[1] = rotl64 ((v)[1], 17);                                           \
      (v)[1] ^= (v)[2];                                                       \
      (v)[2] = rotl64 ((v)[2], 32);                                           \
    }                                                                         \
  while (0)

void
siphash_init (struct siphash_ctx *ctx, uint8_t digestlen, const uint8_t *key,
              uint8_t crounds, uint8_t drounds)
{
  uint64_t k0, k1;

  k0 = buff_get_le64 (key);
  k1 = buff_get_le64 (key + 8);

  ctx->state[0] = 0x736f6d6570736575 ^ k0;
  ctx->state[1] = 0x646f72616e646f6d ^ k1;
  ctx->state[2] = 0x6c7967656e657261 ^ k0;
  ctx->state[3] = 0x7465646279746573 ^ k1;

  /*  Default to siphash-2-4. */
  ctx->crounds = (crounds != 0) ? crounds : SIPHASH_C_ROUNDS;
  ctx->drounds = (drounds != 0) ? drounds : SIPHASH_D_ROUNDS;
  if (digestlen != SIPHASH_MAX_DIGEST_SIZE)
    ctx->digestlen = SIPHASH_MIN_DIGEST_SIZE;
  else
    {
      ctx->digestlen = SIPHASH_MAX_DIGEST_SIZE;
      ctx->state[1] ^= 0xee;
    }

  ctx->bufferlen = 0;
  ctx->inputlen = 0;
}

void
siphash_update (struct siphash_ctx *ctx, const void *inputptr, size_t inputlen)
{
  size_t need;
  uint32_t i;
  uint64_t x;
  const uint8_t *input = inputptr;

  if (inputlen == 0)
    return;

  ctx->inputlen += inputlen;

  if (ctx->bufferlen != 0)
    {
      need = SIPHASH_BLOCK_SIZE - ctx->bufferlen;

      /* Not enough to fill buffer. */
      if (inputlen < need)
        {
          memcpy (&ctx->buffer[ctx->bufferlen], input, inputlen);
          ctx->bufferlen += inputlen;
          return;
        }

      /* Fill the buffer. */
      memcpy (&ctx->buffer[ctx->bufferlen], input, need);
      inputlen -= need;
      input += need;

      /* Process the buffer. */
      x = buff_get_le64 (ctx->buffer);
      ctx->state[3] ^= x;
      for (i = 0; i < ctx->crounds; ++i)
        SIPHASH_ROUND (ctx->state);
      ctx->state[0] ^= x;
    }

  /* Handle all complete blocks. */
  while (inputlen >= SIPHASH_BLOCK_SIZE)
    {
      x = buff_get_le64 (input);
      ctx->state[3] ^= x;
      for (i = 0; i < ctx->crounds; ++i)
        SIPHASH_ROUND (ctx->state);
      ctx->state[0] ^= x;
      input += SIPHASH_BLOCK_SIZE;
      inputlen -= SIPHASH_BLOCK_SIZE;
    }

  /* Save any remaining bytes. */
  if (inputlen != 0)
    memcpy (ctx->buffer, input, inputlen);
  ctx->bufferlen = inputlen;
}

void
siphash_final (uint8_t *digest, struct siphash_ctx *ctx)
{
  uint64_t x;
  uint32_t i;

  x = ctx->inputlen << 56;
  /* Handle remaining bytes in buffer. */
  switch (ctx->bufferlen)
    {
    case 7:
      x |= ((uint64_t)ctx->buffer[6]) << 48;
      /* FALLTHROUGH */
    case 6:
      x |= ((uint64_t)ctx->buffer[5]) << 40;
      /* FALLTHROUGH */
    case 5:
      x |= ((uint64_t)ctx->buffer[4]) << 32;
      /* FALLTHROUGH */
    case 4:
      x |= ((uint64_t)ctx->buffer[3]) << 24;
      /* FALLTHROUGH */
    case 3:
      x |= ((uint64_t)ctx->buffer[2]) << 16;
      /* FALLTHROUGH */
    case 2:
      x |= ((uint64_t)ctx->buffer[1]) << 8;
      /* FALLTHROUGH */
    case 1:
      x |= ((uint64_t)ctx->buffer[0]);
      /* FALLTHROUGH */
    case 0:
      /* FALLTHROUGH */
    default:
      break;
    }

  ctx->state[3] ^= x;
  for (i = 0; i < ctx->crounds; ++i)
    SIPHASH_ROUND (ctx->state);
  ctx->state[0] ^= x;
  if (ctx->digestlen == SIPHASH_MAX_DIGEST_SIZE)
    ctx->state[2] ^= 0xee;
  else
    ctx->state[2] ^= 0xff;
  for (i = 0; i < ctx->drounds; ++i)
    SIPHASH_ROUND (ctx->state);
  x = ctx->state[0] ^ ctx->state[1] ^ ctx->state[2] ^ ctx->state[3];
  buff_put_le64 (digest, x);
  if (ctx->digestlen == SIPHASH_MIN_DIGEST_SIZE)
    goto cleanup;
  ctx->state[1] ^= 0xdd;
  for (i = 0; i < ctx->drounds; ++i)
    SIPHASH_ROUND (ctx->state);
  x = ctx->state[0] ^ ctx->state[1] ^ ctx->state[2] ^ ctx->state[3];
  buff_put_le64 (digest + 8, x);
cleanup:
  fcrypt_memzero (ctx, sizeof (*ctx));
  return;
}
