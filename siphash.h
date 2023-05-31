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

#ifndef SIPHASH_H
#define SIPHASH_H

#include <stddef.h>
#include <stdint.h>

/* Default to Siphash24. */
#define SIPHASH_C_ROUNDS 2
#define SIPHASH_D_ROUNDS 4

#define SIPHASH_KEY_SIZE 16
#define SIPHASH_BLOCK_SIZE 8

#define SIPHASH_MIN_DIGEST_SIZE 8
#define SIPHASH_MAX_DIGEST_SIZE 16

struct siphash_ctx
{
  uint64_t state[4];                  /* Hash state. */
  uint8_t buffer[SIPHASH_BLOCK_SIZE]; /* Input buffer. */
  uint64_t inputlen;                  /* Total bytes. */
  uint8_t digestlen;                  /* 8 or 16 bytes. */
  uint8_t bufferlen;                  /* Used bytes in buffer. */
  uint8_t crounds;                    /* # of compression rounds. */
  uint8_t drounds;                    /* # of finalization rounds. */
};

void siphash_init (struct siphash_ctx *, uint8_t, const uint8_t *, uint8_t,
                   uint8_t);
void siphash_update (struct siphash_ctx *, const void *, size_t);
void siphash_final (uint8_t *, struct siphash_ctx *);

#endif /* SIPHASH_H */
