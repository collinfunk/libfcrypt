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

#ifndef TIGER_H
#define TIGER_H

#include <stddef.h>
#include <stdint.h>

#define TIGER_BLOCK_SIZE 64

#define TIGER192_DIGEST_SIZE 24
#define TIGER160_DIGEST_SIZE 20
#define TIGER128_DIGEST_SIZE 16

struct tiger_ctx
{
  uint64_t state[3];                /* Hash state */
  uint64_t count;                   /* Number of bits mod 2^64 */
  uint8_t buffer[TIGER_BLOCK_SIZE]; /* Input buffer */
  int version;                      /* Tiger2 if 1, else Tiger1 */
};

void tiger1_init (struct tiger_ctx *);
void tiger2_init (struct tiger_ctx *);
void tiger_transform (uint64_t *, const uint8_t *);
void tiger_update (struct tiger_ctx *, const void *, size_t);
void tiger192_final (uint8_t *, struct tiger_ctx *);
void tiger160_final (uint8_t *, struct tiger_ctx *);
void tiger128_final (uint8_t *, struct tiger_ctx *);

#endif /* TIGER_H */
