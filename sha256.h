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

#ifndef SHA256_H
#define SHA256_H

#include <stddef.h>
#include <stdint.h>

#define SHA256_DIGEST_SIZE 32
#define SHA256_BLOCK_SIZE 64

#define SHA224_DIGEST_SIZE 28
#define SHA224_BLOCK_SIZE 64

struct sha256_ctx
{
  uint32_t state[8];                 /* Hash state */
  uint64_t count;                    /* Number of bits mod 2^64 */
  uint8_t buffer[SHA256_BLOCK_SIZE]; /* Input buffer */
};

/* SHA-256 */
void sha256_init (struct sha256_ctx *);
void sha256_transform (uint32_t *, const uint8_t *);
void sha256_update (struct sha256_ctx *, const void *, size_t);
void sha256_final (uint8_t *, struct sha256_ctx *);

/* SHA-224 */
void sha224_init (struct sha256_ctx *);
void sha224_transform (uint32_t *, const uint8_t *);
void sha224_update (struct sha256_ctx *, const void *, size_t);
void sha224_final (uint8_t *, struct sha256_ctx *);

#endif /* SHA256_H */
