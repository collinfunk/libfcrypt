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
 * Implementation of the BLAKE2b variant of BLAKE2. More information
 * about BLAKE2 can be found at https://blake2.net/. Original design by
 * Jean-Philippe Aumasson, Samuel Neves, Zooko Wilcox-O'Hearn, and
 * Christian Winnerlein.
 */

#ifndef BLAKE2B_H
#define BLAKE2B_H

#include <stddef.h>
#include <stdint.h>

#define BLAKE2B_DIGEST_SIZE 64
#define BLAKE2B_KEY_SIZE 64
#define BLAKE2B_BLOCK_SIZE 128

struct blake2b_ctx
{
  uint64_t state[8];
  uint64_t t[2];
  uint64_t f[2];
  uint8_t buffer[BLAKE2B_BLOCK_SIZE];
  size_t bufferlen;
  size_t digestlen;
};

void blake2b_init (struct blake2b_ctx *, size_t);
void blake2b_init_key (struct blake2b_ctx *, size_t, const uint8_t *, size_t);
void blake2b_update (struct blake2b_ctx *, const void *, size_t);
void blake2b_final (uint8_t *, struct blake2b_ctx *);
void blake2b (uint8_t *, const uint8_t *, const uint8_t *, const size_t,
              const size_t, const size_t);

#endif /* BLAKE2B_H */
