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
 * Based on:
 * chacha-merged.c version 20080118
 * D. J. Bernstein
 * Public domain.
 * https://cr.yp.to/chacha.html
 */

#ifndef CHACHA_H
#define CHACHA_H

#include <stddef.h>
#include <stdint.h>

struct chacha_ctx
{
  uint32_t input[16];
};

void chacha128_set_key (struct chacha_ctx *, const uint8_t *);
void chacha256_set_key (struct chacha_ctx *, const uint8_t *);
void chacha_set_key (struct chacha_ctx *, const uint8_t *, size_t);
void chacha_set_iv (struct chacha_ctx *, const uint8_t *, const uint8_t *);
void chacha_encrypt_bytes (struct chacha_ctx *, const uint8_t *, uint8_t *,
                           size_t);

#endif /* CHACHA_H */
