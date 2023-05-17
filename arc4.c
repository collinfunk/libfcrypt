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

#include "arc4.h"

void
arc4_set_key(struct arc4_ctx *ctx, const uint8_t *key, size_t keylen)
{
	size_t i, j, k;
	uint8_t t;

	for (i = 0; i < 256; ++i)
		ctx->state[i] = i;
	for (i = j = k = 0; i < 256; ++i) {
		j = (j + ctx->state[i] + key[k]) & 0xff;
		t = ctx->state[i];
		ctx->state[i] = ctx->state[j];
		ctx->state[j] = t;
		if (++k >= keylen)
			k = 0;
	}
	ctx->i = ctx->j = 0;
}

void
arc4_crypt(struct arc4_ctx *ctx, const uint8_t *src, uint8_t *dest, size_t len)
{
	size_t i;
	uint8_t t;

	for (i = 0; i < len; ++i) {
		ctx->i = (ctx->i + 1) & 0xff;
		ctx->j = (ctx->j + ctx->state[ctx->i]) & 0xff;
		t = ctx->state[ctx->i];
		ctx->state[ctx->i] = ctx->state[ctx->j];
		ctx->state[ctx->j] = t;
		dest[i] = src[i] ^ ctx->state[(ctx->state[ctx->i] +
				ctx->state[ctx->j]) & 0xff];
	}
}

