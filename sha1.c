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

#include "sha1.h"
#include "bswap.h"
#include "circularshift.h"

/* Logical functions used by SHA-1. */
#define F1(b, c, d) (((b) & (c)) | ((~(b)) & (d)))
#define F2(b, c, d) ((b) ^ (c) ^ (d))
#define F3(b, c, d) (((b) & (c)) | ((b) & (d)) | ((c) & (d)))
#define F4(b, c, d) ((b) ^ (c) ^ (d))

/* Constants used by SHA-1. */
#define K1 0x5a827999
#define K2 0x6ed9eba1
#define K3 0x8f1bbcdc
#define K4 0xca62c1d6

void
sha1_init(struct sha1_ctx *ctx)
{
	ctx->state[0] = 0x67452301;
	ctx->state[1] = 0xefcdab89;
	ctx->state[2] = 0x98badcfe;
	ctx->state[3] = 0x10325476;
	ctx->state[4] = 0xc3d2e1f0;
	ctx->count = 0;
}

void
sha1_transform(uint32_t *state, const uint8_t *block)
{
	uint32_t a, b, c, d, e, t, i;
	uint32_t w[80];

	for (i = 0; i < 16; ++i)
		w[i] = buff_get_be32(block + i * 4);
	for (i = 16; i < 80; ++i)
		w[i] = rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];
	e = state[4];

	for (i = 0; i < 20; ++i) {
		t = rotl32(a, 5) + F1(b, c, d) + e + w[i] + K1;
		e = d;
		d = c;
		c = rotl32(b, 30);
		b = a;
		a = t;
	}
	for (i = 20; i < 40; ++i) {
		t = rotl32(a, 5) + F2(b, c, d) + e + w[i] + K2;
		e = d;
		d = c;
		c = rotl32(b, 30);
		b = a;
		a = t;
	}
	for (i = 40; i < 60; ++i) {
		t = rotl32(a, 5) + F3(b, c, d) + e + w[i] + K3;
		e = d;
		d = c;
		c = rotl32(b, 30);
		b = a;
		a = t;
	}
	for (i = 60; i < 80; ++i) {
		t = rotl32(a, 5) + F4(b, c, d) + e + w[i] + K4;
		e = d;
		d = c;
		c = rotl32(b, 30);
		b = a;
		a = t;
	}

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;
}

void
sha1_update(struct sha1_ctx *ctx, const void *inputptr, size_t inputlen)
{
	size_t filled, need;
	const uint8_t *input = inputptr;

	if (inputlen == 0)
		return;

	filled = (size_t)((ctx->count >> 3) & (SHA1_BLOCK_SIZE - 1));
	need = SHA1_BLOCK_SIZE - filled;
	ctx->count += (uint64_t)(inputlen << 3);

	/* Input too short to fill a complete block. */
	if (inputlen < need) {
		memcpy(&ctx->buffer[filled], input, inputlen);
		return;
	}

	/* Check if we need to finish the buffer in ctx. */
	if (filled != 0) {
		memcpy(&ctx->buffer[filled], input, need);
		sha1_transform(ctx->state, ctx->buffer);
		inputlen -= need;
		input += need;
	}

	/* Handle as many blocks as possible. */
	while (inputlen >= SHA1_BLOCK_SIZE) {
		sha1_transform(ctx->state, input);
		inputlen -= SHA1_BLOCK_SIZE;
		input += SHA1_BLOCK_SIZE;
	}

	/* Save any remaining bytes. */
	if (inputlen != 0)
		memcpy(ctx->buffer, input, inputlen);
}

void
sha1_final(uint8_t *digest, struct sha1_ctx *ctx)
{
	size_t padoffset;
	uint32_t i;

	padoffset = (size_t)((ctx->count >> 3) & (SHA1_BLOCK_SIZE - 1));

	ctx->buffer[padoffset++] = 0x80;

	/* Enough room for count. */
	if (padoffset <= 56)
		memset(&ctx->buffer[padoffset], 0, 56 - padoffset);
	else {
		/* Not enough room for count. */
		memset(&ctx->buffer[padoffset], 0, SHA1_BLOCK_SIZE -
				padoffset);
		sha1_transform(ctx->state, ctx->buffer);
		memset(ctx->buffer, 0, 56);
	}

	/* Append the count and handle the block. */
	buff_put_be64(ctx->buffer + 56, ctx->count);
	sha1_transform(ctx->state, ctx->buffer);

	for (i = 0; i < 5; ++i)
		buff_put_be32(digest + i * 4, ctx->state[i]);
	memset(ctx, 0, sizeof(*ctx));
}

