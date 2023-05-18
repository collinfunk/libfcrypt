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

#include "sha256.h"
#include "bswap.h"
#include "circularshift.h"

/* Functions used by SHA-224 and SHA-256. */
#define Ch(b, c, d) (((b) & (c)) ^ ((~(b)) & (d)))
#define Maj(b, c, d) (((b) & (c)) ^ ((b) & (d)) ^ ((c) & (d)))
#define Sigma0(x) (rotr32((x),  2) ^ rotr32((x), 13) ^ rotr32((x), 22))
#define Sigma1(x) (rotr32((x),  6) ^ rotr32((x), 11) ^ rotr32((x), 25))
#define sigma0(x) (rotr32((x),  7) ^ rotr32((x), 18) ^ ((x) >> 3))
#define sigma1(x) (rotr32((x), 17) ^ rotr32((x), 19) ^ ((x) >> 10))

/* Constant values used by SHA-224 and SHA-256. */
#define K(x) (sha256_ktable[(x)])
static const uint32_t sha256_ktable[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

void
sha256_init(struct sha256_ctx *ctx)
{
	ctx->state[0] = 0x6a09e667;
	ctx->state[1] = 0xbb67ae85;
	ctx->state[2] = 0x3c6ef372;
	ctx->state[3] = 0xa54ff53a;
	ctx->state[4] = 0x510e527f;
	ctx->state[5] = 0x9b05688c;
	ctx->state[6] = 0x1f83d9ab;
	ctx->state[7] = 0x5be0cd19;
	ctx->count = 0;
}

void
sha256_transform(uint32_t *state, const uint8_t *block)
{
	uint32_t a, b, c, d, e, f, g, h, i, t1, t2;
	uint32_t w[64];

	for (i = 0; i < 16; ++i)
		w[i] = buff_get_be32(block + i * 4);
	for (i = 16; i < 64; ++i)
		w[i] = sigma1(w[i - 2]) + w[i - 7] +
			sigma0(w[i - 15]) + w[i - 16];

	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];
	e = state[4];
	f = state[5];
	g = state[6];
	h = state[7];

	for (i = 0; i < 64; ++i) {
		t1 = h + Sigma1(e) + Ch(e, f, g) + K(i) + w[i];
		t2 = Sigma0(a) + Maj(a, b, c);
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
sha256_update(struct sha256_ctx *ctx, const void *inputptr, size_t inputlen)
{
	size_t filled, need;
	const uint8_t *input = inputptr;

	if (inputlen == 0)
		return;

	filled = (size_t)((ctx->count >> 3) & (SHA256_BLOCK_SIZE - 1));
	need = SHA256_BLOCK_SIZE - filled;
	ctx->count += (uint64_t)(inputlen << 3);

	/* Input too short to fill a complete block. */
	if (inputlen < need) {
		memcpy(&ctx->buffer[filled], input, inputlen);
		return;
	}

	/* Check if we need to finish the buffer in ctx. */
	if (filled != 0) {
		memcpy(&ctx->buffer[filled], input, need);
		sha256_transform(ctx->state, ctx->buffer);
		inputlen -= need;
		input += need;
	}

	/* Handle as many blocks as possible. */
	while (inputlen >= SHA256_BLOCK_SIZE) {
		sha256_transform(ctx->state, input);
		inputlen -= SHA256_BLOCK_SIZE;
		input += SHA256_BLOCK_SIZE;
	}

	/* Save any remaining bytes. */
	if (inputlen != 0)
		memcpy(ctx->buffer, input, inputlen);
}

/*
 * Internal function used by both SHA-224 and SHA-256. Pads the buffer to
 * 448 bits (56 bytes) so that the 64-bit length can be appended to the end.
 */
static void
sha2xx_pad(struct sha256_ctx *ctx)
{
	size_t padoffset;

	padoffset = (size_t)((ctx->count >> 3) & (SHA256_BLOCK_SIZE - 1));
	ctx->buffer[padoffset++] = 0x80;

	/* Enough room for count. */
	if (padoffset <= 56)
		memset(&ctx->buffer[padoffset], 0, 56 - padoffset);
	else {
		/* Not enough room for count. */
		memset(&ctx->buffer[padoffset], 0, SHA256_BLOCK_SIZE -
				padoffset);
		sha256_transform(ctx->state, ctx->buffer);
		memset(ctx->buffer, 0, 56);
	}

	/* Append the count and handle the block. */
	buff_put_be64(ctx->buffer + 56, ctx->count);
	sha256_transform(ctx->state, ctx->buffer);
}

void
sha256_final(uint8_t *digest, struct sha256_ctx *ctx)
{
	uint32_t i;

	sha2xx_pad(ctx);

	for (i = 0; i < 8; ++i)
		buff_put_be32(digest + i * 4, ctx->state[i]);
	memset(ctx, 0, sizeof(*ctx));
}

void
sha224_init(struct sha256_ctx *ctx)
{
	ctx->state[0] = 0xc1059ed8;
	ctx->state[1] = 0x367cd507;
	ctx->state[2] = 0x3070dd17;
	ctx->state[3] = 0xf70e5939;
	ctx->state[4] = 0xffc00b31;
	ctx->state[5] = 0x68581511;
	ctx->state[6] = 0x64f98fa7;
	ctx->state[7] = 0xbefa4fa4;
	ctx->count = 0;
}

void
sha224_transform(uint32_t *state, const uint8_t *block)
{
	/* Same as SHA-256. */
	sha256_transform(state, block);
}

void
sha224_update(struct sha256_ctx *ctx, const void *inputptr, size_t inputlen)
{
	/* Same as SHA-256. */
	sha256_update(ctx, inputptr, inputlen);
}

void
sha224_final(uint8_t *digest, struct sha256_ctx *ctx)
{
	uint32_t i;

	sha2xx_pad(ctx);

	for (i = 0; i < 7; ++i)
		buff_put_be32(digest + i * 4, ctx->state[i]);
	memset(ctx, 0, sizeof(*ctx));
}

