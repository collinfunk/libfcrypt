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
 * Implementation of the BLAKE2s variant of BLAKE2. More information
 * about BLAKE2 can be found at https://blake2.net/. Original design by
 * Jean-Philippe Aumasson, Samuel Neves, Zooko Wilcox-O'Hearn, and
 * Christian Winnerlein.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "blake2s.h"
#include "bswap.h"
#include "circularshift.h"

#define BLAKE2S_INCREMENT_COUNTER(ctx, inc) do {                     \
		(ctx)->t[0] += (inc);                                \
		if ((ctx)->t[0] < (inc))                             \
			(ctx)->t[1]++;                               \
} while (0)

#define BLAKE2S_SET_LAST_BLOCK(ctx) ((ctx)->f[0] = (uint32_t)-1)

#define BLAKE2S_G(m, r, i, a, b, c, d) do {                          \
	(a) += (b) + (m)[blake2s_sigma[(r)][2 * (i)]];               \
	(d) ^= (a);                                                  \
	(d) = rotr32((d), 16);                                       \
	(c) += (d);                                                  \
	(b) ^= (c);                                                  \
	(b) = rotr32((b), 12);                                       \
	(a) += (b) + (m)[blake2s_sigma[(r)][(2 * (i)) + 1]];         \
	(d) ^= (a);                                                  \
	(d) = rotr32((d), 8);                                        \
	(c) += (d);                                                  \
	(b) ^= (c);                                                  \
	(b) = rotr32((b), 7);                                        \
} while (0)

#define BLAKE2S_ROUND(m, v, r) do {                                  \
	BLAKE2S_G(m, r, 0, (v)[0], (v)[4], (v)[ 8], (v)[12]);        \
	BLAKE2S_G(m, r, 1, (v)[1], (v)[5], (v)[ 9], (v)[13]);        \
	BLAKE2S_G(m, r, 2, (v)[2], (v)[6], (v)[10], (v)[14]);        \
	BLAKE2S_G(m, r, 3, (v)[3], (v)[7], (v)[11], (v)[15]);        \
	BLAKE2S_G(m, r, 4, (v)[0], (v)[5], (v)[10], (v)[15]);        \
	BLAKE2S_G(m, r, 5, (v)[1], (v)[6], (v)[11], (v)[12]);        \
	BLAKE2S_G(m, r, 6, (v)[2], (v)[7], (v)[ 8], (v)[13]);        \
	BLAKE2S_G(m, r, 7, (v)[3], (v)[4], (v)[ 9], (v)[14]);        \
} while (0)

static const uint8_t blake2s_sigma[10][16] = {
	{ 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15},
	{14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3},
	{11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4},
	{ 7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8},
	{ 9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13},
	{ 2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9},
	{12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11},
	{13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10},
	{ 6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5},
	{10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0},
};

void
blake2s_init(struct blake2s_ctx *ctx, size_t digestlen)
{
	ctx->state[0] = 0x6a09e667;
	ctx->state[1] = 0xbb67ae85;
	ctx->state[2] = 0x3c6ef372;
	ctx->state[3] = 0xa54ff53a;
	ctx->state[4] = 0x510e527f;
	ctx->state[5] = 0x9b05688c;
	ctx->state[6] = 0x1f83d9ab;
	ctx->state[7] = 0x5be0cd19;
	ctx->state[0] ^= 0x01010000 | digestlen;
	ctx->t[0] = 0;
	ctx->t[1] = 0;
	ctx->f[0] = 0;
	ctx->f[1] = 0;
	ctx->bufferlen = 0;
	ctx->digestlen = digestlen;
}

void
blake2s_init_key(struct blake2s_ctx *ctx, size_t digestlen,
		const uint8_t *key, size_t keylen)
{
	ctx->state[0] = 0x6a09e667;
	ctx->state[1] = 0xbb67ae85;
	ctx->state[2] = 0x3c6ef372;
	ctx->state[3] = 0xa54ff53a;
	ctx->state[4] = 0x510e527f;
	ctx->state[5] = 0x9b05688c;
	ctx->state[6] = 0x1f83d9ab;
	ctx->state[7] = 0x5be0cd19;
	ctx->state[0] ^= 0x01010000 | (keylen << 8) | digestlen;
	ctx->t[0] = 0;
	ctx->t[1] = 0;
	ctx->f[0] = 0;
	ctx->f[1] = 0;
	ctx->digestlen = digestlen;
	memcpy(ctx->buffer, key, keylen);
	memset(&ctx->buffer[keylen], 0, BLAKE2S_BLOCK_SIZE - keylen);
	ctx->bufferlen = BLAKE2S_BLOCK_SIZE;
}

static void
blake2s_compress_blocks(struct blake2s_ctx *ctx, const uint8_t *blocks,
		size_t count, const uint32_t increment)
{
	uint32_t m[16], v[16];
	uint32_t i;

	for (; count > 0; --count) {
		BLAKE2S_INCREMENT_COUNTER(ctx, increment);
		for (i = 0; i < 16; ++i)
			m[i] = buff_get_le32(blocks + i * 4);
		memcpy(v, ctx->state, 32);
		v[ 8] = 0x6a09e667;
		v[ 9] = 0xbb67ae85;
		v[10] = 0x3c6ef372;
		v[11] = 0xa54ff53a;
		v[12] = 0x510e527f ^ ctx->t[0];
		v[13] = 0x9b05688c ^ ctx->t[1];
		v[14] = 0x1f83d9ab ^ ctx->f[0];
		v[15] = 0x5be0cd19 ^ ctx->f[1];
		BLAKE2S_ROUND(m, v, 0);
		BLAKE2S_ROUND(m, v, 1);
		BLAKE2S_ROUND(m, v, 2);
		BLAKE2S_ROUND(m, v, 3);
		BLAKE2S_ROUND(m, v, 4);
		BLAKE2S_ROUND(m, v, 5);
		BLAKE2S_ROUND(m, v, 6);
		BLAKE2S_ROUND(m, v, 7);
		BLAKE2S_ROUND(m, v, 8);
		BLAKE2S_ROUND(m, v, 9);
		for (i = 0; i < 8; ++i)
			ctx->state[i] ^= v[i]  ^ v[i + 8];
		blocks += BLAKE2S_BLOCK_SIZE;
	}
}

void
blake2s_update(struct blake2s_ctx *ctx, const void *inputptr,
		size_t inputlen)
{
	const size_t need = BLAKE2S_BLOCK_SIZE - ctx->bufferlen;
	const uint8_t *input = inputptr;

	if (inputlen == 0)
		return;

	/* Compress the buffer first. */
	if (inputlen > need) {
		memcpy(&ctx->buffer[ctx->bufferlen], input, need);
		blake2s_compress_blocks(ctx, ctx->buffer, 1,
				BLAKE2S_BLOCK_SIZE);
		ctx->bufferlen = 0;
		input += need;
		inputlen -= need;
	}

	/* Compress all blocks except for one. */
	if (inputlen > BLAKE2S_BLOCK_SIZE) {
		const size_t count = (inputlen + BLAKE2S_BLOCK_SIZE - 1) /
			BLAKE2S_BLOCK_SIZE;
		blake2s_compress_blocks(ctx, input, count - 1,
				BLAKE2S_BLOCK_SIZE);
		input += BLAKE2S_BLOCK_SIZE * (count - 1);
		inputlen -= BLAKE2S_BLOCK_SIZE * (count - 1);
	}

	/* Save the remaining bytes from input. */
	memcpy(&ctx->buffer[ctx->bufferlen], input, inputlen);
	ctx->bufferlen += inputlen;
}

void
blake2s_final(uint8_t *digest, struct blake2s_ctx *ctx)
{
	uint32_t i;

	BLAKE2S_SET_LAST_BLOCK(ctx);
	memset(&ctx->buffer[ctx->bufferlen], 0,
			BLAKE2S_BLOCK_SIZE - ctx->bufferlen);
	blake2s_compress_blocks(ctx, ctx->buffer, 1, ctx->bufferlen);

	/* Set the state to little-endian and output digest. */
	for (i = 0; i < 8; ++i)
		ctx->state[i] = cpu_to_le32(ctx->state[i]);
	memcpy(digest, ctx->state, ctx->digestlen);
	memset(ctx, 0, sizeof(*ctx));
}

void
blake2s(uint8_t *digest, const uint8_t *input, const uint8_t *key,
		const size_t digestlen, const size_t inputlen,
		const size_t keylen)
{
	struct blake2s_ctx ctx;

	if (keylen == 0)
		blake2s_init(&ctx, digestlen);
	else
		blake2s_init_key(&ctx, digestlen, key, keylen);
	blake2s_update(&ctx, input, inputlen);
	blake2s_final(digest, &ctx);
}

