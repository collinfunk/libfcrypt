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

#include "rmd160.h"
#include "bswap.h"
#include "circularshift.h"
#include "fcrypt_memzero.h"

/* Functions used by RIPEMD-160. */
#define F1(b,c,d) ((b) ^ (c) ^ (d))
#define F2(b,c,d) (((b) & (c)) | ((~(b)) & (d)))
#define F3(b,c,d) (((b) | (~(c))) ^ (d))
#define F4(b,c,d) (((b) & (d)) | ((c) & (~(d))))
#define F5(b,c,d) ((b) ^ ((c) | (~(d))))

/* Constants used by RIPEMD-160. */
/* #define K1  0x00000000 */
#define K2  0x5a827999
#define K3  0x6ed9eba1
#define K4  0x8f1bbcdc
#define K5  0xa953fd4e
#define KP1 0x50a28be6
#define KP2 0x5c4dd124
#define KP3 0x6d703ef3
#define KP4 0x7a6d76e9
/* #define KP5 0x00000000 */

#define RMD160_STEP(f, a, b, c, d, e, x, s) do { \
	(a) += f((b), (c), (d)) + (x);           \
	(a) = rotl32((a), (s)) + (e);            \
	(c) = rotl32((c), 10);                   \
} while (0)

void
rmd160_init(struct rmd160_ctx *ctx)
{
	ctx->state[0] = 0x67452301;
	ctx->state[1] = 0xefcdab89;
	ctx->state[2] = 0x98badcfe;
	ctx->state[3] = 0x10325476;
	ctx->state[4] = 0xc3d2e1f0;
	ctx->count = 0;
}

void
rmd160_transform(uint32_t *state, const uint8_t *block)
{
	uint32_t a, b, c, d, e, i;
	uint32_t aa, bb, cc, dd, ee;
	uint32_t w[16];

	for (i = 0; i < 16; ++i)
		w[i] = buff_get_le32(block + i * 4);

	a = aa = state[0];
	b = bb = state[1];
	c = cc = state[2];
	d = dd = state[3];
	e = ee = state[4];

	RMD160_STEP(F1, a, b, c, d, e, w[ 0], 11);
	RMD160_STEP(F1, e, a, b, c, d, w[ 1], 14);
	RMD160_STEP(F1, d, e, a, b, c, w[ 2], 15);
	RMD160_STEP(F1, c, d, e, a, b, w[ 3], 12);
	RMD160_STEP(F1, b, c, d, e, a, w[ 4],  5);
	RMD160_STEP(F1, a, b, c, d, e, w[ 5],  8);
	RMD160_STEP(F1, e, a, b, c, d, w[ 6],  7);
	RMD160_STEP(F1, d, e, a, b, c, w[ 7],  9);
	RMD160_STEP(F1, c, d, e, a, b, w[ 8], 11);
	RMD160_STEP(F1, b, c, d, e, a, w[ 9], 13);
	RMD160_STEP(F1, a, b, c, d, e, w[10], 14);
	RMD160_STEP(F1, e, a, b, c, d, w[11], 15);
	RMD160_STEP(F1, d, e, a, b, c, w[12],  6);
	RMD160_STEP(F1, c, d, e, a, b, w[13],  7);
	RMD160_STEP(F1, b, c, d, e, a, w[14],  9);
	RMD160_STEP(F1, a, b, c, d, e, w[15],  8);

	RMD160_STEP(F2, e, a, b, c, d, w[ 7] + K2,  7);
	RMD160_STEP(F2, d, e, a, b, c, w[ 4] + K2,  6);
	RMD160_STEP(F2, c, d, e, a, b, w[13] + K2,  8);
	RMD160_STEP(F2, b, c, d, e, a, w[ 1] + K2, 13);
	RMD160_STEP(F2, a, b, c, d, e, w[10] + K2, 11);
	RMD160_STEP(F2, e, a, b, c, d, w[ 6] + K2,  9);
	RMD160_STEP(F2, d, e, a, b, c, w[15] + K2,  7);
	RMD160_STEP(F2, c, d, e, a, b, w[ 3] + K2, 15);
	RMD160_STEP(F2, b, c, d, e, a, w[12] + K2,  7);
	RMD160_STEP(F2, a, b, c, d, e, w[ 0] + K2, 12);
	RMD160_STEP(F2, e, a, b, c, d, w[ 9] + K2, 15);
	RMD160_STEP(F2, d, e, a, b, c, w[ 5] + K2,  9);
	RMD160_STEP(F2, c, d, e, a, b, w[ 2] + K2, 11);
	RMD160_STEP(F2, b, c, d, e, a, w[14] + K2,  7);
	RMD160_STEP(F2, a, b, c, d, e, w[11] + K2, 13);
	RMD160_STEP(F2, e, a, b, c, d, w[ 8] + K2, 12);

	RMD160_STEP(F3, d, e, a, b, c, w[ 3] + K3, 11);
	RMD160_STEP(F3, c, d, e, a, b, w[10] + K3, 13);
	RMD160_STEP(F3, b, c, d, e, a, w[14] + K3,  6);
	RMD160_STEP(F3, a, b, c, d, e, w[ 4] + K3,  7);
	RMD160_STEP(F3, e, a, b, c, d, w[ 9] + K3, 14);
	RMD160_STEP(F3, d, e, a, b, c, w[15] + K3,  9);
	RMD160_STEP(F3, c, d, e, a, b, w[ 8] + K3, 13);
	RMD160_STEP(F3, b, c, d, e, a, w[ 1] + K3, 15);
	RMD160_STEP(F3, a, b, c, d, e, w[ 2] + K3, 14);
	RMD160_STEP(F3, e, a, b, c, d, w[ 7] + K3,  8);
	RMD160_STEP(F3, d, e, a, b, c, w[ 0] + K3, 13);
	RMD160_STEP(F3, c, d, e, a, b, w[ 6] + K3,  6);
	RMD160_STEP(F3, b, c, d, e, a, w[13] + K3,  5);
	RMD160_STEP(F3, a, b, c, d, e, w[11] + K3, 12);
	RMD160_STEP(F3, e, a, b, c, d, w[ 5] + K3,  7);
	RMD160_STEP(F3, d, e, a, b, c, w[12] + K3,  5);

	RMD160_STEP(F4, c, d, e, a, b, w[ 1] + K4, 11);
	RMD160_STEP(F4, b, c, d, e, a, w[ 9] + K4, 12);
	RMD160_STEP(F4, a, b, c, d, e, w[11] + K4, 14);
	RMD160_STEP(F4, e, a, b, c, d, w[10] + K4, 15);
	RMD160_STEP(F4, d, e, a, b, c, w[ 0] + K4, 14);
	RMD160_STEP(F4, c, d, e, a, b, w[ 8] + K4, 15);
	RMD160_STEP(F4, b, c, d, e, a, w[12] + K4,  9);
	RMD160_STEP(F4, a, b, c, d, e, w[ 4] + K4,  8);
	RMD160_STEP(F4, e, a, b, c, d, w[13] + K4,  9);
	RMD160_STEP(F4, d, e, a, b, c, w[ 3] + K4, 14);
	RMD160_STEP(F4, c, d, e, a, b, w[ 7] + K4,  5);
	RMD160_STEP(F4, b, c, d, e, a, w[15] + K4,  6);
	RMD160_STEP(F4, a, b, c, d, e, w[14] + K4,  8);
	RMD160_STEP(F4, e, a, b, c, d, w[ 5] + K4,  6);
	RMD160_STEP(F4, d, e, a, b, c, w[ 6] + K4,  5);
	RMD160_STEP(F4, c, d, e, a, b, w[ 2] + K4, 12);

	RMD160_STEP(F5, b, c, d, e, a, w[ 4] + K5,  9);
	RMD160_STEP(F5, a, b, c, d, e, w[ 0] + K5, 15);
	RMD160_STEP(F5, e, a, b, c, d, w[ 5] + K5,  5);
	RMD160_STEP(F5, d, e, a, b, c, w[ 9] + K5, 11);
	RMD160_STEP(F5, c, d, e, a, b, w[ 7] + K5,  6);
	RMD160_STEP(F5, b, c, d, e, a, w[12] + K5,  8);
	RMD160_STEP(F5, a, b, c, d, e, w[ 2] + K5, 13);
	RMD160_STEP(F5, e, a, b, c, d, w[10] + K5, 12);
	RMD160_STEP(F5, d, e, a, b, c, w[14] + K5,  5);
	RMD160_STEP(F5, c, d, e, a, b, w[ 1] + K5, 12);
	RMD160_STEP(F5, b, c, d, e, a, w[ 3] + K5, 13);
	RMD160_STEP(F5, a, b, c, d, e, w[ 8] + K5, 14);
	RMD160_STEP(F5, e, a, b, c, d, w[11] + K5, 11);
	RMD160_STEP(F5, d, e, a, b, c, w[ 6] + K5,  8);
	RMD160_STEP(F5, c, d, e, a, b, w[15] + K5,  5);
	RMD160_STEP(F5, b, c, d, e, a, w[13] + K5,  6);

	RMD160_STEP(F5, aa, bb, cc, dd, ee, w[ 5] + KP1,  8);
	RMD160_STEP(F5, ee, aa, bb, cc, dd, w[14] + KP1,  9);
	RMD160_STEP(F5, dd, ee, aa, bb, cc, w[ 7] + KP1,  9);
	RMD160_STEP(F5, cc, dd, ee, aa, bb, w[ 0] + KP1, 11);
	RMD160_STEP(F5, bb, cc, dd, ee, aa, w[ 9] + KP1, 13);
	RMD160_STEP(F5, aa, bb, cc, dd, ee, w[ 2] + KP1, 15);
	RMD160_STEP(F5, ee, aa, bb, cc, dd, w[11] + KP1, 15);
	RMD160_STEP(F5, dd, ee, aa, bb, cc, w[ 4] + KP1,  5);
	RMD160_STEP(F5, cc, dd, ee, aa, bb, w[13] + KP1,  7);
	RMD160_STEP(F5, bb, cc, dd, ee, aa, w[ 6] + KP1,  7);
	RMD160_STEP(F5, aa, bb, cc, dd, ee, w[15] + KP1,  8);
	RMD160_STEP(F5, ee, aa, bb, cc, dd, w[ 8] + KP1, 11);
	RMD160_STEP(F5, dd, ee, aa, bb, cc, w[ 1] + KP1, 14);
	RMD160_STEP(F5, cc, dd, ee, aa, bb, w[10] + KP1, 14);
	RMD160_STEP(F5, bb, cc, dd, ee, aa, w[ 3] + KP1, 12);
	RMD160_STEP(F5, aa, bb, cc, dd, ee, w[12] + KP1,  6);

	RMD160_STEP(F4, ee, aa, bb, cc, dd, w[ 6] + KP2,  9);
	RMD160_STEP(F4, dd, ee, aa, bb, cc, w[11] + KP2, 13);
	RMD160_STEP(F4, cc, dd, ee, aa, bb, w[ 3] + KP2, 15);
	RMD160_STEP(F4, bb, cc, dd, ee, aa, w[ 7] + KP2,  7);
	RMD160_STEP(F4, aa, bb, cc, dd, ee, w[ 0] + KP2, 12);
	RMD160_STEP(F4, ee, aa, bb, cc, dd, w[13] + KP2,  8);
	RMD160_STEP(F4, dd, ee, aa, bb, cc, w[ 5] + KP2,  9);
	RMD160_STEP(F4, cc, dd, ee, aa, bb, w[10] + KP2, 11);
	RMD160_STEP(F4, bb, cc, dd, ee, aa, w[14] + KP2,  7);
	RMD160_STEP(F4, aa, bb, cc, dd, ee, w[15] + KP2,  7);
	RMD160_STEP(F4, ee, aa, bb, cc, dd, w[ 8] + KP2, 12);
	RMD160_STEP(F4, dd, ee, aa, bb, cc, w[12] + KP2,  7);
	RMD160_STEP(F4, cc, dd, ee, aa, bb, w[ 4] + KP2,  6);
	RMD160_STEP(F4, bb, cc, dd, ee, aa, w[ 9] + KP2, 15);
	RMD160_STEP(F4, aa, bb, cc, dd, ee, w[ 1] + KP2, 13);
	RMD160_STEP(F4, ee, aa, bb, cc, dd, w[ 2] + KP2, 11);

	RMD160_STEP(F3, dd, ee, aa, bb, cc, w[15] + KP3,  9);
	RMD160_STEP(F3, cc, dd, ee, aa, bb, w[ 5] + KP3,  7);
	RMD160_STEP(F3, bb, cc, dd, ee, aa, w[ 1] + KP3, 15);
	RMD160_STEP(F3, aa, bb, cc, dd, ee, w[ 3] + KP3, 11);
	RMD160_STEP(F3, ee, aa, bb, cc, dd, w[ 7] + KP3,  8);
	RMD160_STEP(F3, dd, ee, aa, bb, cc, w[14] + KP3,  6);
	RMD160_STEP(F3, cc, dd, ee, aa, bb, w[ 6] + KP3,  6);
	RMD160_STEP(F3, bb, cc, dd, ee, aa, w[ 9] + KP3, 14);
	RMD160_STEP(F3, aa, bb, cc, dd, ee, w[11] + KP3, 12);
	RMD160_STEP(F3, ee, aa, bb, cc, dd, w[ 8] + KP3, 13);
	RMD160_STEP(F3, dd, ee, aa, bb, cc, w[12] + KP3,  5);
	RMD160_STEP(F3, cc, dd, ee, aa, bb, w[ 2] + KP3, 14);
	RMD160_STEP(F3, bb, cc, dd, ee, aa, w[10] + KP3, 13);
	RMD160_STEP(F3, aa, bb, cc, dd, ee, w[ 0] + KP3, 13);
	RMD160_STEP(F3, ee, aa, bb, cc, dd, w[ 4] + KP3,  7);
	RMD160_STEP(F3, dd, ee, aa, bb, cc, w[13] + KP3,  5);

	RMD160_STEP(F2, cc, dd, ee, aa, bb, w[ 8] + KP4, 15);
	RMD160_STEP(F2, bb, cc, dd, ee, aa, w[ 6] + KP4,  5);
	RMD160_STEP(F2, aa, bb, cc, dd, ee, w[ 4] + KP4,  8);
	RMD160_STEP(F2, ee, aa, bb, cc, dd, w[ 1] + KP4, 11);
	RMD160_STEP(F2, dd, ee, aa, bb, cc, w[ 3] + KP4, 14);
	RMD160_STEP(F2, cc, dd, ee, aa, bb, w[11] + KP4, 14);
	RMD160_STEP(F2, bb, cc, dd, ee, aa, w[15] + KP4,  6);
	RMD160_STEP(F2, aa, bb, cc, dd, ee, w[ 0] + KP4, 14);
	RMD160_STEP(F2, ee, aa, bb, cc, dd, w[ 5] + KP4,  6);
	RMD160_STEP(F2, dd, ee, aa, bb, cc, w[12] + KP4,  9);
	RMD160_STEP(F2, cc, dd, ee, aa, bb, w[ 2] + KP4, 12);
	RMD160_STEP(F2, bb, cc, dd, ee, aa, w[13] + KP4,  9);
	RMD160_STEP(F2, aa, bb, cc, dd, ee, w[ 9] + KP4, 12);
	RMD160_STEP(F2, ee, aa, bb, cc, dd, w[ 7] + KP4,  5);
	RMD160_STEP(F2, dd, ee, aa, bb, cc, w[10] + KP4, 15);
	RMD160_STEP(F2, cc, dd, ee, aa, bb, w[14] + KP4,  8);

	RMD160_STEP(F1, bb, cc, dd, ee, aa, w[12],  8);
	RMD160_STEP(F1, aa, bb, cc, dd, ee, w[15],  5);
	RMD160_STEP(F1, ee, aa, bb, cc, dd, w[10], 12);
	RMD160_STEP(F1, dd, ee, aa, bb, cc, w[ 4],  9);
	RMD160_STEP(F1, cc, dd, ee, aa, bb, w[ 1], 12);
	RMD160_STEP(F1, bb, cc, dd, ee, aa, w[ 5],  5);
	RMD160_STEP(F1, aa, bb, cc, dd, ee, w[ 8], 14);
	RMD160_STEP(F1, ee, aa, bb, cc, dd, w[ 7],  6);
	RMD160_STEP(F1, dd, ee, aa, bb, cc, w[ 6],  8);
	RMD160_STEP(F1, cc, dd, ee, aa, bb, w[ 2], 13);
	RMD160_STEP(F1, bb, cc, dd, ee, aa, w[13],  6);
	RMD160_STEP(F1, aa, bb, cc, dd, ee, w[14],  5);
	RMD160_STEP(F1, ee, aa, bb, cc, dd, w[ 0], 15);
	RMD160_STEP(F1, dd, ee, aa, bb, cc, w[ 3], 13);
	RMD160_STEP(F1, cc, dd, ee, aa, bb, w[ 9], 11);
	RMD160_STEP(F1, bb, cc, dd, ee, aa, w[11], 11);

	dd += c + state[1];
	state[1] = state[2] + d + ee;
	state[2] = state[3] + e + aa;
	state[3] = state[4] + a + bb;
	state[4] = state[0] + b + cc;
	state[0] = dd;
}

void
rmd160_update(struct rmd160_ctx *ctx, const void *inputptr, size_t inputlen)
{
	size_t filled, need;
	const uint8_t *input = inputptr;

	if (inputlen == 0)
		return;

	filled = (size_t)((ctx->count >> 3) & (RMD160_BLOCK_SIZE - 1));
	need = RMD160_BLOCK_SIZE - filled;
	ctx->count += (uint64_t)(inputlen << 3);

	/* Input too short to fill a complete block. */
	if (inputlen < need) {
		memcpy(&ctx->buffer[filled], input, inputlen);
		return;
	}

	/* Check if we need to finish the buffer in ctx. */
	if (filled != 0) {
		memcpy(&ctx->buffer[filled], input, need);
		rmd160_transform(ctx->state, ctx->buffer);
		inputlen -= need;
		input += need;
	}

	/* Handle as many blocks as possible. */
	while (inputlen >= RMD160_BLOCK_SIZE) {
		rmd160_transform(ctx->state, input);
		inputlen -= RMD160_BLOCK_SIZE;
		input += RMD160_BLOCK_SIZE;
	}

	/* Save any remaining bytes. */
	if (inputlen != 0)
		memcpy(ctx->buffer, input, inputlen);
}

void
rmd160_final(uint8_t *digest, struct rmd160_ctx *ctx)
{
	size_t padoffset;
	uint32_t i;

	padoffset = (size_t)((ctx->count >> 3) & (RMD160_BLOCK_SIZE - 1));
	ctx->buffer[padoffset++] = 0x80;

	/* Enough room for count. */
	if (padoffset <= 56)
		memset(&ctx->buffer[padoffset], 0, 56 - padoffset);
	else {
		/* Not enough room for count. */
		memset(&ctx->buffer[padoffset], 0, RMD160_BLOCK_SIZE -
				padoffset);
		rmd160_transform(ctx->state, ctx->buffer);
		memset(ctx->buffer, 0, 56);
	}

	/* Append the count and handle the block. */
	buff_put_le64(ctx->buffer + 56, ctx->count);
	rmd160_transform(ctx->state, ctx->buffer);

	for (i = 0; i < 5; ++i)
		buff_put_le32(digest + i * 4, ctx->state[i]);
	fcrypt_memzero(ctx, sizeof(*ctx));
}

