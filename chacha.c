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

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "chacha.h"
#include "bswap.h"
#include "circularshift.h"

/*
 * Input is a 4 x 4 matrix, indexes shown below:
 *	 0  1  2  3
 *	 4  5  6  7
 *	 8  9 10 11
 *	12 13 14 15
 * Starting state is shown below:
 *	C C C C
 *	K K K K
 *	K K K K
 *	B B N N
 * Where C is a constant, K is the key, B is the block counter, and N is
 * the nonce.
 */

#define CHACHA_QUARTERROUND(a, b, c, d) do {     \
	(a) += (b);                              \
	(d) ^= (a);                              \
	(d) = rotl32((d), 16);                   \
	(c) += (d);                              \
	(b) ^= (c);                              \
	(b) = rotl32((b), 12);                   \
	(a) += (b);                              \
	(d) ^= (a);                              \
	(d) = rotl32((d), 8);                    \
	(c) += (d);                              \
	(b) ^= (c);                              \
	(b) = rotl32((b), 7);                    \
} while (0)

void
chacha128_set_key(struct chacha_ctx *ctx, const uint8_t *key)
{
	/* "expand 16-byte k" */
	ctx->input[ 0] = 0x61707865;
	ctx->input[ 1] = 0x3120646e;
	ctx->input[ 2] = 0x79622d36;
	ctx->input[ 3] = 0x6b206574;
	ctx->input[ 4] = buff_get_le32(key);
	ctx->input[ 5] = buff_get_le32(key + 4);
	ctx->input[ 6] = buff_get_le32(key + 8);
	ctx->input[ 7] = buff_get_le32(key + 12);
	ctx->input[ 8] = ctx->input[4];
	ctx->input[ 9] = ctx->input[5];
	ctx->input[10] = ctx->input[6];
	ctx->input[11] = ctx->input[7];
}

void
chacha256_set_key(struct chacha_ctx *ctx, const uint8_t *key)
{
	/* "expand 32-byte k" */
	ctx->input[ 0] = 0x61707865;
	ctx->input[ 1] = 0x3320646e;
	ctx->input[ 2] = 0x79622d32;
	ctx->input[ 3] = 0x6b206574;
	ctx->input[ 4] = buff_get_le32(key);
	ctx->input[ 5] = buff_get_le32(key + 4);
	ctx->input[ 6] = buff_get_le32(key + 8);
	ctx->input[ 7] = buff_get_le32(key + 12);
	ctx->input[ 8] = buff_get_le32(key + 16);
	ctx->input[ 9] = buff_get_le32(key + 20);
	ctx->input[10] = buff_get_le32(key + 24);
	ctx->input[11] = buff_get_le32(key + 28);
}

void
chacha_set_key(struct chacha_ctx *ctx, const uint8_t *key, size_t keybits)
{
	if (keybits == 256)
		chacha256_set_key(ctx, key);
	else
		chacha128_set_key(ctx, key);
}

void
chacha_set_iv(struct chacha_ctx *ctx, const uint8_t *iv,
		const uint8_t *counter)
{
	if (counter == NULL)
		ctx->input[12] = ctx->input[13] = 0;
	else {
		ctx->input[12] = buff_get_le32(counter);
		ctx->input[13] = buff_get_le32(counter + 4);
	}

	ctx->input[14] = buff_get_le32(iv);
	ctx->input[15] = buff_get_le32(iv + 4);
}

void
chacha_encrypt_bytes(struct chacha_ctx *ctx, const uint8_t *src,
		uint8_t *dest, size_t len)
{
	uint32_t x0, x1,  x2,  x3,  x4,  x5,  x6,  x7;
	uint32_t x8, x9, x10, x11, x12, x13, x14, x15;
	uint32_t y0, y1,  y2,  y3,  y4,  y5,  y6,  y7;
	uint32_t y8, y9, y10, y11, y12, y13, y14, y15;
	uint32_t i;
	uint8_t buffer[64];
	uint8_t *p;

	/* Quit if no input. */
	if (len == 0)
		return;

	y0  = ctx->input[ 0];
	y1  = ctx->input[ 1];
	y2  = ctx->input[ 2];
	y3  = ctx->input[ 3];
	y4  = ctx->input[ 4];
	y5  = ctx->input[ 5];
	y6  = ctx->input[ 6];
	y7  = ctx->input[ 7];
	y8  = ctx->input[ 8];
	y9  = ctx->input[ 9];
	y10 = ctx->input[10];
	y11 = ctx->input[11];
	y12 = ctx->input[12];
	y13 = ctx->input[13];
	y14 = ctx->input[14];
	y15 = ctx->input[15];

	/* -Wmaybe-uninitialized */
	p = NULL;

	for (;; len -= 64, src += 64, dest += 64) {
		if (len < 64) {
			memcpy(buffer, src, len);
			src = buffer;
			p = dest;
			dest = buffer;
		}
		x0  = y0;
		x1  = y1;
		x2  = y2;
		x3  = y3;
		x4  = y4;
		x5  = y5;
		x6  = y6;
		x7  = y7;
		x8  = y8;
		x9  = y9;
		x10 = y10;
		x11 = y11;
		x12 = y12;
		x13 = y13;
		x14 = y14;
		x15 = y15;

		for (i = 0; i < 20; i += 2) {
			CHACHA_QUARTERROUND(x0, x4,  x8, x12);
			CHACHA_QUARTERROUND(x1, x5,  x9, x13);
			CHACHA_QUARTERROUND(x2, x6, x10, x14);
			CHACHA_QUARTERROUND(x3, x7, x11, x15);
			CHACHA_QUARTERROUND(x0, x5, x10, x15);
			CHACHA_QUARTERROUND(x1, x6, x11, x12);
			CHACHA_QUARTERROUND(x2, x7,  x8, x13);
			CHACHA_QUARTERROUND(x3, x4,  x9, x14);
		}

		x0  += y0;
		x1  += y1;
		x2  += y2;
		x3  += y3;
		x4  += y4;
		x5  += y5;
		x6  += y6;
		x7  += y7;
		x8  += y8;
		x9  += y9;
		x10 += y10;
		x11 += y11;
		x12 += y12;
		x13 += y13;
		x14 += y14;
		x15 += y15;

		x0  ^= buff_get_le32(src);
		x1  ^= buff_get_le32(src +  4);
		x2  ^= buff_get_le32(src +  8);
		x3  ^= buff_get_le32(src + 12);
		x4  ^= buff_get_le32(src + 16);
		x5  ^= buff_get_le32(src + 20);
		x6  ^= buff_get_le32(src + 24);
		x7  ^= buff_get_le32(src + 28);
		x8  ^= buff_get_le32(src + 32);
		x9  ^= buff_get_le32(src + 36);
		x10 ^= buff_get_le32(src + 40);
		x11 ^= buff_get_le32(src + 44);
		x12 ^= buff_get_le32(src + 48);
		x13 ^= buff_get_le32(src + 52);
		x14 ^= buff_get_le32(src + 56);
		x15 ^= buff_get_le32(src + 60);

		/* Increment counter. */
		if (++y12 == 0)
			y13++;

		buff_put_le32(dest,       x0);
		buff_put_le32(dest +  4,  x1);
		buff_put_le32(dest +  8,  x2);
		buff_put_le32(dest + 12,  x3);
		buff_put_le32(dest + 16,  x4);
		buff_put_le32(dest + 20,  x5);
		buff_put_le32(dest + 24,  x6);
		buff_put_le32(dest + 28,  x7);
		buff_put_le32(dest + 32,  x8);
		buff_put_le32(dest + 36,  x9);
		buff_put_le32(dest + 40, x10);
		buff_put_le32(dest + 44, x11);
		buff_put_le32(dest + 48, x12);
		buff_put_le32(dest + 52, x13);
		buff_put_le32(dest + 56, x14);
		buff_put_le32(dest + 60, x15);

		if (len <= 64) {
			if (len < 64)
				memcpy(p, src, len);
			ctx->input[12] = y12;
			ctx->input[13] = y13;
			return;
		}
	}
}

