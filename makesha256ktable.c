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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <math.h>

#include "bswap.h"

/* First 64 prime numbers. */
static uint32_t primes[64] = {
	2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
	31, 37, 41, 43, 47, 53, 59, 61, 67,
	71, 73, 79, 83, 89, 97, 101, 103,
	107, 109, 113, 127, 131, 137, 139,
	149, 151, 157, 163, 167, 173, 179,
	181, 191, 193, 197, 199, 211, 223,
	227, 229, 233, 239, 241, 251, 257,
	263, 269, 271, 277, 281, 283, 293,
	307, 311,
};

static uint32_t calculate_kval(uint32_t);

int
main(void)
{
	int i;
	uint32_t k;

	printf("static const uint32_t sha256_ktable[64] = {\n");
	for (i = 1; i <= 64; ++i) {
		k = calculate_kval(primes[i - 1]);
		switch (i & 3) {
			case 0:
				printf("0x%08x,\n", k);
				break;
			case 1:
				printf("\t0x%08x, ", k);
				break;
			default:
				printf("0x%08x, ", k);
				break;
		}
	}
	printf("};\n");

	return 0;
}

static uint32_t
calculate_kval(uint32_t val)
{
	double cr;
	uint32_t retv;

	/* Cube root. */
	cr = cbrt((double)val);

	/* Get the fractional part. */
	retv = (uint32_t)((cr - floor(cr)) * 0xffffffff);

	return retv;
}

