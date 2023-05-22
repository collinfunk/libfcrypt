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
#include <stdio.h>
#include <stdint.h>

/* Table to compute. */
static uint32_t crc32_table[256];

static void build_crc32_table(void);
static void print_cformat_crc32_table(void);

int
main(void)
{
	build_crc32_table();
	print_cformat_crc32_table();
	return 0;
}

/*
 * Computes the lookup table for the CRC-32 with the polynomial representation
 * of: x^32 + x^26 + x^23 + x^22 + x^16 + x^12 + x^11 + x^10 + x^8 + ^x7 +
 *	x^5 + x^4 + x^2 + x + 1
 * Hex representation:         0x04c11db7
 * Reverse hex representation: 0xedb88320
 */
static void
build_crc32_table(void)
{
	uint32_t i, j, curr;

	for (i = 0; i < 256; ++i) {
		curr = i;
		for (j = 0; j < 8; ++j) {
			if ((curr & 1) != 0)
				curr = 0xedb88320 ^ (curr >> 1);
			else
				curr = curr >> 1;
		}
		crc32_table[i] = curr;
	}
}

static void
print_cformat_crc32_table(void)
{
	uint32_t i, val;

	printf("static const uint32_t crc32_table[256] = {\n");
	for (i = 1; i <= 256; ++i) {
		val = crc32_table[i - 1];
				switch (i & 3) {
			case 0:
				printf("0x%08x,\n", val);
				break;
			case 1:
				printf("\t0x%08x, ", val);
				break;
			default:
				printf("0x%08x, ", val);
		}
	}
	printf("};\n");
}

