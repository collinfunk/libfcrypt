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
 * Test vectors are from Ross Anderson's implementation. The source can be
 * found at his site here: https://www.cl.cam.ac.uk/~rja14/
 * His site also contains a link to his paper with Eli Biham
 * "Tiger – A Fast New Hash Function."
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tiger.h"

struct tiger_testcase {
	const char *message;
	const char *hash;
};

static const struct tiger_testcase testcases[] = {
	{
		"",
		"\x32\x93\xac\x63\x0c\x13\xf0\x24\x5f\x92\xbb\xb1"
			"\x76\x6e\x16\x16\x7a\x4e\x58\x49\x2d\xde\x73\xf3"
	},
	{
		"abc",
		"\x2a\xab\x14\x84\xe8\xc1\x58\xf2\xbf\xb8\xc5\xff"
			"\x41\xb5\x7a\x52\x51\x29\x13\x1c\x95\x7b\x5f\x93"
	},
	{
		"Tiger",
		"\xdd\x00\x23\x07\x99\xf5\x00\x9f\xec\x6d\xeb\xc8"
			"\x38\xbb\x6a\x27\xdf\x2b\x9d\x6f\x11\x0c\x79\x37"
	},
	{
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklm"
			"nopqrstuvwxyz0123456789+-",
		"\xf7\x1c\x85\x83\x90\x2a\xfb\x87\x9e\xdf\xe6\x10"
			"\xf8\x2c\x0d\x47\x86\xa3\xa5\x34\x50\x44\x86\xb5"
	},
	{
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ=abcdefghijkl"
			"mnopqrstuvwxyz+0123456789",
		"\x48\xce\xeb\x63\x08\xb8\x7d\x46\xe9\x5d\x65\x61\x12\xcd"
			"\xf1\x8d\x97\x91\x5f\x97\x65\x65\x89\x57"
	},
	{
		"Tiger - A Fast New Hash Function, by Ross Anderson "
			"and Eli Biham, proceedings of Fast Software "
			"Encryption 3, Cambridge.",
		"\xce\x55\xa6\xaf\xd5\x91\xf5\xeb\xac\x54\x7f\xf8\x4f\x89"
			"\x22\x7f\x93\x31\xda\xb0\xb6\x11\xc8\x89",
	},
	{
		"Tiger - A Fast New Hash Function, by Ross Anderson "
			"and Eli Biham, proceedings of Fast Software "
			"Encryption 3, Cambridge, 1996.",
		"\x63\x1a\xbd\xd1\x03\xeb\x9a\x3d\x24\x5b\x6d\xfd\x4d"
			"\x77\xb2\x57\xfc\x74\x39\x50\x1d\x15\x68\xdd"
	},
	{
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
			"0123456789+-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg"
			"hijklmnopqrstuvwxyz0123456789+-",
		"\xc5\x40\x34\xe5\xb4\x3e\xb8\x00\x58\x48\xa7\xe0\xae"
			"\x6a\xac\x76\xe4\xff\x59\x0a\xe7\x15\xfd\x25"
	}
};

static bool run_tiger_testcase(const struct tiger_testcase *);
static bool run_tiger_test64k(void);

int
main(void)
{
	uint32_t i;
	const struct tiger_testcase *curr;
	int rv;

	rv = 0;
	for (i = 0; i < (sizeof(testcases) / sizeof(testcases[0])); ++i) {
		curr = &testcases[i];

		if (!run_tiger_testcase(curr)) {
			fprintf(stderr, "TIGER test %u failed.\n", i);
			rv = 1;
		}
	}

	if (!run_tiger_test64k()) {
		fprintf(stderr, "TIGER 64K test failed.\n");
		rv = 1;
	}

	return rv;
}

static bool
run_tiger_testcase(const struct tiger_testcase *test)
{
	struct tiger_ctx ctx;
	uint8_t digest[TIGER192_DIGEST_SIZE];

	tiger1_init(&ctx);
	tiger_update(&ctx, test->message, strlen(test->message));
	tiger192_final(digest, &ctx);

	for (int i = 0; i < TIGER192_DIGEST_SIZE; ++i)
		printf("%02x", digest[i]);
	printf("\n");

	return memcmp(digest, test->hash, TIGER192_DIGEST_SIZE) == 0;
}

	static bool
run_tiger_test64k(void)
{
	struct tiger_ctx ctx;
	uint32_t i;
	uint8_t *buffer;
	uint8_t digest[TIGER192_DIGEST_SIZE];
	const char expect[TIGER192_DIGEST_SIZE] =
		"\xfd\xf4\xf5\xb3\x51\x39\xf4\x8e\x71\x0e\x42\x1b\xe5"
		"\xaf\x41\x1d\xe1\xa8\xaa\xc3\x33\xf2\x62\x04";

	buffer = calloc(1, 0x10000);
	if (buffer == NULL)
		return false;

	for (i = 0; i < 0x10000; ++i)
		buffer[i] = i & 0xff;

	tiger1_init(&ctx);
	tiger_update(&ctx, buffer, 0x10000);
	tiger192_final(digest, &ctx);

	for (i = 0; i < TIGER192_DIGEST_SIZE; ++i)
		printf("%02x", digest[i]);
	printf("\n");

	if (memcmp(digest, expect, TIGER192_DIGEST_SIZE) != 0)
		goto fail;

	free(buffer);
	return true;
fail:
	free(buffer);
	return false;
}

