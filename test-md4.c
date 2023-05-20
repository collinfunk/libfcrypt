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
 * Test vectors are from RFC 1320.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "md4.h"

struct md4_testcase {
	const char *message;
	const char *digest;
};

static const struct md4_testcase testcases[] = {
	{
		"",
		"\x31\xd6\xcf\xe0\xd1\x6a\xe9\x31\xb7"
			"\x3c\x59\xd7\xe0\xc0\x89\xc0"
	},
	{
		"a",
		"\xbd\xe5\x2c\xb3\x1d\xe3\x3e\x46\x24"
			"\x5e\x05\xfb\xdb\xd6\xfb\x24"
	},
	{
		"abc",
		"\xa4\x48\x01\x7a\xaf\x21\xd8\x52\x5f"
			"\xc1\x0a\xe8\x7a\xa6\x72\x9d"
	},
	{
		"message digest",
		"\xd9\x13\x0a\x81\x64\x54\x9f\xe8\x18"
			"\x87\x48\x06\xe1\xc7\x01\x4b"
	},
	{
		"abcdefghijklmnopqrstuvwxyz",
		"\xd7\x9e\x1c\x30\x8a\xa5\xbb\xcd\xee"
			"\xa8\xed\x63\xdf\x41\x2d\xa9"
	},
	{
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
			"klmnopqrstuvwxyz0123456789",
		"\x04\x3f\x85\x82\xf2\x41\xdb\x35\x1c"
			"\xe6\x27\xe1\x53\xe7\xf0\xe4"
	},
	{
		"1234567890123456789012345678901234567"
			"89012345678901234567890123456"
			"78901234567890",
		"\xe3\x3b\x4d\xdc\x9c\x38\xf2\x19\x9c"
			"\x3e\x7b\x16\x4f\xcc\x05\x36"
	}

};

static bool run_md4_testcase(const struct md4_testcase *);

int
main(void)
{
	uint32_t i;
	int rv;
	const struct md4_testcase *curr;

	rv = 0;
	for (i = 0; i < (sizeof(testcases) / sizeof(testcases[0])); ++i) {
		curr = &testcases[i];
		if (!run_md4_testcase(curr)) {
			fprintf(stderr, "MD4 test %u failed.\n", i);
			rv = 1;
		}
	}

	return rv;
}

static bool
run_md4_testcase(const struct md4_testcase *test)
{
	struct md4_ctx ctx;
	uint32_t i;
	uint8_t digest[MD4_DIGEST_SIZE];

	md4_init(&ctx);
	md4_update(&ctx, test->message, strlen(test->message));
	md4_final(digest, &ctx);

	for (i = 0; i < MD4_DIGEST_SIZE; ++i)
		printf("%02x", digest[i]);
	printf("\n");

	return memcmp(digest, test->digest, MD4_DIGEST_SIZE) == 0;
}

