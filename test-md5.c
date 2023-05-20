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
 * Test vectors are from RFC 1321.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "md5.h"

struct md5_testcase {
	const char *message;
	const char *digest;
};

static const struct md5_testcase testcases[] = {
	{
		"",
		"\xd4\x1d\x8c\xd9\x8f\x00\xb2\x04\xe9"
			"\x80\x09\x98\xec\xf8\x42\x7e"
	},
	{
		"a",
		"\x0c\xc1\x75\xb9\xc0\xf1\xb6\xa8\x31"
			"\xc3\x99\xe2\x69\x77\x26\x61"
	},
	{
		"abc",
		"\x90\x01\x50\x98\x3c\xd2\x4f\xb0\xd6"
			"\x96\x3f\x7d\x28\xe1\x7f\x72"
	},
	{
		"message digest",
		"\xf9\x6b\x69\x7d\x7c\xb7\x93\x8d\x52"
			"\x5a\x2f\x31\xaa\xf1\x61\xd0"
	},
	{
		"abcdefghijklmnopqrstuvwxyz",
		"\xc3\xfc\xd3\xd7\x61\x92\xe4\x00\x7d"
			"\xfb\x49\x6c\xca\x67\xe1\x3b"
	},
	{
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
		"\xd1\x74\xab\x98\xd2\x77\xd9\xf5\xa5"
			"\x61\x1c\x2c\x9f\x41\x9d\x9f"
	},
	{
		"1234567890123456789012345678901234567"
			"89012345678901234567890123456"
			"78901234567890",
		"\x57\xed\xf4\xa2\x2b\xe3\xc9\x55\xac"
			"\x49\xda\x2e\x21\x07\xb6\x7a"
	}

};

static bool run_md5_testcase(const struct md5_testcase *);

int
main(void)
{
	uint32_t i;
	int rv;
	const struct md5_testcase *curr;

	rv = 0;
	for (i = 0; i < (sizeof(testcases) / sizeof(testcases[0])); ++i) {
		curr = &testcases[i];
		if (!run_md5_testcase(curr)) {
			fprintf(stderr, "MD5 test %u failed.\n", i);
			rv = 1;
		}
	}

	return rv;
}

static bool
run_md5_testcase(const struct md5_testcase *test)
{
	struct md5_ctx ctx;
	uint32_t i;
	uint8_t digest[MD5_DIGEST_SIZE];

	md5_init(&ctx);
	md5_update(&ctx, test->message, strlen(test->message));
	md5_final(digest, &ctx);

	for (i = 0; i < MD5_DIGEST_SIZE; ++i)
		printf("%02x", digest[i]);
	printf("\n");

	return memcmp(digest, test->digest, MD5_DIGEST_SIZE) == 0;
}

