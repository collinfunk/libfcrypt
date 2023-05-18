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
 * Test vectors are from RFC 3174.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sha1.h"

struct sha1_testcase {
	const char *message;
	const char *hash;
};

static const struct sha1_testcase testcases[] = {
	{
		"abc",
		"\xa9\x99\x3e\x36\x47\x06\x81\x6a\xba\x3e"
			"\x25\x71\x78\x50\xc2\x6c\x9c\xd0\xd8\x9d"
	},
	{
		"abcdbcdecdefdefgefghfghighijhi",
		"\xf9\x53\x7c\x23\x89\x3d\x20\x14\xf3\x65"
			"\xad\xf8\xff\xe3\x3b\x8e\xb0\x29\x7e\xd1"
	},
	{
		"jkijkljklmklmnlmnomnopnopq",
		"\x34\x6f\xb5\x28\xa2\x4b\x48\xf5\x63\xcb\x06\x14\x70\xbc\xfd\x23\x74\x04\x27\xad"
	},
	{
		"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		"\x84\x98\x3e\x44\x1c\x3b\xd2\x6e\xba\xae\x4a\xa1\xf9\x51\x29\xe5\xe5\x46\x70\xf1"
	},
	{
		"a",
		"\x86\xf7\xe4\x37\xfa\xa5\xa7\xfc\xe1\x5d\x1d\xdc\xb9\xea\xea\xea\x37\x76\x67\xb8"
	},
	{
		"01234567012345670123456701234567",
		"\xc7\x29\xc8\x99\x6e\xe0\xa6\xf7\x4f\x4f\x32\x48\xe8\x95\x7e\xdf\x70\x4f\xb6\x24"
	},
	{
		"01234567012345670123456701234567"
			"01234567012345670123456701234567",
		"\xe0\xc0\x94\xe8\x67\xef\x46\xc3\x50\xef\x54\xa7\xf5\x9d\xd6\x0b\xed\x92\xae\x83"
	}
};

static void hexdump(const uint8_t *, size_t);
static bool run_sha1_testcase(const struct sha1_testcase *);

int
main(void)
{
	uint32_t i;
	int rv;
	const struct sha1_testcase *curr;

	rv = 0;
	for (i = 0; i < (sizeof(testcases) / sizeof(testcases[0])); ++i) {
		curr = &testcases[i];
		if (!run_sha1_testcase(curr)) {
			printf("SHA-1 test %d failed.\n", i);
			rv = 1;
		}
	}

	return rv;
}

static void
hexdump(const uint8_t *data, size_t len)
{
	size_t i;
	for (i = 0; i < len; ++i)
		printf("%02x", data[i]);
	printf("\n");
}

static bool
run_sha1_testcase(const struct sha1_testcase *test)
{
	struct sha1_ctx ctx;
	uint8_t digest[SHA1_DIGEST_SIZE];

	sha1_init(&ctx);
	sha1_update(&ctx, test->message, strlen(test->message));
	sha1_final(digest, &ctx);

	hexdump(digest, SHA1_DIGEST_SIZE);

	if (memcmp(digest, test->hash, SHA1_DIGEST_SIZE) != 0)
		return false;

	return true;
}

