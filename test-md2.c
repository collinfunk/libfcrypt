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
 * Test vectors are from RFC 1319.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "md2.h"

struct md2_testcase
{
  const char *message;
  const char *digest;
};

static const struct md2_testcase testcases[]
    = { { "", "\x83\x50\xe5\xa3\xe2\x4c\x15\x3d"
              "\xf2\x27\x5c\x9f\x80\x69\x27\x73" },
        { "a", "\x32\xec\x01\xec\x4a\x6d\xac\x72"
               "\xc0\xab\x96\xfb\x34\xc0\xb5\xd1" },
        { "abc", "\xda\x85\x3b\x0d\x3f\x88\xd9\x9b"
                 "\x30\x28\x3a\x69\xe6\xde\xd6\xbb" },
        { "message digest", "\xab\x4f\x49\x6b\xfb\x2a\x53\x0b"
                            "\x21\x9f\xf3\x30\x31\xfe\x06\xb0" },
        { "abcdefghijklmnopqrstuvwxyz", "\x4e\x8d\xdf\xf3\x65\x02\x92\xab"
                                        "\x5a\x41\x08\xc3\xaa\x47\x94\x0b" },
        { "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"
          "ghijklmnopqrstuvwxyz0123456789",
          "\xda\x33\xde\xf2\xa4\x2d\xf1\x39"
          "\x75\x35\x28\x46\xc3\x03\x38\xcd" },
        { "1234567890123456789012345678901234567"
          "89012345678901234567890123456"
          "78901234567890",
          "\xd5\x97\x6f\x79\xd8\x3d\x3a\x0d\xc9"
          "\x80\x6c\x3c\x66\xf3\xef\xd8" }

      };

static bool run_md2_testcase (const struct md2_testcase *);

int
main (void)
{
  uint32_t i;
  int rv;
  const struct md2_testcase *curr;

  rv = 0;
  for (i = 0; i < (sizeof (testcases) / sizeof (testcases[0])); ++i)
    {
      curr = &testcases[i];
      if (!run_md2_testcase (curr))
        {
          fprintf (stderr, "MD2 test %u failed.\n", i);
          rv = 1;
        }
    }

  return rv;
}

static bool
run_md2_testcase (const struct md2_testcase *test)
{
  struct md2_ctx ctx;
  uint32_t i;
  uint8_t digest[MD2_DIGEST_SIZE];

  md2_init (&ctx);
  md2_update (&ctx, test->message, strlen (test->message));
  md2_final (digest, &ctx);

  for (i = 0; i < MD2_DIGEST_SIZE; ++i)
    printf ("%02x", digest[i]);
  printf ("\n");

  return memcmp (digest, test->digest, MD2_DIGEST_SIZE) == 0;
}
