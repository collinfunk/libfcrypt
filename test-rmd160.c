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
 * Test vectors found on Antoon Bosselaers's website:
 * https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rmd160.h"

struct rmd160_testcase
{
  const char *message;
  const char *hash;
};

static const struct rmd160_testcase testcases[]
    = { { "", "\x9c\x11\x85\xa5\xc5\xe9\xfc\x54\x61\x28\x08"
              "\x97\x7e\xe8\xf5\x48\xb2\x25\x8d\x31" },
        { "a", "\x0b\xdc\x9d\x2d\x25\x6b\x3e\xe9\xda\xae\x34"
               "\x7b\xe6\xf4\xdc\x83\x5a\x46\x7f\xfe" },
        { "abc", "\x8e\xb2\x08\xf7\xe0\x5d\x98\x7a\x9b\x04\x4a"
                 "\x8e\x98\xc6\xb0\x87\xf1\x5a\x0b\xfc" },
        { "message digest", "\x5d\x06\x89\xef\x49\xd2\xfa\xe5\x72\xb8\x81"
                            "\xb1\x23\xa8\x5f\xfa\x21\x59\x5f\x36" },
        { "abcdefghijklmnopqrstuvwxyz",
          "\xf7\x1c\x27\x10\x9c\x69\x2c\x1b\x56\xbb\xdc"
          "\xeb\x5b\x9d\x28\x65\xb3\x70\x8d\xbc" },
        { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
          "\x12\xa0\x53\x38\x4a\x9c\x0c\x88\xe4\x05\xa0"
          "\x6c\x27\xdc\xf4\x9a\xda\x62\xeb\x2b" },
        { "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn"
          "opqrstuvwxyz0123456789",
          "\xb0\xe2\x0b\x6e\x31\x16\x64\x02\x86\xed\x3a"
          "\x87\xa5\x71\x30\x79\xb2\x1f\x51\x89" },
        { "1234567890123456789012345678901234567890"
          "1234567890123456789012345678901234567890",
          "\x9b\x75\x2e\x45\x57\x3d\x4b\x39\xf4\xdb\xd3"
          "\x32\x3c\xab\x82\xbf\x63\x32\x6b\xfb" } };

static bool run_rmd160_testcase (const struct rmd160_testcase *);
static bool run_rmd160_test1mb (void);

int
main (void)
{
  size_t i;
  int rv;
  const struct rmd160_testcase *curr;

  rv = 0;
  for (i = 0; i < (sizeof (testcases) / sizeof (testcases[0])); ++i)
    {
      curr = &testcases[i];
      if (!run_rmd160_testcase (curr))
        {
          fprintf (stderr, "RMD-160 test #%zu failed.\n", i);
          rv = 1;
        }
    }

  if (!run_rmd160_test1mb ())
    {
      fprintf (stderr, "RMD-160 1MB test failed.\n");
      rv = 1;
    }

  return rv;
}

static bool
run_rmd160_testcase (const struct rmd160_testcase *test)
{
  struct rmd160_ctx ctx;
  uint32_t i;
  uint8_t digest[RMD160_DIGEST_SIZE];

  rmd160_init (&ctx);
  rmd160_update (&ctx, test->message, strlen (test->message));
  rmd160_final (digest, &ctx);

  for (i = 0; i < RMD160_DIGEST_SIZE; ++i)
    printf ("%02x", digest[i]);
  printf ("\n");

  return memcmp (digest, test->hash, RMD160_DIGEST_SIZE) == 0;
}

static bool
run_rmd160_test1mb (void)
{
  struct rmd160_ctx ctx;
  uint32_t i;
  uint8_t digest[RMD160_DIGEST_SIZE];
  static const char expected[RMD160_DIGEST_SIZE]
      = "\x52\x78\x32\x43\xc1\x69\x7b\xdb\xe1\x6d"
        "\x37\xf9\x7f\x68\xf0\x83\x25\xdc\x15\x28";

  uint8_t *ptr;

  ptr = malloc (1000000);
  if (ptr == NULL)
    return false;

  memset (ptr, 'a', 1000000);

  rmd160_init (&ctx);
  rmd160_update (&ctx, ptr, 1000000);
  rmd160_final (digest, &ctx);

  for (i = 0; i < RMD160_DIGEST_SIZE; ++i)
    printf ("%02x", digest[i]);
  printf ("\n");

  free (ptr);
  return memcmp (digest, expected, RMD160_DIGEST_SIZE) == 0;
}
