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

#include "rmd128.h"

struct rmd128_testcase
{
  const char *message;
  const char *hash;
};

static const struct rmd128_testcase testcases[]
    = { { "",
          "\xcd\xf2\x62\x13\xa1\x50\xdc\x3e\xcb\x61\x0f\x18\xf6\xb3\x8b\x46" },
        { "a", "\x86\xbe\x7a\xfa\x33\x9d\x0f\xc7\xcf"
               "\xc7\x85\xe7\x2f\x57\x8d\x33" },
        { "abc", "\xc1\x4a\x12\x19\x9c\x66\xe4\xba\x84"
                 "\x63\x6b\x0f\x69\x14\x4c\x77" },
        { "message digest", "\x9e\x32\x7b\x3d\x6e\x52\x30\x62\xaf"
                            "\xc1\x13\x2d\x7d\xf9\xd1\xb8" },
        { "abcdefghijklmnopqrstuvwxyz", "\xfd\x2a\xa6\x07\xf7\x1d\xc8\xf5\x10"
                                        "\x71\x49\x22\xb3\x71\x83\x4e" },
        { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
          "\xa1\xaa\x06\x89\xd0\xfa\xfa\x2d\xdc"
          "\x22\xe8\x8b\x49\x13\x3a\x06" },
        { "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn"
          "opqrstuvwxyz0123456789",
          "\xd1\xe9\x59\xeb\x17\x9c\x91\x1f\xae"
          "\xa4\x62\x4c\x60\xc5\xc7\x02" },
        { "1234567890123456789012345678901234567890"
          "1234567890123456789012345678901234567890",
          "\x3f\x45\xef\x19\x47\x32\xc2\xdb\xb2"
          "\xc4\xa2\xc7\x69\x79\x5f\xa3" } };

static bool run_rmd128_testcase (const struct rmd128_testcase *);
static bool run_rmd128_test1mb (void);

int
main (void)
{
  size_t i;
  int rv;
  const struct rmd128_testcase *curr;

  rv = 0;
  for (i = 0; i < (sizeof (testcases) / sizeof (testcases[0])); ++i)
    {
      curr = &testcases[i];
      if (!run_rmd128_testcase (curr))
        {
          fprintf (stderr, "RMD-128 test #%zu failed.\n", i);
          rv = 1;
        }
    }

  if (!run_rmd128_test1mb ())
    {
      fprintf (stderr, "RMD-128 1MB test failed.\n");
      rv = 1;
    }

  return rv;
}

static bool
run_rmd128_testcase (const struct rmd128_testcase *test)
{
  struct rmd128_ctx ctx;
  uint32_t i;
  uint8_t digest[RMD128_DIGEST_SIZE];

  rmd128_init (&ctx);
  rmd128_update (&ctx, test->message, strlen (test->message));
  rmd128_final (digest, &ctx);

  for (i = 0; i < RMD128_DIGEST_SIZE; ++i)
    printf ("%02x", digest[i]);
  printf ("\n");

  return memcmp (digest, test->hash, RMD128_DIGEST_SIZE) == 0;
}

static bool
run_rmd128_test1mb (void)
{
  struct rmd128_ctx ctx;
  uint32_t i;
  uint8_t digest[RMD128_DIGEST_SIZE];
  static const char expected[RMD128_DIGEST_SIZE]
      = "\x4a\x7f\x57\x23\xf9\x54\xeb\xa1"
        "\x21\x6c\x9d\x8f\x63\x20\x43\x1f";

  uint8_t *ptr;

  ptr = malloc (1000000);
  if (ptr == NULL)
    return false;

  memset (ptr, 'a', 1000000);

  rmd128_init (&ctx);
  rmd128_update (&ctx, ptr, 1000000);
  rmd128_final (digest, &ctx);

  for (i = 0; i < RMD128_DIGEST_SIZE; ++i)
    printf ("%02x", digest[i]);
  printf ("\n");

  free (ptr);
  return memcmp (digest, expected, RMD128_DIGEST_SIZE) == 0;
}
