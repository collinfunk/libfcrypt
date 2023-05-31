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

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "has160.h"

struct has160_testcase
{
  const char *message;
  const char *hash;
};

static const struct has160_testcase testcases[] = {
  { "", "\x30\x79\x64\xef\x34\x15\x1d\x37\xc8\x04\x7a\xde\xc7\xab\x50\xf4\xff"
        "\x89\x76\x2d" },
  { "a",
    "\x48\x72\xbc\xbc\x4c\xd0\xf0\xa9\xdc\x7c\x2f\x70\x45\xe5\xb4\x3b\x6c\x83"
    "\x0d\xb8" },
  { "abc",
    "\x97\x5e\x81\x04\x88\xcf\x2a\x3d\x49\x83\x84\x78\x12\x4a\xfc\xe4\xb1\xc7"
    "\x88\x04" },
  { "message digest",
    "\x23\x38\xdb\xc8\x63\x8d\x31\x22\x5f\x73\x08\x62\x46\xba\x52\x9f\x96\x71"
    "\x0b\xc6" },
  { "abcdefghijklmnopqrstuvwxyz",
    "\x59\x61\x85\xc9\xab\x67\x03\xd0\xd0\xdb\xb9\x87\x02\xbc\x0f\x57\x29"
    "\xcd\x1d\x3c" },
  { "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    "\xcb\x5d\x7e\xfb\xca\x2f\x02\xe0\xfb\x71\x67\xca\xbb\x12\x3a\xf5\x79"
    "\x57\x64\xe5" },
  { "1234567890123456789012345678901234567"
    "89012345678901234567890123456"
    "78901234567890",
    "\x07\xf0\x5c\x8c\x07\x73\xc5\x5c\xa3\xa5\xa6\x95\xce\x6a\xca\x4c\x43"
    "\x89\x11\xb5" },
};

static bool run_has160_testcase (const struct has160_testcase *);
static bool run_has160_1mb (void);

int
main (void)
{
  const struct has160_testcase *curr;
  uint32_t i;
  int rv;

  curr = testcases;
  for (i = rv = 0; i < sizeof (testcases) / sizeof (testcases[0]); ++i, ++curr)
    {
      if (!run_has160_testcase (curr))
        {
          fprintf (stderr, "HAS-160 test %u failed.\n", i);
          rv = 1;
        }
    }

  if (!run_has160_1mb ())
    {
      fprintf (stderr, "HAS-160 1 mb test failed.\n");
      rv = 1;
    }

  return rv;
}

static bool
run_has160_testcase (const struct has160_testcase *test)
{
  struct has160_ctx ctx;
  size_t i;
  uint8_t digest[HAS160_DIGEST_SIZE];

  has160_init (&ctx);
  has160_update (&ctx, test->message, strlen (test->message));
  has160_final (digest, &ctx);

  for (i = 0; i < HAS160_DIGEST_SIZE; ++i)
    printf ("%02x", digest[i]);
  printf ("\n");

  return memcmp (digest, test->hash, HAS160_DIGEST_SIZE) == 0;
}

/*
 * A million 'a' characters
 */
static bool
run_has160_1mb (void)
{
  struct has160_ctx ctx;
  uint32_t i;
  uint8_t *input;
  uint8_t digest[HAS160_DIGEST_SIZE];
  const char *expect = "\xd6\xad\x6f\x06\x08\xb8\x78\xda\x9b\x87\x99\x9c\x25"
                       "\x25\xcc\x84\xf4\xc9\xf1\x8d";

  input = malloc (0xf4240);
  if (input == NULL)
    {
      fprintf (stderr, "Failed to allocate memory for large HAS-160 test.\n");
      return false;
    }

  memset (input, 'a', 0xf4240);

  has160_init (&ctx);
  has160_update (&ctx, input, 0xf4240);
  has160_final (digest, &ctx);

  for (i = 0; i < HAS160_DIGEST_SIZE; ++i)
    printf ("%02x", digest[i]);
  printf ("\n");

  free (input);

  return memcmp (digest, expect, HAS160_DIGEST_SIZE) == 0;
}
