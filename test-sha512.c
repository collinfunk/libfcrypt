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
 * Most test vectors are from RFC 6234.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sha512.h"

struct sha512_testcase
{
  const char *message;
  const char *hash;
};

static const struct sha512_testcase testcases[] = {
  { "a", "\x1f\x40\xfc\x92\xda\x24\x16\x94\x75\x09\x79\xee\x6c\xf5\x82"
         "\xf2\xd5\xd7\xd2\x8e\x18\x33\x5d\xe0\x5a\xbc\x54\xd0"
         "\x56\x0e\x0f\x53\x02\x86\x0c\x65\x2b\xf0\x8d\x56\x02"
         "\x52\xaa\x5e\x74\x21\x05\x46\xf3\x69\xfb\xbb\xce\x8c"
         "\x12\xcf\xc7\x95\x7b\x26\x52\xfe\x9a\x75" },
  { "abc", "\xdd\xaf\x35\xa1\x93\x61\x7a\xba\xcc\x41\x73\x49\xae\x20\x41"
           "\x31\x12\xe6\xfa\x4e\x89\xa9\x7e\xa2\x0a\x9e\xee\xe6"
           "\x4b\x55\xd3\x9a\x21\x92\x99\x2a\x27\x4f\xc1\xa8\x36"
           "\xba\x3c\x23\xa3\xfe\xeb\xbd\x45\x4d\x44\x23\x64\x3c"
           "\xe8\x0e\x2a\x9a\xc9\x4f\xa5\x4c\xa4\x9f" },
  { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    "\x20\x4a\x8f\xc6\xdd\xa8\x2f\x0a\x0c\xed\x7b\xeb\x8e\x08\xa4"
    "\x16\x57\xc1\x6e\xf4\x68\xb2\x28\xa8\x27\x9b\xe3\x31"
    "\xa7\x03\xc3\x35\x96\xfd\x15\xc1\x3b\x1b\x07\xf9\xaa"
    "\x1d\x3b\xea\x57\x78\x9c\xa0\x31\xad\x85\xc7\xa7\x1d"
    "\xd7\x03\x54\xec\x63\x12\x38\xca\x34\x45" },
  { "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn",
    "\x67\xf2\x0f\x48\x0d\x93\x89\xd4\x8e\xc1\x73\x45\xe0\xd6\xe4"
    "\x06\xea\x19\x32\x53\xc5\x37\x86\x21\x9e\xca\xc2\x0f"
    "\xe3\xa3\x04\x37\xf4\xa4\x59\xc8\x51\xbf\xa0\x6d\xb9"
    "\x90\xbe\xd6\xf9\x05\x8f\x87\x08\x53\x93\x9f\x8c\x09"
    "\x81\xa5\x00\x91\xfd\x57\x15\x93\x96\xa0" },
  { "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
    "\xd0\xd3\xc7\x83\xe7\x24\xf8\x37\xe3\x84\xba\xd9\xf8\x3b\x19"
    "\x56\xe8\xda\xb2\x0d\xc8\xcf\x4a\x9c\xcc\xb3\xcc\x20"
    "\x7b\xe0\x34\x9a\x63\xca\x66\xe2\x18\xfc\x50\xe3\x0e"
    "\xb8\xa1\xa3\x4b\x02\xc6\x26\x22\x48\x37\x34\x82\x88"
    "\xbb\xb0\x36\xf2\xc5\x0e\xc5\x2a\xf4\xdb" },
  { "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
    "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrst"
    "nopqrstu",
    "\x8e\x95\x9b\x75\xda\xe3\x13\xda\x8c\xf4\xf7\x28\x14\xfc"
    "\x14\x3f\x8f\x77\x79\xc6\xeb\x9f\x7f\xa1\x72\x99\xae"
    "\xad\xb6\x88\x90\x18\x50\x1d\x28\x9e\x49\x00\xf7\xe4"
    "\x33\x1b\x99\xde\xc4\xb5\x43\x3a\xc7\xd3\x29\xee\xb6"
    "\xdd\x26\x54\x5e\x96\xe5\x5b\x87\x4b\xe9\x09" },
  { "01234567012345670123456701234567",
    "\xf8\xc0\x08\x59\x01\xbb\x2e\x5f\xc2\x90\x92\x1c\x7b\x08\xcf"
    "\x9c\x2e\x4c\x30\x5c\xa4\x17\xbd\x18\xd3\x7f\xc8\xe6"
    "\xd5\xb0\x8c\x05\xac\xed\xbc\xe6\xa9\x2c\x4b\xc3\x09"
    "\x8c\x32\x4b\xf1\x93\x0a\xb7\x6a\xa1\xdb\xb3\x33\x61"
    "\x29\x00\x6d\x99\x1f\xfc\x8d\x4a\x9d\x09" },
  { "01234567012345670123456701234567"
    "01234567012345670123456701234567",
    "\x84\x6e\x0e\xf7\x34\x36\x43\x8a\x4a\xcb\x0b\xa7\x07\x8c\xfe"
    "\x38\x1f\x10\xa0\xf5\xed\xeb\xcb\x98\x5b\x37\x90\x08"
    "\x6e\xf5\xe7\xac\x59\x92\xac\x9c\x23\xc7\x77\x61\xc7"
    "\x64\xbb\x3b\x1c\x25\x70\x2d\x06\xb9\x99\x55\xeb\x19"
    "\x7d\x45\xb8\x2f\xb3\xd1\x24\x69\x9d\x78" },
};

static bool run_sha512_testcase (const struct sha512_testcase *);

int
main (void)
{
  uint32_t i;
  int rv;
  const struct sha512_testcase *curr;

  rv = 0;
  for (i = 0; i < (sizeof (testcases) / sizeof (testcases[0])); ++i)
    {
      curr = &testcases[i];
      if (!run_sha512_testcase (curr))
        {
          fprintf (stderr, "SHA-512 test %u failed.\n", i);
          rv = 1;
        }
    }

  return rv;
}

static bool
run_sha512_testcase (const struct sha512_testcase *test)
{
  uint32_t i;
  struct sha512_ctx ctx;
  uint8_t digest[SHA512_DIGEST_SIZE];

  sha512_init (&ctx);
  sha512_update (&ctx, test->message, strlen (test->message));
  sha512_final (digest, &ctx);

  for (i = 0; i < SHA512_DIGEST_SIZE; ++i)
    printf ("%02x", digest[i]);
  printf ("\n");

  if (memcmp (digest, test->hash, SHA512_DIGEST_SIZE) != 0)
    return false;

  return true;
}
