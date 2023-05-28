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

#ifndef AES_H
#define AES_H

#include <stddef.h>
#include <stdint.h>

#define AES128_KEY_SIZE 16
#define AES128_BLOCK_SIZE 16
#define AES128_ROUNDS 10

#define AES192_KEY_SIZE 24
#define AES192_BLOCK_SIZE 16
#define AES192_ROUNDS 12

#define AES256_KEY_SIZE 32
#define AES256_BLOCK_SIZE 16
#define AES256_ROUNDS 14

struct aes128_ctx {
	uint32_t ek[44];
	uint32_t dk[44];
};

struct aes192_ctx {
	uint32_t ek[52];
	uint32_t dk[52];
};

struct aes256_ctx {
	uint32_t ek[60];
	uint32_t dk[60];
};

void aes128_set_encrypt_key(struct aes128_ctx *, const uint8_t *);
void aes192_set_encrypt_key(struct aes192_ctx *, const uint8_t *);
void aes256_set_encrypt_key(struct aes256_ctx *, const uint8_t *);
void aes128_set_decrypt_key(struct aes128_ctx *, const uint8_t *);
void aes192_set_decrypt_key(struct aes192_ctx *, const uint8_t *);
void aes256_set_decrypt_key(struct aes256_ctx *, const uint8_t *);
void aes128_encrypt(struct aes128_ctx *, const uint8_t *, uint8_t *);
void aes192_encrypt(struct aes192_ctx *, const uint8_t *, uint8_t *);
void aes256_encrypt(struct aes256_ctx *, const uint8_t *, uint8_t *);
void aes128_decrypt(struct aes128_ctx *, const uint8_t *, uint8_t *);
void aes192_decrypt(struct aes192_ctx *, const uint8_t *, uint8_t *);
void aes256_decrypt(struct aes256_ctx *, const uint8_t *, uint8_t *);

#endif /* AES_H */

