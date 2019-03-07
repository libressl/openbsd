/*
 * Copyright (c) 2019 Ribose Inc
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef HEADER_SM2_H
#define HEADER_SM2_H

#include <openssl/ec.h>
#include <openssl/ecdsa.h>

/* The default user id as specified in GM/T 0009-2012 */
#define SM2_DEFAULT_USERID "1234567812345678"

int SM2_compute_userid_digest(uint8_t *out,
							  const EVP_MD *digest,
							  const char *user_id, const EC_KEY *key);

/*
 * SM2 signature operation. Computes ZA (user id digest) and then signs
 * H(ZA || msg) using SM2
 */
ECDSA_SIG *SM2_do_sign(const EC_KEY *key,
					   const EVP_MD *digest,
					   const char *user_id, const uint8_t *msg, size_t msg_len);

int SM2_do_verify(const EC_KEY *key,
				  const EVP_MD *digest,
				  const ECDSA_SIG *signature,
				  const char *user_id, const uint8_t *msg, size_t msg_len);

/*
 * SM2 signature generation. Assumes input is an SM3 digest
 */
int SM2_sign(int type, const unsigned char *dgst, int dgstlen,
			 unsigned char *sig, unsigned int *siglen, EC_KEY *eckey);

/*
 * SM2 signature verification. Assumes input is an SM3 digest
 */
int SM2_verify(int type, const unsigned char *dgst, int dgstlen,
			   const unsigned char *sig, int siglen, EC_KEY *eckey);


/*
 * SM2 encryption
 */
size_t SM2_ciphertext_size(const EC_KEY *key,
						   const EVP_MD *digest,
						   size_t msg_len);

int SM2_encrypt(const EC_KEY *key,
				const EVP_MD *digest,
				const uint8_t *msg,
				size_t msg_len,
				uint8_t *ciphertext_buf, size_t *ciphertext_len);

int SM2_decrypt(const EC_KEY *key,
				const EVP_MD *digest,
				const uint8_t *ciphertext,
				size_t ciphertext_len, uint8_t *ptext_buf, size_t *ptext_len);

int ERR_load_SM2_strings(void);

#endif
