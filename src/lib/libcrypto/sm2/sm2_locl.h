/*	$OpenBSD: sm2_locl.h,v 1.1 2019/03/19 16:44:25 tb Exp $	*/
/*
 * Copyright (c) 2019, Ribose Inc
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

#ifndef HEADER_SM2_LOCL_H
#define HEADER_SM2_LOCL_H

#include <openssl/ec.h>
#include <openssl/ecdsa.h>

__BEGIN_HIDDEN_DECLS

/* The default user id as specified in GM/T 0009-2012 */
#define SM2_DEFAULT_USERID "1234567812345678"

int SM2_compute_userid_digest(uint8_t *out,
							  const EVP_MD *digest,
							  const uint8_t *uid,
							  size_t uid_len,
							  const EC_KEY *key);

/*
 * SM2 signature operation. Computes ZA (user id digest) and then signs
 * H(ZA || msg) using SM2
 */
ECDSA_SIG *SM2_do_sign(const EC_KEY *key,
					   const EVP_MD *digest,
					   const uint8_t *uid, size_t uid_len,
					   const uint8_t *msg, size_t msg_len);

int SM2_do_verify(const EC_KEY *key,
				  const EVP_MD *digest,
				  const ECDSA_SIG *signature,
				  const uint8_t *uid, size_t uid_len,
				  const uint8_t *msg, size_t msg_len);

__END_HIDDEN_DECLS

#endif

