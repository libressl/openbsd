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

#include <openssl/sm2.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <string.h>

int SM2_compute_userid_digest(uint8_t *out,
							  const EVP_MD *digest,
							  const char *user_id,
							  const EC_KEY *key)
{
	int rc = 0;

	const EC_GROUP *group = EC_KEY_get0_group(key);

	BN_CTX *ctx = NULL;
	EVP_MD_CTX *hash = NULL;

	BIGNUM *p = NULL;
	BIGNUM *a = NULL;
	BIGNUM *b = NULL;

	BIGNUM *xG = NULL;
	BIGNUM *yG = NULL;
	BIGNUM *xA = NULL;
	BIGNUM *yA = NULL;

	int p_bytes = 0;
	uint8_t *buf = NULL;
	size_t uid_len = 0;
	uint16_t entla = 0;
	uint8_t e_byte = 0;

	hash = EVP_MD_CTX_new();
	if (hash == NULL)
	   goto done;

	ctx = BN_CTX_new();
	if (ctx == NULL)
	   goto done;

	p = BN_CTX_get(ctx);
	a = BN_CTX_get(ctx);
	b = BN_CTX_get(ctx);
	xG = BN_CTX_get(ctx);
	yG = BN_CTX_get(ctx);
	xA = BN_CTX_get(ctx);
	yA = BN_CTX_get(ctx);

	if (p == NULL || a == NULL || b == NULL ||
		xG == NULL || yG == NULL || xA == NULL || yA == NULL)
	   goto done;

	memset(out, 0, EVP_MD_size(digest));

	if (EVP_DigestInit(hash, digest) == 0)
		goto done;

	/*
	   ZA=H256(ENTLA || IDA || a || b || xG || yG || xA || yA)
	 */

	uid_len = strlen(user_id);

	if (uid_len >= 8192)        /* too large */
		goto done;

	entla = (unsigned short)(8 * uid_len);

	e_byte = entla >> 8;
	if (EVP_DigestUpdate(hash, &e_byte, 1) == 0)
		goto done;
	e_byte = entla & 0xFF;
	if (EVP_DigestUpdate(hash, &e_byte, 1) == 0)
		goto done;

	if (EVP_DigestUpdate(hash, user_id, uid_len) == 0)
		goto done;

	if (EC_GROUP_get_curve_GFp(group, p, a, b, ctx) == 0)
		goto done;

	p_bytes = BN_num_bytes(p);
	buf = OPENSSL_zalloc(p_bytes);

	BN_bn2binpad(a, buf, p_bytes);
	if (EVP_DigestUpdate(hash, buf, p_bytes) == 0)
		goto done;
	BN_bn2binpad(b, buf, p_bytes);
	if (EVP_DigestUpdate(hash, buf, p_bytes) == 0)
		goto done;
	EC_POINT_get_affine_coordinates_GFp(group,
										EC_GROUP_get0_generator(group),
										xG, yG, ctx);
	BN_bn2binpad(xG, buf, p_bytes);
	if (EVP_DigestUpdate(hash, buf, p_bytes) == 0)
		goto done;
	BN_bn2binpad(yG, buf, p_bytes);
	if (EVP_DigestUpdate(hash, buf, p_bytes) == 0)
		goto done;

	EC_POINT_get_affine_coordinates_GFp(group,
										EC_KEY_get0_public_key(key),
										xA, yA, ctx);
	BN_bn2binpad(xA, buf, p_bytes);
	if (EVP_DigestUpdate(hash, buf, p_bytes) == 0)
		goto done;
	BN_bn2binpad(yA, buf, p_bytes);
	if (EVP_DigestUpdate(hash, buf, p_bytes) == 0)
		goto done;

	if (EVP_DigestFinal(hash, out, NULL) == 0)
		goto done;

	rc = 1;

 done:
	OPENSSL_free(buf);
	BN_CTX_free(ctx);
	EVP_MD_CTX_free(hash);
	return rc;
}
