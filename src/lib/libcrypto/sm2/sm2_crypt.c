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
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <string.h>

typedef struct SM2_Ciphertext_st SM2_Ciphertext;

SM2_Ciphertext *SM2_Ciphertext_new(void);
void SM2_Ciphertext_free(SM2_Ciphertext *a);
SM2_Ciphertext *d2i_SM2_Ciphertext(SM2_Ciphertext **a, const unsigned char **in, long len);
int i2d_SM2_Ciphertext(SM2_Ciphertext *a, unsigned char **out);

struct SM2_Ciphertext_st {
	BIGNUM *C1x;
	BIGNUM *C1y;
	ASN1_OCTET_STRING *C3;
	ASN1_OCTET_STRING *C2;
};

static const ASN1_TEMPLATE SM2_Ciphertext_seq_tt[] = {
	{
		.flags = 0,
		.tag = 0,
		.offset = offsetof(SM2_Ciphertext, C1x),
		.field_name = "C1x",
		.item = &BIGNUM_it,
	},
	{
		.flags = 0,
		.tag = 0,
		.offset = offsetof(SM2_Ciphertext, C1y),
		.field_name = "C1y",
		.item = &BIGNUM_it,
	},
	{
		.flags = 0,
		.tag = 0,
		.offset = offsetof(SM2_Ciphertext, C3),
		.field_name = "C3",
		.item = &ASN1_OCTET_STRING_it,
	},
	{
		.flags = 0,
		.tag = 0,
		.offset = offsetof(SM2_Ciphertext, C2),
		.field_name = "C2",
		.item = &ASN1_OCTET_STRING_it,
	},
};

const ASN1_ITEM SM2_Ciphertext_it = {
	.itype = ASN1_ITYPE_SEQUENCE,
	.utype = V_ASN1_SEQUENCE,
	.templates = SM2_Ciphertext_seq_tt,
	.tcount = sizeof(SM2_Ciphertext_seq_tt) / sizeof(ASN1_TEMPLATE),
	.funcs = NULL,
	.size = sizeof(SM2_Ciphertext),
	.sname = "SM2_Ciphertext",
};

SM2_Ciphertext *
d2i_SM2_Ciphertext(SM2_Ciphertext **a, const unsigned char **in, long len)
{
	return (SM2_Ciphertext *) ASN1_item_d2i((ASN1_VALUE **)a, in, len, &SM2_Ciphertext_it);
}

int
i2d_SM2_Ciphertext(SM2_Ciphertext *a, unsigned char **out)
{
	return ASN1_item_i2d((ASN1_VALUE *)a, out, &SM2_Ciphertext_it);
}

SM2_Ciphertext *
SM2_Ciphertext_new(void)
{
	return (SM2_Ciphertext *)ASN1_item_new(&SM2_Ciphertext_it);
}

void
SM2_Ciphertext_free(SM2_Ciphertext *a)
{
	ASN1_item_free((ASN1_VALUE *)a, &SM2_Ciphertext_it);
}

static size_t EC_field_size(const EC_GROUP *group)
{
	/* Is there some simpler way to do this? */
	BIGNUM *p = BN_new();
	BIGNUM *a = BN_new();
	BIGNUM *b = BN_new();
	size_t field_size = 0;

	if (p == NULL || a == NULL || b == NULL)
	   goto done;

	EC_GROUP_get_curve_GFp(group, p, a, b, NULL);
	field_size = (BN_num_bits(p) + 7) / 8;

 done:
	BN_free(p);
	BN_free(a);
	BN_free(b);

	return field_size;
}

size_t SM2_ciphertext_size(const EC_KEY *key, const EVP_MD *digest, size_t msg_len)
{
	return 10 + 2 * EC_field_size(EC_KEY_get0_group(key)) +
		EVP_MD_size(digest) + msg_len;
}

int SM2_encrypt(const EC_KEY *key,
				const EVP_MD *digest,
				const uint8_t *msg,
				size_t msg_len, uint8_t *ciphertext_buf, size_t *ciphertext_len)
{
	int rc = 0;
	size_t i;
	int x2size = 0;
	int y2size = 0;
	BN_CTX *ctx = NULL;
	BIGNUM *k = NULL;
	BIGNUM *x1 = NULL;
	BIGNUM *y1 = NULL;
	BIGNUM *x2 = NULL;
	BIGNUM *y2 = NULL;
	BIGNUM *order = NULL;
	EVP_MD_CTX *hash = NULL;
	struct SM2_Ciphertext_st ctext_struct;
	const EC_GROUP *group = NULL;
	const EC_POINT *P = NULL;
	EC_POINT *kG = NULL;
	EC_POINT *kP = NULL;
	uint8_t *msg_mask = NULL;
	uint8_t *x2y2 = NULL;
	uint8_t *C3 = NULL;
	size_t field_size = 0;
	size_t C3_size = 0;

	hash = EVP_MD_CTX_new();
	group = EC_KEY_get0_group(key);
	
	if ((order = BN_new()) == NULL)
		goto done;

	if (!EC_GROUP_get_order(group, order, NULL))
		goto done;

	P = EC_KEY_get0_public_key(key);
	field_size = EC_field_size(group);
	C3_size = EVP_MD_size(digest);

	if (field_size == 0 || C3_size == 0)
		goto done;

	kG = EC_POINT_new(group);
	kP = EC_POINT_new(group);
	if (kG == NULL || kP == NULL)
		goto done;

	ctx = BN_CTX_new();
	if (ctx == NULL)
		goto done;

	BN_CTX_start(ctx);
	k = BN_CTX_get(ctx);
	x1 = BN_CTX_get(ctx);
	x2 = BN_CTX_get(ctx);
	y1 = BN_CTX_get(ctx);
	y2 = BN_CTX_get(ctx);

	if (y2 == NULL)
	   goto done;

	x2y2 = calloc(1, 2 * field_size);
	C3 = calloc(1, C3_size);

	if (x2y2 == NULL || C3 == NULL)
		goto done;

	memset(ciphertext_buf, 0, *ciphertext_len);

	BN_rand_range(k, order);

	if (EC_POINT_mul(group, kG, k, NULL, NULL, ctx) == 0)
		goto done;

	if (EC_POINT_get_affine_coordinates_GFp(group, kG, x1, y1, ctx) == 0)
		goto done;

	if (EC_POINT_mul(group, kP, NULL, P, k, ctx) == 0)
		goto done;

	if (EC_POINT_get_affine_coordinates_GFp(group, kP, x2, y2, ctx) == 0)
		goto done;

	x2size = BN_num_bytes(x2);
	y2size = BN_num_bytes(y2);
	if ((x2size > field_size) || (y2size > field_size))
		goto done;

	BN_bn2bin(x2, x2y2 + field_size - x2size);
	BN_bn2bin(y2, x2y2 + 2 * field_size - y2size);

	msg_mask = calloc(1, msg_len);
	if (msg_mask == NULL)
		goto done;

	/* X9.63 with no salt happens to match the KDF used in SM2 */
	if (ECDH_KDF_X9_62(msg_mask, msg_len, x2y2, 2 * field_size, NULL, 0, digest) == 0)
		goto done;

	for (i = 0; i != msg_len; ++i)
		msg_mask[i] ^= msg[i];

	if (EVP_DigestInit(hash, digest) == 0)
		goto done;

	if (EVP_DigestUpdate(hash, x2y2, field_size) == 0)
		goto done;

	if (EVP_DigestUpdate(hash, msg, msg_len) == 0)
		goto done;

	if (EVP_DigestUpdate(hash, x2y2 + field_size, field_size) == 0)
		goto done;

	if (EVP_DigestFinal(hash, C3, NULL) == 0)
		goto done;

	ctext_struct.C1x = x1;
	ctext_struct.C1y = y1;
	ctext_struct.C3 = ASN1_OCTET_STRING_new();
	ASN1_OCTET_STRING_set(ctext_struct.C3, C3, C3_size);
	ctext_struct.C2 = ASN1_OCTET_STRING_new();
	ASN1_OCTET_STRING_set(ctext_struct.C2, msg_mask, msg_len);

	*ciphertext_len = i2d_SM2_Ciphertext(&ctext_struct, &ciphertext_buf);

	ASN1_OCTET_STRING_free(ctext_struct.C2);
	ASN1_OCTET_STRING_free(ctext_struct.C3);

	rc = 1;

 done:
	free(msg_mask);
	free(x2y2);
	free(C3);
	EVP_MD_CTX_free(hash);
	BN_CTX_free(ctx);
	EC_POINT_free(kG);
	EC_POINT_free(kP);
	BN_free(order);
	return rc;
}

int SM2_decrypt(const EC_KEY *key,
				const EVP_MD *digest,
				const uint8_t *ciphertext,
				size_t ciphertext_len, uint8_t *ptext_buf, size_t *ptext_len)
{
	int rc = 0;
	int i;
	size_t x2size = 0;
	size_t y2size = 0;
	BN_CTX *ctx = NULL;
	const EC_GROUP *group = NULL;
	EC_POINT *C1 = NULL;
	struct SM2_Ciphertext_st *sm2_ctext = NULL;
	BIGNUM *x2 = NULL;
	BIGNUM *y2 = NULL;
	uint8_t *x2y2 = NULL;
	uint8_t *computed_C3 = NULL;
	size_t field_size = 0;
	int hash_size = 0;
	uint8_t *msg_mask = NULL;
	const uint8_t *C2 = NULL;
	const uint8_t *C3 = NULL;
	int msg_len = 0;
	EVP_MD_CTX *hash = NULL;

	group = EC_KEY_get0_group(key);
	field_size = EC_field_size(group);
	hash_size = EVP_MD_size(digest);

	if (field_size == 0 || hash_size == 0)
		goto done;

	memset(ptext_buf, 0xFF, *ptext_len);

	sm2_ctext = d2i_SM2_Ciphertext(NULL, &ciphertext, ciphertext_len);

	if (sm2_ctext == NULL)
		goto done;

	if (sm2_ctext->C3->length != hash_size)
		goto done;

	C2 = sm2_ctext->C2->data;
	C3 = sm2_ctext->C3->data;
	msg_len = sm2_ctext->C2->length;

	ctx = BN_CTX_new();
	if (ctx == NULL)
		goto done;

	BN_CTX_start(ctx);
	x2 = BN_CTX_get(ctx);
	y2 = BN_CTX_get(ctx);

	if(y2 == NULL)
		goto done;

	msg_mask = calloc(1, msg_len);
	x2y2 = calloc(1, 2 * field_size);
	computed_C3 = calloc(1, hash_size);

	if (msg_mask == NULL || x2y2 == NULL || computed_C3 == NULL)
		goto done;

	C1 = EC_POINT_new(group);
	if (C1 == NULL)
		goto done;

	if (EC_POINT_set_affine_coordinates_GFp
		(group, C1, sm2_ctext->C1x, sm2_ctext->C1y, ctx) == 0)
		goto done;

	if (EC_POINT_mul(group, C1, NULL, C1, EC_KEY_get0_private_key(key), ctx) == 0)
		goto done;

	if (EC_POINT_get_affine_coordinates_GFp(group, C1, x2, y2, ctx) == 0)
		goto done;

	x2size = BN_num_bytes(x2);
	y2size = BN_num_bytes(y2);
	if ((x2size > field_size) || (y2size > field_size))
		goto done;

	BN_bn2bin(x2, x2y2 + field_size - x2size);
	BN_bn2bin(y2, x2y2 + 2 * field_size - y2size);

	if (ECDH_KDF_X9_62(msg_mask, msg_len, x2y2, 2 * field_size, NULL, 0, digest) == 0)
		goto done;

	for (i = 0; i != msg_len; ++i)
		ptext_buf[i] = C2[i] ^ msg_mask[i];

	hash = EVP_MD_CTX_new();

	if (hash == NULL)
	   goto done;

	if (EVP_DigestInit(hash, digest) == 0)
		goto done;

	if (EVP_DigestUpdate(hash, x2y2, field_size) == 0)
		goto done;

	if (EVP_DigestUpdate(hash, ptext_buf, msg_len) == 0)
		goto done;

	if (EVP_DigestUpdate(hash, x2y2 + field_size, field_size) == 0)
		goto done;

	if (EVP_DigestFinal(hash, computed_C3, NULL) == 0)
		goto done;

	if (memcmp(computed_C3, C3, hash_size) != 0)
		goto done;

	rc = 1;

 done:

	if (rc == 0)
		memset(ptext_buf, 0, *ptext_len);

	free(msg_mask);
	free(x2y2);
	free(computed_C3);
	EC_POINT_free(C1);
	BN_CTX_free(ctx);
	SM2_Ciphertext_free(sm2_ctext);
	EVP_MD_CTX_free(hash);

	return rc;
}
