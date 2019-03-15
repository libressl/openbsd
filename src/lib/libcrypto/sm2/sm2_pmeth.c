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
#include "internal/cryptlib.h"
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include "internal/evp_int.h"

/* EC pkey context structure */

typedef struct {
	EC_GROUP *gen_group;
	const EVP_MD *md;
	char* user_id;
} EC_PKEY_CTX;

static int pkey_sm2_init(EVP_PKEY_CTX *ctx)
{
	SM2_PKEY_CTX *dctx;

	dctx = calloc(1, sizeof(*dctx));
	if (dctx == NULL)
		return 0;

	ctx->data = dctx;
	return 1;
}

static int pkey_sm2_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
{
	SM2_PKEY_CTX *dctx, *sctx;
	if (!pkey_sm2_init(dst))
		return 0;
	sctx = src->data;
	dctx = dst->data;
	if (sctx->gen_group) {
		dctx->gen_group = EC_GROUP_dup(sctx->gen_group);
		if (!dctx->gen_group)
			return 0;
	}
	dctx->md = sctx->md;
	return 1;
}

static void pkey_sm2_cleanup(EVP_PKEY_CTX *ctx)
{
	SM2_PKEY_CTX *dctx = ctx->data;
	if (dctx) {
		EC_GROUP_free(dctx->gen_group);
		free(dctx);
	}
}

static int pkey_sm2_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
						const unsigned char *tbs, size_t tbslen)
{
	SM2_PKEY_CTX *dctx = ctx->data;
	EC_KEY *ec = ctx->pkey->pkey.ec;
	ECDSA_SIG* der_sig = NULL;
	const EVP_MD* md = NULL;
	const char* user_id = NULL;

	if (!sig) {
		/* ECDSA and SM2 signatures have the same size */
		*siglen = ECDSA_size(ec);
		return 1;
	} else if (*siglen < (size_t)ECDSA_size(ec)) {
		ECerr(EC_F_PKEY_SM2_SIGN, EC_R_BUFFER_TOO_SMALL);
		return 0;
	}

	md = (dctx->md) ? dctx->md : EVP_sm3();
	user_id = (dctx->user_id) ? dctx->user_id : SM2_DEFAULT_USERID;
	der_sig = SM2_do_sign(ec, md, user_id, tbs, tbslen);

	if(der_sig == NULL)
		return 0;

	// Now ASN.1 encode ...
	*siglen = i2d_ECDSA_SIG(der_sig, &sig);

	return 1;
}

static int pkey_sm2_verify(EVP_PKEY_CTX *ctx,
						  const unsigned char *sig, size_t siglen,
						  const unsigned char *tbs, size_t tbslen)
{
	int ret, type;
	SM2_PKEY_CTX *dctx = ctx->data;
	EC_KEY *ec = ctx->pkey->pkey.ec;

	if (dctx->md)
		type = EVP_MD_type(dctx->md);
	else
		type = NID_sm3;

	ret = ECDSA_verify(type, tbs, tbslen, sig, siglen, ec);

	return ret;
}

static int pkey_sm2_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
	SM2_PKEY_CTX *dctx = ctx->data;
	EC_GROUP *group;
	switch (type) {
	case EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID:
		group = EC_GROUP_new_by_curve_name(p1);
		if (group == NULL) {
			ECerr(EC_F_PKEY_SM2_CTRL, EC_R_INVALID_CURVE);
			return 0;
		}
		EC_GROUP_free(dctx->gen_group);
		dctx->gen_group = group;
		return 1;

	case EVP_PKEY_CTRL_MD:
		{
		int md_type = EVP_MD_type((const EVP_MD *)p2);
		if (md_type != NID_sm3 &&
			md_type != NID_sha256 &&
			md_type != NID_sha512_256) {
			ECerr(EC_F_PKEY_SM2_CTRL, EC_R_INVALID_DIGEST_TYPE);
			return 0;
		}
		dctx->md = p2;
		return 1;
		}

	case EVP_PKEY_CTRL_GET_MD:
		*(const EVP_MD **)p2 = dctx->md;
		return 1;

		/* Default behaviour is OK */
	case EVP_PKEY_CTRL_DIGESTINIT:
	case EVP_PKEY_CTRL_PKCS7_SIGN:
	case EVP_PKEY_CTRL_CMS_SIGN:
		return 1;

	default:
		return -2;

	}
}

static int pkey_sm2_ctrl_str(EVP_PKEY_CTX *ctx,
							const char *type, const char *value)
{
	if (strcmp(type, "ec_paramgen_curve") == 0) {
		int nid;
		nid = EC_curve_nist2nid(value);
		if (nid == NID_undef)
			nid = OBJ_sn2nid(value);
		if (nid == NID_undef)
			nid = OBJ_ln2nid(value);
		if (nid == NID_undef) {
			ECerr(EC_F_PKEY_SM2_CTRL_STR, EC_R_INVALID_CURVE);
			return 0;
		}
		return EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid);
	} else if (strcmp(type, "ec_param_enc") == 0) {
		int param_enc;
		if (strcmp(value, "explicit") == 0)
			param_enc = 0;
		else if (strcmp(value, "named_curve") == 0)
			param_enc = OPENSSL_EC_NAMED_CURVE;
		else
			return -2;
		return EVP_PKEY_CTX_set_ec_param_enc(ctx, param_enc);
	} else if(strcmp(type, "user_id") == 0) {
		SM2_PKEY_CTX *dctx = ctx->data;
		free(dctx->user_id);
		dctx->user_id = OPENSSL_strdup(value);
	}
	return -2;
}

static int pkey_sm2_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
	EC_KEY *ec = NULL;
	SM2_PKEY_CTX *dctx = ctx->data;
	int ret = 0;
	if (dctx->gen_group == NULL) {
		ECerr(EC_F_PKEY_SM2_PARAMGEN, EC_R_NO_PARAMETERS_SET);
		return 0;
	}
	ec = EC_KEY_new();
	if (ec == NULL)
		return 0;
	ret = EC_KEY_set_group(ec, dctx->gen_group);
	if (ret)
		EVP_PKEY_assign_EC_KEY(pkey, ec);
	else
		EC_KEY_free(ec);
	return ret;
}

static int pkey_sm2_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
	EC_KEY *ec = NULL;
	SM2_PKEY_CTX *dctx = ctx->data;
	if (ctx->pkey == NULL && dctx->gen_group == NULL) {
		ECerr(EC_F_PKEY_SM2_KEYGEN, EC_R_NO_PARAMETERS_SET);
		return 0;
	}
	ec = EC_KEY_new();
	if (!ec)
		return 0;
	EVP_PKEY_assign_EC_KEY(pkey, ec);
	if (ctx->pkey) {
		/* Note: if error return, pkey is freed by parent routine */
		if (!EVP_PKEY_copy_parameters(pkey, ctx->pkey))
			return 0;
	} else {
		if (!EC_KEY_set_group(ec, dctx->gen_group))
			return 0;
	}
	return EC_KEY_generate_key(pkey->pkey.ec);
}

const EVP_PKEY_METHOD sm2_pkey_meth = {
	EVP_PKEY_SM2,
	0,
	pkey_sm2_init,
	pkey_sm2_copy,
	pkey_sm2_cleanup,

	0,
	pkey_sm2_paramgen,

	0,
	pkey_sm2_keygen,

	0,
	pkey_sm2_sign,

	0,
	pkey_sm2_verify,

	0, 0,

	0, 0, 0, 0,

	0, 0,

	0, 0,

	0,
	0,
	pkey_sm2_ctrl,
	pkey_sm2_ctrl_str
};
