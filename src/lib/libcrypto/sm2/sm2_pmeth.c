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

#include <string.h>

#include <openssl/sm2.h>
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include "evp_locl.h"
#include "sm2_locl.h"

/* SM2 pkey context structure */

typedef struct {
	/* key and paramgen group */
	EC_GROUP *gen_group;
	/* message  digest */
	const EVP_MD *md;
	/* personalization string */
	char* uid;
} SM2_PKEY_CTX;

static int pkey_sm2_init(EVP_PKEY_CTX *ctx)
{
	SM2_PKEY_CTX *dctx;

	dctx = calloc(1, sizeof(*dctx));
	if (dctx == NULL) {
		SM2error(ERR_R_MALLOC_FAILURE);
		return 0;
	}

	ctx->data = dctx;
	return 1;
}

static void pkey_sm2_cleanup(EVP_PKEY_CTX *ctx)
{
	SM2_PKEY_CTX *dctx = ctx->data;

	if (dctx) {
		EC_GROUP_free(dctx->gen_group);
		free(dctx->uid);
		free(dctx);
		ctx->data = NULL;
	}
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
		if (!dctx->gen_group) {
			SM2error(ERR_R_MALLOC_FAILURE);
			pkey_sm2_cleanup(dst);
			return 0;
		}
	}

	if (sctx->uid != NULL) {
		dctx->uid = strdup(sctx->uid);
		if (dctx->uid == NULL) {
			SM2error(ERR_R_MALLOC_FAILURE);
			pkey_sm2_cleanup(dst);
			return 0;
		}
	}

	dctx->md = sctx->md;

	return 1;
}

static int pkey_sm2_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
						const unsigned char *tbs, size_t tbslen)
{
	int ret;
	unsigned int sltmp;
	EC_KEY *ec = ctx->pkey->pkey.ec;
	const int sig_sz = ECDSA_size(ctx->pkey->pkey.ec);

	if (sig_sz <= 0) {
		return 0;
	}

	if (sig == NULL) {
		*siglen = (size_t) sig_sz;
		return 1;
	}

	if (*siglen < (size_t)sig_sz) {
		SM2error(SM2_R_BUFFER_TOO_SMALL);
		return 0;
	}

	ret = SM2_sign(tbs, tbslen, sig, &sltmp, ec);

	if (ret <= 0)
		return ret;
	*siglen = (size_t)sltmp;
	return 1;
}

static int pkey_sm2_verify(EVP_PKEY_CTX *ctx,
						  const unsigned char *sig, size_t siglen,
						  const unsigned char *tbs, size_t tbslen)
{
	EC_KEY *ec = ctx->pkey->pkey.ec;

	return SM2_verify(tbs, tbslen, sig, siglen, ec);
}

static int pkey_sm2_encrypt(EVP_PKEY_CTX *ctx,
							unsigned char *out, size_t *outlen,
							const unsigned char *in, size_t inlen)
{
	EC_KEY *ec = ctx->pkey->pkey.ec;
	SM2_PKEY_CTX *dctx = ctx->data;
	const EVP_MD *md = (dctx->md == NULL) ? EVP_sm3() : dctx->md;

	if (out == NULL) {
		if (!SM2_ciphertext_size(ec, md, inlen, outlen))
			return -1;
		else
			return 1;
	}

	return SM2_encrypt(ec, md, in, inlen, out, outlen);
}

static int pkey_sm2_decrypt(EVP_PKEY_CTX *ctx,
							unsigned char *out, size_t *outlen,
							const unsigned char *in, size_t inlen)
{
	EC_KEY *ec = ctx->pkey->pkey.ec;
	SM2_PKEY_CTX *dctx = ctx->data;
	const EVP_MD *md = (dctx->md == NULL) ? EVP_sm3() : dctx->md;

	if (out == NULL) {
		if (!SM2_plaintext_size(ec, md, inlen, outlen))
			return -1;
		else
			return 1;
	}

	return SM2_decrypt(ec, md, in, inlen, out, outlen);
}

static int pkey_sm2_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
	SM2_PKEY_CTX *dctx = ctx->data;
	EC_GROUP *group = NULL;

	switch (type) {
	case EVP_PKEY_CTRL_DIGESTINIT:
		if (dctx->uid != NULL) {
			EC_KEY *ec = ctx->pkey->pkey.ec;
			EVP_MD_CTX *md_ctx = (EVP_MD_CTX*) p2;
			const EVP_MD* md = NULL;
			int md_len = 0;
			uint8_t za[EVP_MAX_MD_SIZE] = {0};

			md = EVP_MD_CTX_md(md_ctx);
			if (md == NULL) {
				SM2error(ERR_R_EVP_LIB);
				return 0;
			}

			md_len = EVP_MD_size(md);
			if (md_len <= 0) {
				SM2error(SM2_R_INVALID_DIGEST);
				return 0;
			}

			if (SM2_compute_userid_digest(za, md, dctx->uid, ec) != 1) {
				SM2error(SM2_R_DIGEST_FAILURE);
				return 0;
			}

			return EVP_DigestUpdate(md_ctx, za, md_len);
		}
		return 1;

	case EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID:
		group = EC_GROUP_new_by_curve_name(p1);
		if (group == NULL) {
			SM2error(SM2_R_INVALID_CURVE);
			return 0;
		}
		EC_GROUP_free(dctx->gen_group);
		dctx->gen_group = group;
		return 1;

	case EVP_PKEY_CTRL_SM2_SET_UID:
		free(dctx->uid);
		dctx->uid = strdup(p2);
		if (dctx->uid == NULL) {
			SM2error(ERR_R_MALLOC_FAILURE);
			return 0;
		}
		return 1;

	case EVP_PKEY_CTRL_SM2_GET_UID:
		*(char **)p2 = dctx->uid;
		return 1;

	case EVP_PKEY_CTRL_MD:
		dctx->md = p2;
		return 1;

	default:
		return -2;

	}
}

static int pkey_sm2_ctrl_str(EVP_PKEY_CTX *ctx,
							 const char *type, const char *value)
{
	if (strcmp(type, "ec_paramgen_curve") == 0) {
		int nid = NID_undef;

		if (((nid = EC_curve_nist2nid(value)) == NID_undef)
			&& ((nid = OBJ_sn2nid(value)) == NID_undef)
			&& ((nid = OBJ_ln2nid(value)) == NID_undef)) {
			SM2error(SM2_R_INVALID_CURVE);
			return 0;
		}
		return EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid);
	} else if (strcmp(type, "sm2_uid") == 0) {
		return EVP_PKEY_CTX_set_sm2_uid(ctx, value);
	}

	return -2;
}

const EVP_PKEY_METHOD sm2_pkey_meth = {
	.pkey_id = EVP_PKEY_SM2,
	.init = pkey_sm2_init,
	.copy = pkey_sm2_copy,
	.cleanup = pkey_sm2_cleanup,

	.sign = pkey_sm2_sign,

	.verify = pkey_sm2_verify,

	.encrypt = pkey_sm2_encrypt,

	.decrypt = pkey_sm2_decrypt,

	.ctrl = pkey_sm2_ctrl,
	.ctrl_str = pkey_sm2_ctrl_str
};
