/*	$OpenBSD: sm2evptest.c,v 1.1 2019/03/21 15:20:00 tb Exp $	*/
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ec.h>
#include <openssl/evp.h>

#ifdef OPENSSL_NO_SM2
int main(int argc, char *argv[])
{
	printf("No SM2 support\n");
	return (0);
}
#else
static int test_EVP_SM2(void)
{
	int ret = 0;
	EVP_PKEY *pkey = NULL;
	EVP_PKEY *params = NULL;
	EVP_PKEY_CTX *pctx = NULL;
	EVP_PKEY_CTX *kctx = NULL;
	size_t sig_len = 0;
	unsigned char *sig = NULL;
	EVP_MD_CTX *md_ctx = NULL;
	EVP_MD_CTX *md_ctx_verify = NULL;
	EVP_PKEY_CTX *cctx = NULL;

	uint8_t ciphertext[128];
	size_t ctext_len = sizeof(ciphertext);

	uint8_t plaintext[8];
	size_t ptext_len = sizeof(plaintext);

	uint8_t kMsg[4] = {1, 2, 3, 4};

	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
	if (pctx == NULL)
		goto done;

	if (EVP_PKEY_paramgen_init(pctx) != 1)
		goto done;

	if (!EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_sm2))
		goto done;

	if (!EVP_PKEY_paramgen(pctx, &params))
		goto done;

	kctx = EVP_PKEY_CTX_new(params, NULL);
	if (kctx == NULL)
		goto done;

	if (!EVP_PKEY_keygen_init(kctx))
		goto done;

	if (!EVP_PKEY_keygen(kctx, &pkey))
		goto done;

	if (!EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2))
		goto done;

	if ((md_ctx = EVP_MD_CTX_new()) == NULL)
		goto done;

	if ((md_ctx_verify = EVP_MD_CTX_new()) == NULL)
		goto done;

	if (!EVP_DigestSignInit(md_ctx, NULL, EVP_sm3(), NULL, pkey))
		goto done;

	if(!EVP_DigestSignUpdate(md_ctx, kMsg, sizeof(kMsg)))
		goto done;

	/* Determine the size of the signature. */
	if (!EVP_DigestSignFinal(md_ctx, NULL, &sig_len))
		goto done;

	if (sig_len != (size_t) EVP_PKEY_size(pkey))
		goto done;

	if ((sig = malloc(sig_len)) == NULL)
		goto done;

	if (!EVP_DigestSignFinal(md_ctx, sig, &sig_len))
		goto done;

	/* Ensure that the signature round-trips. */

	if (!EVP_DigestVerifyInit(md_ctx_verify, NULL, EVP_sm3(), NULL, pkey))
		goto done;

	if (!EVP_DigestVerifyUpdate(md_ctx_verify, kMsg, sizeof(kMsg)))
		goto done;

	if (!EVP_DigestVerifyFinal(md_ctx_verify, sig, sig_len))
		goto done;

	/* now check encryption/decryption */

	if ((cctx = EVP_PKEY_CTX_new(pkey, NULL)) == NULL)
		goto done;

	if (!EVP_PKEY_encrypt_init(cctx))
		goto done;

	if (!EVP_PKEY_encrypt(cctx, ciphertext, &ctext_len, kMsg, sizeof(kMsg)))
		goto done;

	if (!EVP_PKEY_decrypt_init(cctx))
		goto done;

	if (!EVP_PKEY_decrypt(cctx, plaintext, &ptext_len, ciphertext, ctext_len))
		goto done;

	if (ptext_len != sizeof(kMsg))
		goto done;

	if (memcmp(plaintext, kMsg, sizeof(kMsg)) != 0)
		goto done;

	ret = 1;
done:
	EVP_PKEY_CTX_free(pctx);
	EVP_PKEY_CTX_free(kctx);
	EVP_PKEY_CTX_free(cctx);
	EVP_PKEY_free(pkey);
	EVP_PKEY_free(params);
	EVP_MD_CTX_free(md_ctx);
	EVP_MD_CTX_free(md_ctx_verify);
	free(sig);
	return ret;
}

int main(int argc, char *argv[])
{
	return test_EVP_SM2();
}

#endif
