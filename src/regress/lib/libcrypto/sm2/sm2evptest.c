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
#include <openssl/pem.h>

#ifdef OPENSSL_NO_SM2
int main(int argc, char *argv[])
{
	printf("No SM2 support\n");
	return (0);
}
#else
static int test_EVP_SM2_verify(void)
{
	/* From https://tools.ietf.org/html/draft-shen-sm2-ecdsa-02#appendix-A */
	const char *pubkey =
		"-----BEGIN PUBLIC KEY-----\n"
		"MIIBMzCB7AYHKoZIzj0CATCB4AIBATAsBgcqhkjOPQEBAiEAhULWnkwETxjouSQ1\n"
		"v2/33kVyg5FcRVF9ci7biwjx38MwRAQgeHlotPoyw/0kF4Quc7v+/y88hItoMdfg\n"
		"7GUiizk35JgEIGPkxtOyOwyEnPhCQUhL/kj2HVmlsWugbm4S0donxSSaBEEEQh3r\n"
		"1hti6rZ0ZDTrw8wxXjIiCzut1QvcTE5sFH/t1D0GgFEry7QsB9RzSdIVO3DE5df9\n"
		"/L+jbqGoWEG55G4JogIhAIVC1p5MBE8Y6LkkNb9v990pdyBjBIVijVrnTufDLnm3\n"
		"AgEBA0IABArkx3mKoPEZRxvuEYJb5GICu3nipYRElel8BP9N8lSKfAJA+I8c1OFj\n"
		"Uqc8F7fxbwc1PlOhdtaEqf4Ma7eY6Fc=\n"
		"-----END PUBLIC KEY-----\n";

	const char *input = "message digest";
	const char *user_id = "ALICE123@YAHOO.COM";

	const uint8_t signature[] = {
		0x30, 0x44, 0x02, 0x20,
		0x40, 0xF1, 0xEC, 0x59, 0xF7, 0x93, 0xD9, 0xF4, 0x9E, 0x09, 0xDC,
		0xEF, 0x49, 0x13, 0x0D, 0x41, 0x94, 0xF7, 0x9F, 0xB1, 0xEE, 0xD2,
		0xCA, 0xA5, 0x5B, 0xAC, 0xDB, 0x49, 0xC4, 0xE7, 0x55, 0xD1,
		0x02, 0x20,
		0x6F, 0xC6, 0xDA, 0xC3, 0x2C, 0x5D, 0x5C, 0xF1, 0x0C, 0x77, 0xDF,
		0xB2, 0x0F, 0x7C, 0x2E, 0xB6, 0x67, 0xA4, 0x57, 0x87, 0x2F, 0xB0,
		0x9E, 0xC5, 0x63, 0x27, 0xA6, 0x7E, 0xC7, 0xDE, 0xEB, 0xE7
	};

	int rc = 0;
	BIO *bufio = NULL;
	EVP_PKEY *pkey = NULL;
	EVP_MD_CTX *md_ctx_verify = NULL;
	EVP_PKEY_CTX *verify_ctx = NULL;

	bufio = BIO_new_mem_buf(pubkey, strlen(pubkey));
	if (bufio == NULL)
		goto done;

	pkey = PEM_read_bio_PUBKEY(bufio, NULL, NULL, NULL);
	if (pkey == NULL)
		goto done;

	if (!EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2))
		goto done;

	md_ctx_verify = EVP_MD_CTX_new();
	if (md_ctx_verify == NULL)
		goto done;

	if (!EVP_DigestVerifyInit(md_ctx_verify, &verify_ctx, EVP_sm3(), NULL, pkey))
		goto done;

	if (!EVP_PKEY_CTX_set_sm2_uid(verify_ctx, user_id) > 0)
		goto done;

	if (!EVP_DigestVerifyInit(md_ctx_verify, NULL, EVP_sm3(), NULL, pkey))
		goto done;

	if (!EVP_DigestVerifyUpdate(md_ctx_verify, input, strlen(input)))
		goto done;

	if (!EVP_DigestVerifyFinal(md_ctx_verify, signature, sizeof(signature)))
		goto done;

	rc = 1;

done:
	BIO_free(bufio);
	EVP_PKEY_free(pkey);
	EVP_MD_CTX_free(md_ctx_verify);

	return rc;
}

static int test_EVP_SM2(void)
{
	int ret = 0;
	EVP_PKEY *pkey = NULL;
	EVP_PKEY *params = NULL;
	EVP_PKEY_CTX *pctx = NULL;
	EVP_PKEY_CTX *sign_ctx = NULL;
	EVP_PKEY_CTX *verify_ctx = NULL;
	EVP_PKEY_CTX *kctx = NULL;
	size_t sig_len = 0;
	unsigned char *sig = NULL;
	EVP_MD_CTX *md_ctx = NULL;
	EVP_MD_CTX *md_ctx_verify = NULL;
	EVP_PKEY_CTX *cctx = NULL;
	int useid;

	uint8_t ciphertext[128];
	size_t ctext_len = sizeof(ciphertext);

	uint8_t plaintext[8];
	size_t ptext_len = sizeof(plaintext);

	uint8_t kMsg[4] = {1, 2, 3, 4};

	char *uid_output = NULL;

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

	for (use_uid = 0; use_uid <= 1; ++use_uid) {
		if (!EVP_DigestSignInit(md_ctx, &sign_ctx, EVP_sm3(), NULL, pkey))
			goto done;

		if (use_uid) {
			if (EVP_PKEY_CTX_set_sm2_uid(sign_ctx, "nobody@example.com") <= 0)
				goto done;

			if (EVP_PKEY_CTX_get_sm2_uid(sign_ctx, &uid_output) <= 0)
				goto done;

			if (strcmp(uid_output, "nobody@example.com") != 0)
				goto done;

			if (!EVP_DigestSignInit(md_ctx, NULL, EVP_sm3(), NULL, pkey))
				goto done;
		}

		if(!EVP_DigestSignUpdate(md_ctx, kMsg, sizeof(kMsg)))
			goto done;

		/* Determine the size of the signature. */
		if (!EVP_DigestSignFinal(md_ctx, NULL, &sig_len))
			goto done;

		if (sig_len != (size_t) EVP_PKEY_size(pkey))
			goto done;

		sig = malloc(sig_len);
		if (sig == NULL)
			goto done;

		if (!EVP_DigestSignFinal(md_ctx, sig, &sig_len))
			goto done;

		/* Ensure that the signature round-trips. */

		if (!EVP_DigestVerifyInit(md_ctx_verify, &verify_ctx, EVP_sm3(), NULL, pkey))
			goto done;

		if (use_uid) {
			if (EVP_PKEY_CTX_set_sm2_uid(verify_ctx, "nobody@example.com") <= 0)
				goto done;

			if (EVP_PKEY_CTX_get_sm2_uid(sign_ctx, &uid_output) <= 0)
				goto done;

			if (strcmp(uid_output, "nobody@example.com") != 0)
				goto done;

			if (!EVP_DigestVerifyInit(md_ctx_verify, NULL, EVP_sm3(), NULL, pkey))
				goto done;
		}

		if (!EVP_DigestVerifyUpdate(md_ctx_verify, kMsg, sizeof(kMsg)))
			goto done;

		if (!EVP_DigestVerifyFinal(md_ctx_verify, sig, sig_len))
			goto done;
		
		free(sig);
		sig = NULL; 
	}

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
	EVP_PKEY_free(params);
	EVP_MD_CTX_free(md_ctx);
	EVP_MD_CTX_free(md_ctx_verify);
	EVP_PKEY_CTX_free(pctx);
	EVP_PKEY_CTX_free(kctx);
	EVP_PKEY_CTX_free(cctx);
	EVP_PKEY_free(pkey);
	free(sig);
	return ret;
}

int main(int argc, char *argv[])
{
	if (!test_EVP_SM2())
		return 1;
	if (!test_EVP_SM2_verify())
		return 1;
	
	return 0;
}

#endif
