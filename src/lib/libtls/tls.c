/* $OpenBSD: tls.c,v 1.94 2022/02/08 19:13:50 tb Exp $ */
/*
 * Copyright (c) 2014 Joel Sing <jsing@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
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

#include <sys/socket.h>

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/safestack.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <tls.h>
#include "tls_internal.h"

static struct tls_config *tls_config_default;

static int tls_init_rv = -1;

static void
tls_do_init(void)
{
	OPENSSL_init_ssl(OPENSSL_INIT_NO_LOAD_CONFIG, NULL);

	if (BIO_sock_init() != 1)
		return;

	if ((tls_config_default = tls_config_new_internal()) == NULL)
		return;

	tls_config_default->refcount++;

	tls_init_rv = 0;
}

static int
tls_keypair_to_pkey(struct tls *ctx, struct tls_keypair *keypair, EVP_PKEY **pkey)
{
	BIO *bio = NULL;
	X509 *x509 = NULL;
	char *mem;
	size_t len;
	int ret = -1;

	*pkey = NULL;

	if (ctx->config->use_fake_private_key) {
		mem = keypair->cert_mem;
		len = keypair->cert_len;
	} else {
		mem = keypair->key_mem;
		len = keypair->key_len;
	}

	if (mem == NULL)
		return (0);

	if (len > INT_MAX) {
		tls_set_errorx(ctx, ctx->config->use_fake_private_key ?
		    "cert too long" : "key too long");
		goto err;
	}

	if ((bio = BIO_new_mem_buf(mem, len)) == NULL) {
		tls_set_errorx(ctx, "failed to create buffer");
		goto err;
	}

	if (ctx->config->use_fake_private_key) {
		if ((x509 = PEM_read_bio_X509(bio, NULL, tls_password_cb,
		    NULL)) == NULL) {
			tls_set_errorx(ctx, "failed to read X509 certificate");
			goto err;
		}
		if ((*pkey = X509_get_pubkey(x509)) == NULL) {
			tls_set_errorx(ctx, "failed to retrieve pubkey");
			goto err;
		}
	} else {
		if ((*pkey = PEM_read_bio_PrivateKey(bio, NULL, tls_password_cb,
		    NULL)) ==  NULL) {
			tls_set_errorx(ctx, "failed to read private key");
			goto err;
		}
	}

	ret = 0;
 err:
	BIO_free(bio);
	X509_free(x509);
	return (ret);
}

static int
tls_keypair_setup_pkey(struct tls *ctx, struct tls_keypair *keypair, EVP_PKEY *pkey)
{
	RSA_METHOD *rsa_method;
	ECDSA_METHOD *ecdsa_method;
	RSA *rsa = NULL;
	EC_KEY *eckey = NULL;
	int ret = -1;

	/* Only install the pubkey hash if fake private keys are used. */
	if (!ctx->config->skip_private_key_check)
		return (0);

	if (keypair->pubkey_hash == NULL) {
		tls_set_errorx(ctx, "public key hash not set");
		goto err;
	}

	switch (EVP_PKEY_id(pkey)) {
	case EVP_PKEY_RSA:
		if ((rsa = EVP_PKEY_get1_RSA(pkey)) == NULL ||
		    RSA_set_ex_data(rsa, 0, keypair->pubkey_hash) == 0) {
			tls_set_errorx(ctx, "RSA key setup failure");
			goto err;
		}
		if (ctx->config->sign_cb == NULL)
			break;
		if ((rsa_method = tls_signer_rsa_method()) == NULL ||
		    RSA_set_ex_data(rsa, 1, ctx->config) == 0 ||
		    RSA_set_method(rsa, rsa_method) == 0) {
			tls_set_errorx(ctx, "failed to setup RSA key");
			goto err;
		}
		break;
	case EVP_PKEY_EC:
		if ((eckey = EVP_PKEY_get1_EC_KEY(pkey)) == NULL ||
		    ECDSA_set_ex_data(eckey, 0, keypair->pubkey_hash) == 0) {
			tls_set_errorx(ctx, "EC key setup failure");
			goto err;
		}
		if (ctx->config->sign_cb == NULL)
			break;
		if ((ecdsa_method = tls_signer_ecdsa_method()) == NULL ||
		    ECDSA_set_ex_data(eckey, 1, ctx->config) == 0 ||
		    ECDSA_set_method(eckey, ecdsa_method) == 0) {
			tls_set_errorx(ctx, "failed to setup EC key");
			goto err;
		}
		break;
	default:
		tls_set_errorx(ctx, "incorrect key type");
		goto err;
	}

	ret = 0;

 err:
	RSA_free(rsa);
	EC_KEY_free(eckey);
	return (ret);
}

static int
tls_ssl_cert_verify_cb(X509_STORE_CTX *x509_ctx, void *arg)
{
	struct tls *ctx = arg;
	int x509_err;

	if (ctx->config->verify_cert == 0)
		return (1);

	if ((X509_verify_cert(x509_ctx)) < 0) {
		tls_set_errorx(ctx, "X509 verify cert failed");
		return (0);
	}

	x509_err = X509_STORE_CTX_get_error(x509_ctx);
	if (x509_err == X509_V_OK)
		return (1);

	tls_set_errorx(ctx, "certificate verification failed: %s",
	    X509_verify_cert_error_string(x509_err));

	return (0);
}
