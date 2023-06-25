/* $OpenBSD: ecs_lib.c,v 1.21 2023/06/25 19:04:35 tb Exp $ */
/* ====================================================================
 * Copyright (c) 1998-2005 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <string.h>

#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif
#include <openssl/err.h>
#include <openssl/bn.h>

#include "ec_local.h"
#include "ecs_local.h"

static const ECDSA_METHOD *default_ECDSA_method = NULL;

static const ECDSA_METHOD openssl_ecdsa_meth = {
	.name = "OpenSSL ECDSA method",
	.ecdsa_do_sign = ossl_ecdsa_sign_sig,
	.ecdsa_sign_setup = ossl_ecdsa_sign_setup,
	.ecdsa_do_verify = ossl_ecdsa_verify_sig,
};

const ECDSA_METHOD *
ECDSA_OpenSSL(void)
{
	return &openssl_ecdsa_meth;
}

void
ECDSA_set_default_method(const ECDSA_METHOD *meth)
{
	default_ECDSA_method = meth;
}

const ECDSA_METHOD *
ECDSA_get_default_method(void)
{
	if (!default_ECDSA_method) {
		default_ECDSA_method = ECDSA_OpenSSL();
	}
	return default_ECDSA_method;
}

int
ECDSA_set_method(EC_KEY *eckey, const ECDSA_METHOD *meth)
{
	return 0;
}

int
ECDSA_size(const EC_KEY *r)
{
	BIGNUM *order = NULL;
	const EC_GROUP *group;
	ECDSA_SIG signature;
	int ret = 0;

	if (r == NULL)
		goto err;

	if ((group = EC_KEY_get0_group(r)) == NULL)
		goto err;

	if ((order = BN_new()) == NULL)
		goto err;

	if (!EC_GROUP_get_order(group, order, NULL))
		goto err;

	signature.r = order;
	signature.s = order;

	if ((ret = i2d_ECDSA_SIG(&signature, NULL)) < 0)
		ret = 0;

 err:
	BN_free(order);

	return ret;
}

int
ECDSA_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
    CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func)
{
	return -1;
}

int
ECDSA_set_ex_data(EC_KEY *d, int idx, void *arg)
{
	return 0;
}

void *
ECDSA_get_ex_data(EC_KEY *d, int idx)
{
	return NULL;
}
