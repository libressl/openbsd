/* $OpenBSD: evp_pkey.c,v 1.30 2024/07/14 16:06:31 tb Exp $ */
/* Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project 1999.
 */
/* ====================================================================
 * Copyright (c) 1999-2005 The OpenSSL Project.  All rights reserved.
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
 *    licensing@OpenSSL.org.
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

#include <stdio.h>
#include <stdlib.h>

#include <openssl/err.h>
#include <openssl/x509.h>

#include "asn1_local.h"
#include "evp_local.h"

/* Extract a private key from a PKCS8 structure */

EVP_PKEY *
EVP_PKCS82PKEY(const PKCS8_PRIV_KEY_INFO *p8)
{
	EVP_PKEY *pkey = NULL;
	const ASN1_OBJECT *algoid;
	char obj_tmp[80];

	if (!PKCS8_pkey_get0(&algoid, NULL, NULL, NULL, p8))
		return NULL;

	if (!(pkey = EVP_PKEY_new())) {
		EVPerror(ERR_R_MALLOC_FAILURE);
		return NULL;
	}

	if (!EVP_PKEY_set_type(pkey, OBJ_obj2nid(algoid))) {
		EVPerror(EVP_R_UNSUPPORTED_PRIVATE_KEY_ALGORITHM);
		i2t_ASN1_OBJECT(obj_tmp, 80, algoid);
		ERR_asprintf_error_data("TYPE=%s", obj_tmp);
		goto error;
	}

	if (pkey->ameth->priv_decode) {
		if (!pkey->ameth->priv_decode(pkey, p8)) {
			EVPerror(EVP_R_PRIVATE_KEY_DECODE_ERROR);
			goto error;
		}
	} else {
		EVPerror(EVP_R_METHOD_NOT_SUPPORTED);
		goto error;
	}

	return pkey;

error:
	EVP_PKEY_free(pkey);
	return NULL;
}
LCRYPTO_ALIAS(EVP_PKCS82PKEY);

/* Turn a private key into a PKCS8 structure */

PKCS8_PRIV_KEY_INFO *
EVP_PKEY2PKCS8(EVP_PKEY *pkey)
{
	PKCS8_PRIV_KEY_INFO *p8;

	if (!(p8 = PKCS8_PRIV_KEY_INFO_new())) {
		EVPerror(ERR_R_MALLOC_FAILURE);
		return NULL;
	}

	if (pkey->ameth) {
		if (pkey->ameth->priv_encode) {
			if (!pkey->ameth->priv_encode(p8, pkey)) {
				EVPerror(EVP_R_PRIVATE_KEY_ENCODE_ERROR);
				goto error;
			}
		} else {
			EVPerror(EVP_R_METHOD_NOT_SUPPORTED);
			goto error;
		}
	} else {
		EVPerror(EVP_R_UNSUPPORTED_PRIVATE_KEY_ALGORITHM);
		goto error;
	}
	return p8;

error:
	PKCS8_PRIV_KEY_INFO_free(p8);
	return NULL;
}
LCRYPTO_ALIAS(EVP_PKEY2PKCS8);

/*
 * XXX - This is only used by openssl(1) pkcs12 for the Microsoft-specific
 * NID_ms_csp_name and NID_LocalKeySet. This turns out to be the only reason
 * why attributes hangs off the EVP_PKEY struct.
 */
int
EVP_PKEY_add1_attr_by_NID(EVP_PKEY *pkey, int nid, int type,
    const unsigned char *bytes, int len)
{
	STACK_OF(X509_ATTRIBUTE) *attrs = NULL;
	X509_ATTRIBUTE *attr = NULL;
	int ret = 0;

	if ((attr = X509_ATTRIBUTE_create_by_NID(NULL, nid, type,
	    bytes, len)) == NULL)
		goto err;

	if ((attrs = pkey->attributes) == NULL)
		attrs = sk_X509_ATTRIBUTE_new_null();
	if (attrs == NULL)
		goto err;

	if (sk_X509_ATTRIBUTE_push(attrs, attr) <= 0)
		goto err;
	attr = NULL;

	pkey->attributes = attrs;
	attrs = NULL;

	ret = 1;

 err:
	X509_ATTRIBUTE_free(attr);
	if (attrs != pkey->attributes)
		sk_X509_ATTRIBUTE_pop_free(attrs, X509_ATTRIBUTE_free);

	return ret;
}
LCRYPTO_ALIAS(EVP_PKEY_add1_attr_by_NID);

/*
 * XXX - delete all the garbage below in the next bump.
 */

int
EVP_PKEY_get_attr_count(const EVP_PKEY *key)
{
	EVPerror(ERR_R_DISABLED);
	return 0;
}
LCRYPTO_ALIAS(EVP_PKEY_get_attr_count);

int
EVP_PKEY_get_attr_by_NID(const EVP_PKEY *key, int nid, int lastpos)
{
	EVPerror(ERR_R_DISABLED);
	return -1;
}
LCRYPTO_ALIAS(EVP_PKEY_get_attr_by_NID);

int
EVP_PKEY_get_attr_by_OBJ(const EVP_PKEY *key, const ASN1_OBJECT *obj,
    int lastpos)
{
	EVPerror(ERR_R_DISABLED);
	return -1;
}
LCRYPTO_ALIAS(EVP_PKEY_get_attr_by_OBJ);

X509_ATTRIBUTE *
EVP_PKEY_get_attr(const EVP_PKEY *key, int loc)
{
	EVPerror(ERR_R_DISABLED);
	return NULL;
}
LCRYPTO_ALIAS(EVP_PKEY_get_attr);

X509_ATTRIBUTE *
EVP_PKEY_delete_attr(EVP_PKEY *key, int loc)
{
	EVPerror(ERR_R_DISABLED);
	return NULL;
}
LCRYPTO_ALIAS(EVP_PKEY_delete_attr);

int
EVP_PKEY_add1_attr(EVP_PKEY *key, X509_ATTRIBUTE *attr)
{
	EVPerror(ERR_R_DISABLED);
	return 0;
}
LCRYPTO_ALIAS(EVP_PKEY_add1_attr);

int
EVP_PKEY_add1_attr_by_OBJ(EVP_PKEY *key, const ASN1_OBJECT *obj, int type,
    const unsigned char *bytes, int len)
{
	EVPerror(ERR_R_DISABLED);
	return 0;
}
LCRYPTO_ALIAS(EVP_PKEY_add1_attr_by_OBJ);

int
EVP_PKEY_add1_attr_by_txt(EVP_PKEY *key, const char *attrname, int type,
    const unsigned char *bytes, int len)
{
	EVPerror(ERR_R_DISABLED);
	return 0;
}
LCRYPTO_ALIAS(EVP_PKEY_add1_attr_by_txt);
