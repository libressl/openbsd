/* $OpenBSD: x_attrib.c,v 1.11 2015/02/10 04:21:50 jsing Exp $ */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#include <stdio.h>

#include <openssl/asn1t.h>
#include <openssl/objects.h>
#include <openssl/x509.h>

/* X509_ATTRIBUTE: this has the following form:
 *
 * typedef struct x509_attributes_st
 *	{
 *	ASN1_OBJECT *object;
 *	int single;
 *	union	{
 *		char		*ptr;
 * 		STACK_OF(ASN1_TYPE) *set;
 * 		ASN1_TYPE	*single;
 *		} value;
 *	} X509_ATTRIBUTE;
 *
 * this needs some extra thought because the CHOICE type is
 * merged with the main structure and because the value can
 * be anything at all we *must* try the SET OF first because
 * the ASN1_ANY type will swallow anything including the whole
 * SET OF structure.
 */

ASN1_CHOICE(X509_ATTRIBUTE_SET) = {
	ASN1_SET_OF(X509_ATTRIBUTE, value.set, ASN1_ANY),
	ASN1_SIMPLE(X509_ATTRIBUTE, value.single, ASN1_ANY)
} ASN1_CHOICE_END_selector(X509_ATTRIBUTE, X509_ATTRIBUTE_SET, single)

ASN1_SEQUENCE(X509_ATTRIBUTE) = {
	ASN1_SIMPLE(X509_ATTRIBUTE, object, ASN1_OBJECT),
	/* CHOICE type merged with parent */
	ASN1_EX_COMBINE(0, 0, X509_ATTRIBUTE_SET)
} ASN1_SEQUENCE_END(X509_ATTRIBUTE)


X509_ATTRIBUTE *
d2i_X509_ATTRIBUTE(X509_ATTRIBUTE **a, const unsigned char **in, long len)
{
	return (X509_ATTRIBUTE *)ASN1_item_d2i((ASN1_VALUE **)a, in, len,
	    &X509_ATTRIBUTE_it);
}

int
i2d_X509_ATTRIBUTE(X509_ATTRIBUTE *a, unsigned char **out)
{
	return ASN1_item_i2d((ASN1_VALUE *)a, out, &X509_ATTRIBUTE_it);
}

X509_ATTRIBUTE *
X509_ATTRIBUTE_new(void)
{
	return (X509_ATTRIBUTE *)ASN1_item_new(&X509_ATTRIBUTE_it);
}

void
X509_ATTRIBUTE_free(X509_ATTRIBUTE *a)
{
	ASN1_item_free((ASN1_VALUE *)a, &X509_ATTRIBUTE_it);
}

X509_ATTRIBUTE *
X509_ATTRIBUTE_dup(X509_ATTRIBUTE *x)
{
	return ASN1_item_dup(ASN1_ITEM_rptr(X509_ATTRIBUTE), x);
}

X509_ATTRIBUTE *
X509_ATTRIBUTE_create(int nid, int atrtype, void *value)
{
	X509_ATTRIBUTE *ret = NULL;
	ASN1_TYPE *val = NULL;

	if ((ret = X509_ATTRIBUTE_new()) == NULL)
		return (NULL);
	ret->object = OBJ_nid2obj(nid);
	ret->single = 0;
	if ((ret->value.set = sk_ASN1_TYPE_new_null()) == NULL)
		goto err;
	if ((val = ASN1_TYPE_new()) == NULL)
		goto err;
	if (!sk_ASN1_TYPE_push(ret->value.set, val))
		goto err;

	ASN1_TYPE_set(val, atrtype, value);
	return (ret);

err:
	if (ret != NULL)
		X509_ATTRIBUTE_free(ret);
	if (val != NULL)
		ASN1_TYPE_free(val);
	return (NULL);
}
