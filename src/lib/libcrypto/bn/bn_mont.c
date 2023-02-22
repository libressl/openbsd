/* $OpenBSD: bn_mont.c,v 1.46 2023/02/22 06:00:24 jsing Exp $ */
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
/* ====================================================================
 * Copyright (c) 1998-2006 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
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

/*
 * Details about Montgomery multiplication algorithms can be found at
 * http://security.ece.orst.edu/publications.html, e.g.
 * http://security.ece.orst.edu/koc/papers/j37acmon.pdf and
 * sections 3.8 and 4.2 in http://security.ece.orst.edu/koc/papers/r01rsasw.pdf
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "bn_internal.h"
#include "bn_local.h"

BN_MONT_CTX *
BN_MONT_CTX_new(void)
{
	BN_MONT_CTX *mctx;

	if ((mctx = calloc(1, sizeof(BN_MONT_CTX))) == NULL)
		return NULL;
	mctx->flags = BN_FLG_MALLOCED;

	BN_init(&mctx->RR);
	BN_init(&mctx->N);

	return mctx;
}

void
BN_MONT_CTX_init(BN_MONT_CTX *mctx)
{
	memset(mctx, 0, sizeof(*mctx));

	BN_init(&mctx->RR);
	BN_init(&mctx->N);
}

void
BN_MONT_CTX_free(BN_MONT_CTX *mctx)
{
	if (mctx == NULL)
		return;

	BN_free(&mctx->RR);
	BN_free(&mctx->N);

	if (mctx->flags & BN_FLG_MALLOCED)
		free(mctx);
}

BN_MONT_CTX *
BN_MONT_CTX_copy(BN_MONT_CTX *dst, BN_MONT_CTX *src)
{
	if (dst == src)
		return dst;

	if (!BN_copy(&dst->RR, &src->RR))
		return NULL;
	if (!BN_copy(&dst->N, &src->N))
		return NULL;

	dst->ri = src->ri;
	dst->n0[0] = src->n0[0];
	dst->n0[1] = src->n0[1];

	return dst;
}

int
BN_MONT_CTX_set(BN_MONT_CTX *mont, const BIGNUM *mod, BN_CTX *ctx)
{
	BIGNUM *N, *Ninv, *Rinv, *R;
	int ret = 0;

	BN_CTX_start(ctx);

	if ((N = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((Ninv = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((R = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((Rinv = BN_CTX_get(ctx)) == NULL)
		goto err;

	/* Save modulus and determine length of R. */
	if (BN_is_zero(mod))
		goto err;
	if (!BN_copy(&mont->N, mod))
		 goto err;
	mont->N.neg = 0;
	mont->ri = ((BN_num_bits(mod) + BN_BITS2 - 1) / BN_BITS2) * BN_BITS2;
	if (mont->ri * 2 < mont->ri)
		goto err;

	/*
	 * Compute Ninv = (R * Rinv - 1)/N mod R, for R = 2^64. This provides
	 * a single or double word result (dependent on BN word size), that is
	 * later used to implement Montgomery reduction.
	 */
	BN_zero(R);
	if (!BN_set_bit(R, 64))
		goto err;

	/* N = N mod R. */
	if (!bn_wexpand(N, 2))
		goto err;
	if (!BN_set_word(N, mod->d[0]))
		goto err;
#if BN_BITS2 == 32
	if (mod->top > 1) {
		N->d[1] = mod->d[1];
		N->top += bn_ct_ne_zero(N->d[1]);
	}
#endif

	/* Rinv = R^-1 mod N */
	if ((BN_mod_inverse_ct(Rinv, R, N, ctx)) == NULL)
		goto err;

	/* Ninv = (R * Rinv - 1) / N */
	if (!BN_lshift(Ninv, Rinv, 64))
		goto err;
	if (BN_is_zero(Ninv)) {
		/* R * Rinv == 0, set to R so that R * Rinv - 1 is mod R. */
		if (!BN_set_bit(Ninv, 64))
			goto err;
	}
	if (!BN_sub_word(Ninv, 1))
		goto err;
	if (!BN_div_ct(Ninv, NULL, Ninv, N, ctx))
		goto err;

	/* Store least significant word(s) of Ninv. */
	mont->n0[0] = mont->n0[1] = 0;
	if (Ninv->top > 0)
		mont->n0[0] = Ninv->d[0];
#if BN_BITS2 == 32
	/* Some BN_BITS2 == 32 platforms (namely parisc) use two words of Ninv. */
	if (Ninv->top > 1)
		mont->n0[1] = Ninv->d[1];
#endif

	/* Compute RR = R * R mod N, for use when converting to Montgomery form. */
	BN_zero(&mont->RR);
	if (!BN_set_bit(&mont->RR, mont->ri * 2))
		goto err;
	if (!BN_mod_ct(&mont->RR, &mont->RR, &mont->N, ctx))
		goto err;

	ret = 1;
 err:
	BN_CTX_end(ctx);

	return ret;
}

BN_MONT_CTX *
BN_MONT_CTX_set_locked(BN_MONT_CTX **pmctx, int lock, const BIGNUM *mod,
    BN_CTX *ctx)
{
	BN_MONT_CTX *mctx = NULL;

	CRYPTO_r_lock(lock);
	mctx = *pmctx;
	CRYPTO_r_unlock(lock);

	if (mctx != NULL)
		goto done;

	if ((mctx = BN_MONT_CTX_new()) == NULL)
		goto err;
	if (!BN_MONT_CTX_set(mctx, mod, ctx))
		goto err;

	CRYPTO_w_lock(lock);
	if (*pmctx != NULL) {
		/* Someone else raced us... */
		BN_MONT_CTX_free(mctx);
		mctx = *pmctx;
	} else {
		*pmctx = mctx;
	}
	CRYPTO_w_unlock(lock);

	goto done;
 err:
	BN_MONT_CTX_free(mctx);
	mctx = NULL;
 done:
	return mctx;
}

#ifdef OPENSSL_NO_ASM
#ifdef OPENSSL_BN_ASM_MONT
int
bn_mul_mont(BN_ULONG *rp, const BN_ULONG *ap, const BN_ULONG *bp,
    const BN_ULONG *np, const BN_ULONG *n0p, int num)
{
	BN_ULONG c0, c1, *tp, n0 = *n0p;
	int i = 0, j;

	tp = calloc(num + 2, sizeof(BN_ULONG));
	if (tp == NULL)
		return 0;

	for (i = 0; i < num; i++) {
		c0 = bn_mul_add_words(tp, ap, num, bp[i]);
		c1 = (tp[num] + c0) & BN_MASK2;
		tp[num] = c1;
		tp[num + 1] = (c1 < c0 ? 1 : 0);

		c0 = bn_mul_add_words(tp, np, num, tp[0] * n0);
		c1 = (tp[num] + c0) & BN_MASK2;
		tp[num] = c1;
		tp[num + 1] += (c1 < c0 ? 1 : 0);
		for (j = 0; j <= num; j++)
			tp[j] = tp[j + 1];
	}

	if (tp[num] != 0 || tp[num - 1] >= np[num - 1]) {
		c0 = bn_sub_words(rp, tp, np, num);
		if (tp[num] != 0 || c0 == 0) {
			goto out;
		}
	}
	memcpy(rp, tp, num * sizeof(BN_ULONG));
out:
	freezero(tp, (num + 2) * sizeof(BN_ULONG));
	return 1;
}
#else /* !OPENSSL_BN_ASM_MONT */
int
bn_mul_mont(BN_ULONG *rp, const BN_ULONG *ap, const BN_ULONG *bp,
    const BN_ULONG *np, const BN_ULONG *n0, int num)
{
	/*
	 * Return value of 0 indicates that multiplication/convolution was not
	 * performed to signal the caller to fall down to alternative/original
	 * code-path.
	 */
	return 0;
}
#endif /* !OPENSSL_BN_ASM_MONT */
#endif /* OPENSSL_NO_ASM */

static int BN_from_montgomery_word(BIGNUM *ret, BIGNUM *r, BN_MONT_CTX *mont);

int
BN_mod_mul_montgomery(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
    BN_MONT_CTX *mont, BN_CTX *ctx)
{
	BIGNUM *tmp;
	int ret = 0;

#if defined(OPENSSL_BN_ASM_MONT)
	int num = mont->N.top;

	if (num > 1 && a->top == num && b->top == num) {
		if (!bn_wexpand(r, num))
			return (0);
		if (bn_mul_mont(r->d, a->d, b->d, mont->N.d, mont->n0, num)) {
			r->top = num;
			bn_correct_top(r);
			BN_set_negative(r, a->neg ^ b->neg);
			return (1);
		}
	}
#endif

	BN_CTX_start(ctx);
	if ((tmp = BN_CTX_get(ctx)) == NULL)
		goto err;

	if (a == b) {
		if (!BN_sqr(tmp, a, ctx))
			goto err;
	} else {
		if (!BN_mul(tmp, a,b, ctx))
			goto err;
	}
	/* reduce from aRR to aR */
	if (!BN_from_montgomery_word(r, tmp, mont))
		goto err;
	ret = 1;
err:
	BN_CTX_end(ctx);
	return (ret);
}

int
BN_to_montgomery(BIGNUM *r, const BIGNUM *a, BN_MONT_CTX *mont, BN_CTX *ctx)
{
	/* Compute r = a * R * R * R^-1 mod N = aR mod N */
	return BN_mod_mul_montgomery(r, a, &mont->RR, mont, ctx);
}

static int
BN_from_montgomery_word(BIGNUM *ret, BIGNUM *r, BN_MONT_CTX *mont)
{
	BIGNUM *n;
	BN_ULONG *ap, *np, *rp, n0, v, carry;
	int nl, max, i;

	n = &(mont->N);
	nl = n->top;
	if (nl == 0) {
		ret->top = 0;
		return (1);
	}

	max = (2 * nl); /* carry is stored separately */
	if (!bn_wexpand(r, max))
		return (0);

	BN_set_negative(r, r->neg ^ n->neg);
	np = n->d;
	rp = r->d;

	/* clear the top words of T */
#if 1
	for (i=r->top; i<max; i++) /* memset? XXX */
		rp[i] = 0;
#else
	memset(&(rp[r->top]), 0, (max - r->top) * sizeof(BN_ULONG));
#endif

	r->top = max;
	n0 = mont->n0[0];

	for (carry = 0, i = 0; i < nl; i++, rp++) {
		v = bn_mul_add_words(rp, np, nl, (rp[0] * n0) & BN_MASK2);
		v = (v + carry + rp[nl]) & BN_MASK2;
		carry |= (v != rp[nl]);
		carry &= (v <= rp[nl]);
		rp[nl] = v;
	}

	if (!bn_wexpand(ret, nl))
		return (0);
	ret->top = nl;
	BN_set_negative(ret, r->neg);

	rp = ret->d;
	ap = &(r->d[nl]);

#define BRANCH_FREE 1
#if BRANCH_FREE
	{
		BN_ULONG *nrp;
		size_t m;

		v = bn_sub_words(rp, ap, np, nl) - carry;
		/* if subtraction result is real, then
		 * trick unconditional memcpy below to perform in-place
		 * "refresh" instead of actual copy. */
		m = (0 - (size_t)v);
		nrp = (BN_ULONG *)(((uintptr_t)rp & ~m)|((uintptr_t)ap & m));

		for (i = 0, nl -= 4; i < nl; i += 4) {
			BN_ULONG t1, t2, t3, t4;

			t1 = nrp[i + 0];
			t2 = nrp[i + 1];
			t3 = nrp[i + 2];
			ap[i + 0] = 0;
			t4 = nrp[i + 3];
			ap[i + 1] = 0;
			rp[i + 0] = t1;
			ap[i + 2] = 0;
			rp[i + 1] = t2;
			ap[i + 3] = 0;
			rp[i + 2] = t3;
			rp[i + 3] = t4;
		}
		for (nl += 4; i < nl; i++)
			rp[i] = nrp[i], ap[i] = 0;
	}
#else
	if (bn_sub_words (rp, ap, np, nl) - carry)
		memcpy(rp, ap, nl*sizeof(BN_ULONG));
#endif
	bn_correct_top(r);
	bn_correct_top(ret);

	return (1);
}

int
BN_from_montgomery(BIGNUM *ret, const BIGNUM *a, BN_MONT_CTX *mont, BN_CTX *ctx)
{
	int retn = 0;
	BIGNUM *t;

	BN_CTX_start(ctx);
	if ((t = BN_CTX_get(ctx)) && BN_copy(t, a))
		retn = BN_from_montgomery_word(ret, t, mont);
	BN_CTX_end(ctx);
	return (retn);
}
