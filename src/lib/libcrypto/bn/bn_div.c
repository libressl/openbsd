/* $OpenBSD: bn_div.c,v 1.31 2023/01/18 05:29:48 jsing Exp $ */
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

#include <openssl/opensslconf.h>

#include <openssl/bn.h>
#include <openssl/err.h>

#include "bn_local.h"

BN_ULONG bn_div_3_words(const BN_ULONG *m, BN_ULONG d1, BN_ULONG d0);

#ifndef BN_DIV3W

#if !defined(OPENSSL_NO_ASM) && !defined(OPENSSL_NO_INLINE_ASM)
# if defined(__GNUC__) && __GNUC__>=2
#  if defined(__i386) || defined (__i386__)
   /*
    * There were two reasons for implementing this template:
    * - GNU C generates a call to a function (__udivdi3 to be exact)
    *   in reply to ((((BN_ULLONG)n0)<<BN_BITS2)|n1)/d0 (I fail to
    *   understand why...);
    * - divl doesn't only calculate quotient, but also leaves
    *   remainder in %edx which we can definitely use here:-)
    *
    *					<appro@fy.chalmers.se>
    */
#undef bn_div_words
#  define bn_div_words(n0,n1,d0)		\
	({  asm volatile (			\
		"divl	%4"			\
		: "=a"(q), "=d"(rem)		\
		: "a"(n1), "d"(n0), "g"(d0)	\
		: "cc");			\
	    q;					\
	})
#  define REMAINDER_IS_ALREADY_CALCULATED
#  elif defined(__x86_64)
   /*
    * Same story here, but it's 128-bit by 64-bit division. Wow!
    *					<appro@fy.chalmers.se>
    */
#  undef bn_div_words
#  define bn_div_words(n0,n1,d0)		\
	({  asm volatile (			\
		"divq	%4"			\
		: "=a"(q), "=d"(rem)		\
		: "a"(n1), "d"(n0), "g"(d0)	\
		: "cc");			\
	    q;					\
	})
#  define REMAINDER_IS_ALREADY_CALCULATED
#  endif /* __<cpu> */
# endif /* __GNUC__ */
#endif /* OPENSSL_NO_ASM */

/*
 * Interface is somewhat quirky, |m| is pointer to most significant limb,
 * and less significant limb is referred at |m[-1]|. This means that caller
 * is responsible for ensuring that |m[-1]| is valid. Second condition that
 * has to be met is that |d0|'s most significant bit has to be set. Or in
 * other words divisor has to be "bit-aligned to the left." The subroutine
 * considers four limbs, two of which are "overlapping," hence the name...
 */
BN_ULONG
bn_div_3_words(const BN_ULONG *m, BN_ULONG d1, BN_ULONG d0)
{
	BN_ULONG n0, n1, q;
	BN_ULONG rem = 0;

	n0 = m[0];
	n1 = m[-1];

	if (n0 == d0)
		return BN_MASK2;

	/* n0 < d0 */
	{
#ifdef BN_LLONG
		BN_ULLONG t2;

#if defined(BN_DIV2W) && !defined(bn_div_words)
		q = (BN_ULONG)((((BN_ULLONG)n0 << BN_BITS2) | n1) / d0);
#else
		q = bn_div_words(n0, n1, d0);
#endif

#ifndef REMAINDER_IS_ALREADY_CALCULATED
		/*
		 * rem doesn't have to be BN_ULLONG. The least we
		 * know it's less that d0, isn't it?
		 */
		rem = (n1 - q * d0) & BN_MASK2;
#endif
		t2 = (BN_ULLONG)d1 * q;

		for (;;) {
			if (t2 <= (((BN_ULLONG)rem << BN_BITS2) | m[-2]))
				break;
			q--;
			rem += d0;
			if (rem < d0) break; /* don't let rem overflow */
				t2 -= d1;
		}
#else /* !BN_LLONG */
		BN_ULONG t2l, t2h;

		q = bn_div_words(n0, n1, d0);
#ifndef REMAINDER_IS_ALREADY_CALCULATED
		rem = (n1 - q * d0) & BN_MASK2;
#endif

#if defined(BN_UMULT_LOHI)
		BN_UMULT_LOHI(t2l, t2h, d1, q);
#elif defined(BN_UMULT_HIGH)
		t2l = d1 * q;
		t2h = BN_UMULT_HIGH(d1, q);
#else
		{
			BN_ULONG ql, qh;
			t2l = LBITS(d1);
			t2h = HBITS(d1);
			ql = LBITS(q);
			qh = HBITS(q);
			mul64(t2l, t2h, ql, qh); /* t2 = (BN_ULLONG)d1 * q; */
		}
#endif

		for (;;) {
			if (t2h < rem || (t2h == rem && t2l <= m[-2]))
				break;
			q--;
			rem += d0;
			if (rem < d0)
				break; /* don't let rem overflow */
			if (t2l < d1)
				t2h--;
			t2l -= d1;
		}
#endif /* !BN_LLONG */
	}

	return q;
}
#endif /* !BN_DIV3W */

/*
 * BN_div_internal computes quotient := numerator / divisor, rounding towards
 * zero and setting remainder such that quotient * divisor + remainder equals
 * the numerator. Thus:
 *
 *   quotient->neg  == numerator->neg ^ divisor->neg   (unless result is zero)
 *   remainder->neg == numerator->neg           (unless the remainder is zero)
 *
 * If either the quotient or remainder is NULL, the respective value is not
 * returned.
 */
static int
BN_div_internal(BIGNUM *quotient, BIGNUM *remainder, const BIGNUM *numerator,
    const BIGNUM *divisor, BN_CTX *ctx, int ct)
{
	int norm_shift, i, loop;
	BIGNUM *tmp, wnum, *snum, *sdiv, *res;
	BN_ULONG *resp, *wnump;
	BN_ULONG d0, d1;
	int num_n, div_n;
	int no_branch = 0;
	int ret = 0;

	BN_CTX_start(ctx);

	/* Invalid zero-padding would have particularly bad consequences. */
	if (numerator->top > 0 && numerator->d[numerator->top - 1] == 0) {
		BNerror(BN_R_NOT_INITIALIZED);
		goto err;
	}

	if (ct)
		no_branch = 1;

	if (BN_is_zero(divisor)) {
		BNerror(BN_R_DIV_BY_ZERO);
		goto err;
	}

	if (!no_branch) {
		if (BN_ucmp(numerator, divisor) < 0) {
			if (remainder != NULL) {
				if (BN_copy(remainder, numerator) == NULL)
					goto err;
			}
			if (quotient != NULL)
				BN_zero(quotient);

			goto done;
		}
	}

	if ((tmp = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((snum = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((sdiv = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((res = quotient) == NULL) {
		if ((res = BN_CTX_get(ctx)) == NULL)
			goto err;
	}

	/* First we normalise the numbers. */
	norm_shift = BN_BITS2 - BN_num_bits(divisor) % BN_BITS2;
	if (!BN_lshift(sdiv, divisor, norm_shift))
		goto err;
	sdiv->neg = 0;
	norm_shift += BN_BITS2;
	if (!BN_lshift(snum, numerator, norm_shift))
		goto err;
	snum->neg = 0;

	if (no_branch) {
		/*
		 * Since we don't know whether snum is larger than sdiv, we pad
		 * snum with enough zeroes without changing its value.
		 */
		if (snum->top <= sdiv->top + 1) {
			if (!bn_wexpand(snum, sdiv->top + 2))
				goto err;
			for (i = snum->top; i < sdiv->top + 2; i++)
				snum->d[i] = 0;
			snum->top = sdiv->top + 2;
		} else {
			if (!bn_wexpand(snum, snum->top + 1))
				goto err;
			snum->d[snum->top] = 0;
			snum->top++;
		}
	}

	div_n = sdiv->top;
	num_n = snum->top;
	loop = num_n - div_n;

	/*
	 * Setup a 'window' into snum - this is the part that corresponds to the
	 * current 'area' being divided.
	 */
	wnum.neg = 0;
	wnum.d = &(snum->d[loop]);
	wnum.top = div_n;
	/* only needed when BN_ucmp messes up the values between top and max */
	wnum.dmax  = snum->dmax - loop; /* so we don't step out of bounds */
	wnum.flags = snum->flags | BN_FLG_STATIC_DATA;

	/* Get the top 2 words of sdiv */
	/* div_n=sdiv->top; */
	d0 = sdiv->d[div_n - 1];
	d1 = (div_n == 1) ? 0 : sdiv->d[div_n - 2];

	/* pointer to the 'top' of snum */
	wnump = &(snum->d[num_n - 1]);

	/* Setup to 'res' */
	res->neg = (numerator->neg ^ divisor->neg);
	if (!bn_wexpand(res, (loop + 1)))
		goto err;
	res->top = loop - no_branch;
	resp = &(res->d[loop - 1]);

	/* space for temp */
	if (!bn_wexpand(tmp, (div_n + 1)))
		goto err;

	if (!no_branch) {
		if (BN_ucmp(&wnum, sdiv) >= 0) {
			bn_sub_words(wnum.d, wnum.d, sdiv->d, div_n);
			*resp = 1;
		} else
			res->top--;
	}

	/*
	 * If res->top == 0 then clear the neg value otherwise decrease the resp
	 * pointer.
	 */
	if (res->top == 0)
		res->neg = 0;
	else
		resp--;

	for (i = 0; i < loop - 1; i++, wnump--, resp--) {
		BN_ULONG q, l0;

		/*
		 * The first part of the loop uses the top two words of snum and
		 * sdiv to calculate a BN_ULONG q such that:
		 *
		 *  | wnum - sdiv * q | < sdiv
		 */
		q = bn_div_3_words(wnump, d1, d0);
		l0 = bn_mul_words(tmp->d, sdiv->d, div_n, q);
		tmp->d[div_n] = l0;
		wnum.d--;

		/*
		 * Ignore top values of the bignums just sub the two BN_ULONG
		 * arrays with bn_sub_words.
		 */
		if (bn_sub_words(wnum.d, wnum.d, tmp->d, div_n + 1)) {
			/*
			 * Note: As we have considered only the leading two
			 * BN_ULONGs in the calculation of q, sdiv * q might be
			 * greater than wnum (but then (q-1) * sdiv is less or
			 * equal than wnum).
			 */
			q--;
			if (bn_add_words(wnum.d, wnum.d, sdiv->d, div_n)) {
				/*
				 * We can't have an overflow here (assuming
				 * that q != 0, but if q == 0 then tmp is
				 * zero anyway).
				 */
				(*wnump)++;
			}
		}
		/* store part of the result */
		*resp = q;
	}

	bn_correct_top(snum);

	if (remainder != NULL) {
		/*
		 * Keep a copy of the neg flag in numerator because if
		 * remainder == numerator, BN_rshift() will overwrite it.
		 */
		int neg = numerator->neg;

		BN_rshift(remainder, snum, norm_shift);
		if (!BN_is_zero(remainder))
			remainder->neg = neg;
	}

	if (no_branch)
		bn_correct_top(res);

 done:
	ret = 1;
 err:
	BN_CTX_end(ctx);

	return ret;
}

int
BN_div(BIGNUM *quotient, BIGNUM *remainder, const BIGNUM *numerator,
    const BIGNUM *divisor, BN_CTX *ctx)
{
	int ct;

	ct = BN_get_flags(numerator, BN_FLG_CONSTTIME) != 0 ||
	    BN_get_flags(divisor, BN_FLG_CONSTTIME) != 0;

	return BN_div_internal(quotient, remainder, numerator, divisor, ctx, ct);
}

int
BN_div_nonct(BIGNUM *quotient, BIGNUM *remainder, const BIGNUM *numerator,
    const BIGNUM *divisor, BN_CTX *ctx)
{
	return BN_div_internal(quotient, remainder, numerator, divisor, ctx, 0);
}

int
BN_div_ct(BIGNUM *quotient, BIGNUM *remainder, const BIGNUM *numerator,
    const BIGNUM *divisor, BN_CTX *ctx)
{
	return BN_div_internal(quotient, remainder, numerator, divisor, ctx, 1);
}
