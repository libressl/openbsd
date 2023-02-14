/* $OpenBSD: bn_lib.c,v 1.76 2023/02/14 18:22:35 jsing Exp $ */
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

#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

#include <openssl/opensslconf.h>

#include <openssl/err.h>

#include "bn_local.h"
#include "bn_internal.h"

BIGNUM *
BN_new(void)
{
	BIGNUM *bn;

	if ((bn = calloc(1, sizeof(BIGNUM))) == NULL) {
		BNerror(ERR_R_MALLOC_FAILURE);
		return NULL;
	}
	bn->flags = BN_FLG_MALLOCED;

	return bn;
}

void
BN_init(BIGNUM *a)
{
	memset(a, 0, sizeof(BIGNUM));
}

void
BN_clear(BIGNUM *a)
{
	if (a->d != NULL)
		explicit_bzero(a->d, a->dmax * sizeof(a->d[0]));
	a->top = 0;
	a->neg = 0;
}

void
BN_free(BIGNUM *bn)
{
	if (bn == NULL)
		return;

	if (!BN_get_flags(bn, BN_FLG_STATIC_DATA))
		freezero(bn->d, bn->dmax * sizeof(bn->d[0]));

	if (!BN_get_flags(bn, BN_FLG_MALLOCED)) {
		explicit_bzero(bn, sizeof(*bn));
		return;
	}

	freezero(bn, sizeof(*bn));
}

void
BN_clear_free(BIGNUM *bn)
{
	BN_free(bn);
}

/* This stuff appears to be completely unused, so is deprecated */
#ifndef OPENSSL_NO_DEPRECATED
/* For a 32 bit machine
 * 2 -   4 ==  128
 * 3 -   8 ==  256
 * 4 -  16 ==  512
 * 5 -  32 == 1024
 * 6 -  64 == 2048
 * 7 - 128 == 4096
 * 8 - 256 == 8192
 */
static int bn_limit_bits = 0;
static int bn_limit_num = 8;        /* (1<<bn_limit_bits) */
static int bn_limit_bits_low = 0;
static int bn_limit_num_low = 8;    /* (1<<bn_limit_bits_low) */
static int bn_limit_bits_high = 0;
static int bn_limit_num_high = 8;   /* (1<<bn_limit_bits_high) */
static int bn_limit_bits_mont = 0;
static int bn_limit_num_mont = 8;   /* (1<<bn_limit_bits_mont) */

void
BN_set_params(int mult, int high, int low, int mont)
{
	if (mult >= 0) {
		if (mult > (int)(sizeof(int) * 8) - 1)
			mult = sizeof(int) * 8 - 1;
		bn_limit_bits = mult;
		bn_limit_num = 1 << mult;
	}
	if (high >= 0) {
		if (high > (int)(sizeof(int) * 8) - 1)
			high = sizeof(int) * 8 - 1;
		bn_limit_bits_high = high;
		bn_limit_num_high = 1 << high;
	}
	if (low >= 0) {
		if (low > (int)(sizeof(int) * 8) - 1)
			low = sizeof(int) * 8 - 1;
		bn_limit_bits_low = low;
		bn_limit_num_low = 1 << low;
	}
	if (mont >= 0) {
		if (mont > (int)(sizeof(int) * 8) - 1)
			mont = sizeof(int) * 8 - 1;
		bn_limit_bits_mont = mont;
		bn_limit_num_mont = 1 << mont;
	}
}

int
BN_get_params(int which)
{
	if (which == 0)
		return (bn_limit_bits);
	else if (which == 1)
		return (bn_limit_bits_high);
	else if (which == 2)
		return (bn_limit_bits_low);
	else if (which == 3)
		return (bn_limit_bits_mont);
	else
		return (0);
}
#endif

void
BN_set_flags(BIGNUM *b, int n)
{
	b->flags |= n;
}

int
BN_get_flags(const BIGNUM *b, int n)
{
	return b->flags & n;
}

void
BN_with_flags(BIGNUM *dest, const BIGNUM *b, int flags)
{
	int dest_flags;

	dest_flags = (dest->flags & BN_FLG_MALLOCED) |
	    (b->flags & ~BN_FLG_MALLOCED) | BN_FLG_STATIC_DATA | flags;

	*dest = *b;
	dest->flags = dest_flags;
}

const BIGNUM *
BN_value_one(void)
{
	static const BN_ULONG data_one = 1L;
	static const BIGNUM const_one = {
		(BN_ULONG *)&data_one, 1, 1, 0, BN_FLG_STATIC_DATA
	};

	return (&const_one);
}

#ifndef HAVE_BN_WORD_CLZ
int
bn_word_clz(BN_ULONG w)
{
	BN_ULONG bits, mask, shift;

	bits = shift = BN_BITS2;
	mask = 0;

	while ((shift >>= 1) != 0) {
		bits += (shift & mask) - (shift & ~mask);
		mask = bn_ct_ne_zero_mask(w >> bits);
	}
	bits += 1 & mask;

	bits -= bn_ct_eq_zero(w);

	return BN_BITS2 - bits;
}
#endif

int
BN_num_bits_word(BN_ULONG w)
{
	return BN_BITS2 - bn_word_clz(w);
}

int
BN_num_bits(const BIGNUM *a)
{
	int i = a->top - 1;

	if (BN_is_zero(a))
		return 0;
	return ((i * BN_BITS2) + BN_num_bits_word(a->d[i]));
}

void
bn_correct_top(BIGNUM *a)
{
	while (a->top > 0 && a->d[a->top - 1] == 0)
		a->top--;
}

static int
bn_expand_internal(BIGNUM *bn, int words)
{
	BN_ULONG *d;

	if (words < 0) {
		BNerror(BN_R_BIGNUM_TOO_LONG); // XXX
		return 0;
	}

	if (words > INT_MAX / (4 * BN_BITS2)) {
		BNerror(BN_R_BIGNUM_TOO_LONG);
		return 0;
	}
	if (BN_get_flags(bn, BN_FLG_STATIC_DATA)) {
		BNerror(BN_R_EXPAND_ON_STATIC_BIGNUM_DATA);
		return 0;
	}

	d = recallocarray(bn->d, bn->dmax, words, sizeof(BN_ULONG));
	if (d == NULL) {
		BNerror(ERR_R_MALLOC_FAILURE);
		return 0;
	}
	bn->d = d;
	bn->dmax = words;

	return 1;
}

int
bn_expand(BIGNUM *bn, int bits)
{
	int words;

	if (bits < 0)
		return 0;

	if (bits > (INT_MAX - BN_BITS2 + 1))
		return 0;

	words = (bits + BN_BITS2 - 1) / BN_BITS2;

	return bn_wexpand(bn, words);
}

int
bn_wexpand(BIGNUM *bn, int words)
{
	if (words < 0)
		return 0;

	if (words <= bn->dmax)
		return 1;

	return bn_expand_internal(bn, words);
}

BIGNUM *
BN_dup(const BIGNUM *a)
{
	BIGNUM *t;

	if (a == NULL)
		return NULL;

	t = BN_new();
	if (t == NULL)
		return NULL;
	if (!BN_copy(t, a)) {
		BN_free(t);
		return NULL;
	}
	return t;
}

BIGNUM *
BN_copy(BIGNUM *a, const BIGNUM *b)
{
	int i;
	BN_ULONG *A;
	const BN_ULONG *B;


	if (a == b)
		return (a);
	if (!bn_wexpand(a, b->top))
		return (NULL);

#if 1
	A = a->d;
	B = b->d;
	for (i = b->top >> 2; i > 0; i--, A += 4, B += 4) {
		BN_ULONG a0, a1, a2, a3;
		a0 = B[0];
		a1 = B[1];
		a2 = B[2];
		a3 = B[3];
		A[0] = a0;
		A[1] = a1;
		A[2] = a2;
		A[3] = a3;
	}
	switch (b->top & 3) {
	case 3:
		A[2] = B[2];
	case 2:
		A[1] = B[1];
	case 1:
		A[0] = B[0];
	}
#else
	memcpy(a->d, b->d, sizeof(b->d[0]) * b->top);
#endif

	a->top = b->top;
	a->neg = b->neg;
	return (a);
}

void
BN_swap(BIGNUM *a, BIGNUM *b)
{
	int flags_old_a, flags_old_b;
	BN_ULONG *tmp_d;
	int tmp_top, tmp_dmax, tmp_neg;


	flags_old_a = a->flags;
	flags_old_b = b->flags;

	tmp_d = a->d;
	tmp_top = a->top;
	tmp_dmax = a->dmax;
	tmp_neg = a->neg;

	a->d = b->d;
	a->top = b->top;
	a->dmax = b->dmax;
	a->neg = b->neg;

	b->d = tmp_d;
	b->top = tmp_top;
	b->dmax = tmp_dmax;
	b->neg = tmp_neg;

	a->flags = (flags_old_a & BN_FLG_MALLOCED) |
	    (flags_old_b & BN_FLG_STATIC_DATA);
	b->flags = (flags_old_b & BN_FLG_MALLOCED) |
	    (flags_old_a & BN_FLG_STATIC_DATA);
}

BN_ULONG
BN_get_word(const BIGNUM *a)
{
	if (a->top > 1)
		return BN_MASK2;
	else if (a->top == 1)
		return a->d[0];
	/* a->top == 0 */
	return 0;
}

int
BN_set_word(BIGNUM *a, BN_ULONG w)
{
	if (!bn_wexpand(a, 1))
		return (0);
	a->neg = 0;
	a->d[0] = w;
	a->top = (w ? 1 : 0);
	return (1);
}

BIGNUM *
BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret)
{
	unsigned int i, m;
	unsigned int n;
	BN_ULONG l;
	BIGNUM *bn = NULL;

	if (len < 0)
		return (NULL);
	if (ret == NULL)
		ret = bn = BN_new();
	if (ret == NULL)
		return (NULL);
	l = 0;
	n = len;
	if (n == 0) {
		ret->top = 0;
		return (ret);
	}
	i = ((n - 1) / BN_BYTES) + 1;
	m = ((n - 1) % (BN_BYTES));
	if (!bn_wexpand(ret, (int)i)) {
		BN_free(bn);
		return NULL;
	}
	ret->top = i;
	ret->neg = 0;
	while (n--) {
		l = (l << 8L) | *(s++);
		if (m-- == 0) {
			ret->d[--i] = l;
			l = 0;
			m = BN_BYTES - 1;
		}
	}
	/* need to call this due to clear byte at top if avoiding
	 * having the top bit set (-ve number) */
	bn_correct_top(ret);
	return (ret);
}

typedef enum {
	big,
	little,
} endianness_t;

/* ignore negative */
static int
bn2binpad(const BIGNUM *a, unsigned char *to, int tolen, endianness_t endianness)
{
	int n;
	size_t i, lasti, j, atop, mask;
	BN_ULONG l;

	/*
	 * In case |a| is fixed-top, BN_num_bytes can return bogus length,
	 * but it's assumed that fixed-top inputs ought to be "nominated"
	 * even for padded output, so it works out...
	 */
	n = BN_num_bytes(a);
	if (tolen == -1)
		tolen = n;
	else if (tolen < n) {	/* uncommon/unlike case */
		BIGNUM temp = *a;

		bn_correct_top(&temp);

		n = BN_num_bytes(&temp);
		if (tolen < n)
			return -1;
	}

	/* Swipe through whole available data and don't give away padded zero. */
	atop = a->dmax * BN_BYTES;
	if (atop == 0) {
		explicit_bzero(to, tolen);
		return tolen;
	}

	lasti = atop - 1;
	atop = a->top * BN_BYTES;

	if (endianness == big)
		to += tolen; /* start from the end of the buffer */

	for (i = 0, j = 0; j < (size_t)tolen; j++) {
		unsigned char val;

		l = a->d[i / BN_BYTES];
		mask = 0 - ((j - atop) >> (8 * sizeof(i) - 1));
		val = (unsigned char)(l >> (8 * (i % BN_BYTES)) & mask);

		if (endianness == big)
			*--to = val;
		else
			*to++ = val;

		i += (i - lasti) >> (8 * sizeof(i) - 1); /* stay on last limb */
	}

	return tolen;
}

int
BN_bn2binpad(const BIGNUM *a, unsigned char *to, int tolen)
{
	if (tolen < 0)
		return -1;
	return bn2binpad(a, to, tolen, big);
}

int
BN_bn2bin(const BIGNUM *a, unsigned char *to)
{
	return bn2binpad(a, to, -1, big);
}

BIGNUM *
BN_lebin2bn(const unsigned char *s, int len, BIGNUM *ret)
{
	unsigned int i, m, n;
	BN_ULONG l;
	BIGNUM *bn = NULL;

	if (ret == NULL)
		ret = bn = BN_new();
	if (ret == NULL)
		return NULL;


	s += len;
	/* Skip trailing zeroes. */
	for (; len > 0 && s[-1] == 0; s--, len--)
		continue;

	n = len;
	if (n == 0) {
		ret->top = 0;
		return ret;
	}

	i = ((n - 1) / BN_BYTES) + 1;
	m = (n - 1) % BN_BYTES;
	if (!bn_wexpand(ret, (int)i)) {
		BN_free(bn);
		return NULL;
	}

	ret->top = i;
	ret->neg = 0;
	l = 0;
	while (n-- > 0) {
		s--;
		l = (l << 8L) | *s;
		if (m-- == 0) {
			ret->d[--i] = l;
			l = 0;
			m = BN_BYTES - 1;
		}
	}

	/*
	 * need to call this due to clear byte at top if avoiding having the
	 * top bit set (-ve number)
	 */
	bn_correct_top(ret);

	return ret;
}

int
BN_bn2lebinpad(const BIGNUM *a, unsigned char *to, int tolen)
{
	if (tolen < 0)
		return -1;

	return bn2binpad(a, to, tolen, little);
}

int
BN_ucmp(const BIGNUM *a, const BIGNUM *b)
{
	int i;

	if (a->top < b->top)
		return -1;
	if (a->top > b->top)
		return 1;

	for (i = a->top - 1; i >= 0; i--) {
		if (a->d[i] != b->d[i])
			return (a->d[i] > b->d[i] ? 1 : -1);
	}

	return 0;
}

int
BN_cmp(const BIGNUM *a, const BIGNUM *b)
{
	if (a == NULL || b == NULL) {
		if (a != NULL)
			return -1;
		if (b != NULL)
			return 1;
		return 0;
	}

	if (a->neg != b->neg)
		return b->neg - a->neg;

	if (a->neg)
		return BN_ucmp(b, a);

	return BN_ucmp(a, b);
}

int
BN_set_bit(BIGNUM *a, int n)
{
	int i, j, k;

	if (n < 0)
		return 0;

	i = n / BN_BITS2;
	j = n % BN_BITS2;
	if (a->top <= i) {
		if (!bn_wexpand(a, i + 1))
			return (0);
		for (k = a->top; k < i + 1; k++)
			a->d[k] = 0;
		a->top = i + 1;
	}

	a->d[i] |= (((BN_ULONG)1) << j);
	return (1);
}

int
BN_clear_bit(BIGNUM *a, int n)
{
	int i, j;

	if (n < 0)
		return 0;

	i = n / BN_BITS2;
	j = n % BN_BITS2;
	if (a->top <= i)
		return (0);

	a->d[i] &= (~(((BN_ULONG)1) << j));
	bn_correct_top(a);
	return (1);
}

int
BN_is_bit_set(const BIGNUM *a, int n)
{
	int i, j;

	if (n < 0)
		return 0;
	i = n / BN_BITS2;
	j = n % BN_BITS2;
	if (a->top <= i)
		return 0;
	return (int)(((a->d[i]) >> j) & ((BN_ULONG)1));
}

int
BN_mask_bits(BIGNUM *a, int n)
{
	int b, w;

	if (n < 0)
		return 0;

	w = n / BN_BITS2;
	b = n % BN_BITS2;
	if (w >= a->top)
		return 0;
	if (b == 0)
		a->top = w;
	else {
		a->top = w + 1;
		a->d[w] &= ~(BN_MASK2 << b);
	}
	bn_correct_top(a);
	return (1);
}

void
BN_set_negative(BIGNUM *bn, int neg)
{
	bn->neg = ~BN_is_zero(bn) & bn_ct_ne_zero(neg);
}

int
bn_cmp_words(const BN_ULONG *a, const BN_ULONG *b, int n)
{
	int i;
	BN_ULONG aa, bb;

	aa = a[n - 1];
	bb = b[n - 1];
	if (aa != bb)
		return ((aa > bb) ? 1 : -1);
	for (i = n - 2; i >= 0; i--) {
		aa = a[i];
		bb = b[i];
		if (aa != bb)
			return ((aa > bb) ? 1 : -1);
	}
	return (0);
}

/* Here follows a specialised variants of bn_cmp_words().  It has the
   property of performing the operation on arrays of different sizes.
   The sizes of those arrays is expressed through cl, which is the
   common length ( basicall, min(len(a),len(b)) ), and dl, which is the
   delta between the two lengths, calculated as len(a)-len(b).
   All lengths are the number of BN_ULONGs...  */

int
bn_cmp_part_words(const BN_ULONG *a, const BN_ULONG *b, int cl, int dl)
{
	int n, i;

	n = cl - 1;

	if (dl < 0) {
		for (i = dl; i < 0; i++) {
			if (b[n - i] != 0)
				return -1; /* a < b */
		}
	}
	if (dl > 0) {
		for (i = dl; i > 0; i--) {
			if (a[n + i] != 0)
				return 1; /* a > b */
		}
	}
	return bn_cmp_words(a, b, cl);
}

/*
 * Constant-time conditional swap of a and b.
 * a and b are swapped if condition is not 0.
 * The code assumes that at most one bit of condition is set.
 * nwords is the number of words to swap.
 * The code assumes that at least nwords are allocated in both a and b,
 * and that no more than nwords are used by either a or b.
 * a and b cannot be the same number
 */
void
BN_consttime_swap(BN_ULONG condition, BIGNUM *a, BIGNUM *b, int nwords)
{
	BN_ULONG t;
	int i;

	assert(a != b);
	assert((condition & (condition - 1)) == 0);
	assert(sizeof(BN_ULONG) >= sizeof(int));

	condition = ((condition - 1) >> (BN_BITS2 - 1)) - 1;

	t = (a->top^b->top) & condition;
	a->top ^= t;
	b->top ^= t;

#define BN_CONSTTIME_SWAP(ind) \
	do { \
		t = (a->d[ind] ^ b->d[ind]) & condition; \
		a->d[ind] ^= t; \
		b->d[ind] ^= t; \
	} while (0)


	switch (nwords) {
	default:
		for (i = 10; i < nwords; i++)
			BN_CONSTTIME_SWAP(i);
		/* Fallthrough */
	case 10: BN_CONSTTIME_SWAP(9); /* Fallthrough */
	case 9: BN_CONSTTIME_SWAP(8); /* Fallthrough */
	case 8: BN_CONSTTIME_SWAP(7); /* Fallthrough */
	case 7: BN_CONSTTIME_SWAP(6); /* Fallthrough */
	case 6: BN_CONSTTIME_SWAP(5); /* Fallthrough */
	case 5: BN_CONSTTIME_SWAP(4); /* Fallthrough */
	case 4: BN_CONSTTIME_SWAP(3); /* Fallthrough */
	case 3: BN_CONSTTIME_SWAP(2); /* Fallthrough */
	case 2: BN_CONSTTIME_SWAP(1); /* Fallthrough */
	case 1:
		BN_CONSTTIME_SWAP(0);
	}
#undef BN_CONSTTIME_SWAP
}

/*
 * Constant-time conditional swap of a and b.
 * a and b are swapped if condition is not 0.
 * nwords is the number of words to swap.
 */
int
BN_swap_ct(BN_ULONG condition, BIGNUM *a, BIGNUM *b, size_t nwords)
{
	BN_ULONG t;
	int i, words;

	if (a == b)
		return 1;
	if (nwords > INT_MAX)
		return 0;
	words = (int)nwords;
	if (!bn_wexpand(a, words) || !bn_wexpand(b, words))
		return 0;
	if (a->top > words || b->top > words) {
		BNerror(BN_R_INVALID_LENGTH);
		return 0;
	}

	/* Set condition to 0 (if it was zero) or all 1s otherwise. */
	condition = ((~condition & (condition - 1)) >> (BN_BITS2 - 1)) - 1;

	/* swap top field */
	t = (a->top ^ b->top) & condition;
	a->top ^= t;
	b->top ^= t;

	/* swap neg field */
	t = (a->neg ^ b->neg) & condition;
	a->neg ^= t;
	b->neg ^= t;

	/* swap BN_FLG_CONSTTIME from flag field */
	t = ((a->flags ^ b->flags) & BN_FLG_CONSTTIME) & condition;
	a->flags ^= t;
	b->flags ^= t;

	/* swap the data */
	for (i = 0; i < words; i++) {
		t = (a->d[i] ^ b->d[i]) & condition;
		a->d[i] ^= t;
		b->d[i] ^= t;
	}

	return 1;
}

void
BN_zero(BIGNUM *a)
{
	a->neg = 0;
	a->top = 0;
}

void
BN_zero_ex(BIGNUM *a)
{
	BN_zero(a);
}

int
BN_one(BIGNUM *a)
{
	return BN_set_word(a, 1);
}

int
BN_abs_is_word(const BIGNUM *a, const BN_ULONG w)
{
	return (a->top == 1 && a->d[0] == w) || (w == 0 && a->top == 0);
}

int
BN_is_zero(const BIGNUM *bn)
{
	BN_ULONG bits = 0;
	int i;

	for (i = 0; i < bn->top; i++)
		bits |= bn->d[i];

	return bits == 0;
}

int
BN_is_one(const BIGNUM *a)
{
	return BN_abs_is_word(a, 1) && !a->neg;
}

int
BN_is_word(const BIGNUM *a, const BN_ULONG w)
{
	return BN_abs_is_word(a, w) && (w == 0 || !a->neg);
}

int
BN_is_odd(const BIGNUM *a)
{
	return a->top > 0 && (a->d[0] & 1);
}

int
BN_is_negative(const BIGNUM *a)
{
	return a->neg != 0;
}

/*
 * Bits of security, see SP800-57, section 5.6.11, table 2.
 */
int
BN_security_bits(int L, int N)
{
	int secbits, bits;

	if (L >= 15360)
		secbits = 256;
	else if (L >= 7680)
		secbits = 192;
	else if (L >= 3072)
		secbits = 128;
	else if (L >= 2048)
		secbits = 112;
	else if (L >= 1024)
		secbits = 80;
	else
		return 0;

	if (N == -1)
		return secbits;

	bits = N / 2;
	if (bits < 80)
		return 0;

	return bits >= secbits ? secbits : bits;
}

BN_GENCB *
BN_GENCB_new(void)
{
	BN_GENCB *cb;

	if ((cb = calloc(1, sizeof(*cb))) == NULL)
		return NULL;

	return cb;
}

void
BN_GENCB_free(BN_GENCB *cb)
{
	if (cb == NULL)
		return;
	free(cb);
}

/* Populate a BN_GENCB structure with an "old"-style callback */
void
BN_GENCB_set_old(BN_GENCB *gencb, void (*cb)(int, int, void *), void *cb_arg)
{
	gencb->ver = 1;
	gencb->cb.cb_1 = cb;
	gencb->arg = cb_arg;
}

/* Populate a BN_GENCB structure with a "new"-style callback */
void
BN_GENCB_set(BN_GENCB *gencb, int (*cb)(int, int, BN_GENCB *), void *cb_arg)
{
	gencb->ver = 2;
	gencb->cb.cb_2 = cb;
	gencb->arg = cb_arg;
}

void *
BN_GENCB_get_arg(BN_GENCB *cb)
{
	return cb->arg;
}
