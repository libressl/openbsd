/*	$OpenBSD: bn_bpsw.c,v 1.7 2022/08/31 21:34:14 tb Exp $ */
/*
 * Copyright (c) 2022 Martin Grenouilloux <martin.grenouilloux@lse.epita.fr>
 * Copyright (c) 2022 Theo Buehler <tb@openbsd.org>
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

#include <openssl/bn.h>

#include "bn_lcl.h"
#include "bn_prime.h"

/*
 * For an odd n compute a / 2 (mod n). If a is even, we can do a plain
 * division, otherwise calculate (a + n) / 2. Then reduce (mod n).
 */

static int
bn_div_by_two_mod_odd_n(BIGNUM *a, const BIGNUM *n, BN_CTX *ctx)
{
	if (!BN_is_odd(n))
		return 0;

	if (BN_is_odd(a)) {
		if (!BN_add(a, a, n))
			return 0;
	}
	if (!BN_rshift1(a, a))
		return 0;
	if (!BN_mod_ct(a, a, n, ctx))
		return 0;

	return 1;
}

/*
 * Given the next binary digit of k and the current Lucas terms U and V, this
 * helper computes the next terms in the Lucas sequence defined as follows:
 *
 *   U' = U * V                  (mod n)
 *   V' = (V^2 + D * U^2) / 2    (mod n)
 *
 * If digit == 0, bn_lucas_step() returns U' and V'. If digit == 1, it returns
 *
 *   U'' = (U' + V') / 2         (mod n)
 *   V'' = (V' + D * U') / 2     (mod n)
 *
 * Compare with FIPS 186-4, Appendix C.3.3, step 6.
 */

static int
bn_lucas_step(BIGNUM *U, BIGNUM *V, int digit, const BIGNUM *D,
    const BIGNUM *n, BN_CTX *ctx)
{
	BIGNUM *tmp;
	int ret = 0;

	BN_CTX_start(ctx);

	if ((tmp = BN_CTX_get(ctx)) == NULL)
		goto err;

	/* Calculate D * U^2 before computing U'. */
	if (!BN_sqr(tmp, U, ctx))
		goto err;
	if (!BN_mul(tmp, D, tmp, ctx))
		goto err;

	/* U' = U * V (mod n). */
	if (!BN_mod_mul(U, U, V, n, ctx))
		goto err;

	/* V' = (V^2 + D * U^2) / 2 (mod n). */
	if (!BN_sqr(V, V, ctx))
		goto err;
	if (!BN_add(V, V, tmp))
		goto err;
	if (!bn_div_by_two_mod_odd_n(V, n, ctx))
		goto err;

	if (digit == 1) {
		/* Calculate D * U' before computing U''. */
		if (!BN_mul(tmp, D, U, ctx))
			goto err;

		/* U'' = (U' + V') / 2 (mod n). */
		if (!BN_add(U, U, V))
			goto err;
		if (!bn_div_by_two_mod_odd_n(U, n, ctx))
			goto err;

		/* V'' = (V' + D * U') / 2 (mod n). */
		if (!BN_add(V, V, tmp))
			goto err;
		if (!bn_div_by_two_mod_odd_n(V, n, ctx))
			goto err;
	}

	ret = 1;

 err:
	BN_CTX_end(ctx);

	return ret;
}

/*
 * Compute the Lucas terms U_k, V_k, see FIPS 186-4, Appendix C.3.3, steps 4-6.
 */

static int
bn_lucas(BIGNUM *U, BIGNUM *V, const BIGNUM *k, const BIGNUM *D,
    const BIGNUM *n, BN_CTX *ctx)
{
	int digit, i;
	int ret = 0;

	if (!BN_one(U))
		goto err;
	if (!BN_one(V))
		goto err;

	/*
	 * Iterate over the digits of k from MSB to LSB. Start at digit 2
	 * since the first digit is dealt with by setting U = 1 and V = 1.
	 */

	for (i = BN_num_bits(k) - 2; i >= 0; i--) {
		digit = BN_is_bit_set(k, i);

		if (!bn_lucas_step(U, V, digit, D, n, ctx))
			goto err;
	}

	ret = 1;

 err:
	return ret;
}

/*
 * This is a stronger variant of the Lucas test in FIPS 186-4, Appendix C.3.3.
 * Every strong Lucas pseudoprime n is also a Lucas pseudoprime since
 * U_{n+1} == 0 follows from U_k == 0 or V_{k * 2^r} == 0 for 0 <= r < s.
 */

static int
bn_strong_lucas_test(int *is_prime, const BIGNUM *n, const BIGNUM *D,
    BN_CTX *ctx)
{
	BIGNUM *k, *U, *V;
	int r, s;
	int ret = 0;

	BN_CTX_start(ctx);

	if ((k = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((U = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((V = BN_CTX_get(ctx)) == NULL)
		goto err;

	/*
	 * Factorize n + 1 = k * 2^s with odd k: shift away the s trailing ones
	 * of n and set the lowest bit of the resulting number k.
	 */

	s = 0;
	while (BN_is_bit_set(n, s))
		s++;
	if (!BN_rshift(k, n, s))
		goto err;
	if (!BN_set_bit(k, 0))
		goto err;

	/*
	 * Calculate the Lucas terms U_k and V_k. If either of them is zero,
	 * then n is a strong Lucas pseudoprime.
	 */

	if (!bn_lucas(U, V, k, D, n, ctx))
		goto err;

	if (BN_is_zero(U) || BN_is_zero(V)) {
		*is_prime = 1;
		goto done;
	}

	/*
	 * Calculate the Lucas terms U_{k * 2^r}, V_{k * 2^r} for 1 <= r < s.
	 * If any V_{k * 2^r} is zero then n is a strong Lucas pseudoprime.
	 */

	for (r = 1; r < s; r++) {
		if (!bn_lucas_step(U, V, 0, D, n, ctx))
			goto err;

		if (BN_is_zero(V)) {
			*is_prime = 1;
			goto done;
		}
	}

	/*
	 * If we got here, n is definitely composite.
	 */

	*is_prime = 0;

 done:
	ret = 1;

 err:
	BN_CTX_end(ctx);

	return ret;
}

/*
 * Test n for primality using the strong Lucas test with Selfridge's Method A.
 * Returns 1 if n is prime or a strong Lucas-Selfridge pseudoprime.
 * If it returns 0 then n is definitely composite.
 */

static int
bn_strong_lucas_selfridge(int *is_prime, const BIGNUM *n, BN_CTX *ctx)
{
	BIGNUM *D, *two;
	int is_perfect_square, jacobi_symbol, sign;
	int ret = 0;

	BN_CTX_start(ctx);

	/* If n is a perfect square, it is composite. */
	if (!bn_is_perfect_square(&is_perfect_square, n, ctx))
		goto err;
	if (is_perfect_square) {
		*is_prime = 0;
		goto done;
	}

	/*
	 * Find the first D in the Selfridge sequence 5, -7, 9, -11, 13, ...
	 * such that the Jacobi symbol (D/n) is -1.
	 */

	if ((D = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((two = BN_CTX_get(ctx)) == NULL)
		goto err;

	sign = 1;
	if (!BN_set_word(D, 5))
		goto err;
	if (!BN_set_word(two, 2))
		goto err;

	while (1) {
		/* For odd n the Kronecker symbol computes the Jacobi symbol. */
		if ((jacobi_symbol = BN_kronecker(D, n, ctx)) == -2)
			goto err;

		/* We found the value for D. */
		if (jacobi_symbol == -1)
			break;

		/* n and D have prime factors in common. */
		if (jacobi_symbol == 0) {
			*is_prime = 0;
			goto done;
		}

		sign = -sign;
		if (!BN_uadd(D, D, two))
			goto err;
		BN_set_negative(D, sign == -1);
	}

	if (!bn_strong_lucas_test(is_prime, n, D, ctx))
		goto err;

 done:
	ret = 1;

 err:
	BN_CTX_end(ctx);

	return ret;
}

/*
 * Miller-Rabin primality test for base 2.
 */

static int
bn_miller_rabin_base_2(int *is_prime, const BIGNUM *n, BN_CTX *ctx)
{
	BIGNUM *n_minus_one, *k, *x;
	int i, s;
	int ret = 0;

	BN_CTX_start(ctx);

	if ((n_minus_one = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((k = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((x = BN_CTX_get(ctx)) == NULL)
		goto err;

	if (BN_is_word(n, 2) || BN_is_word(n, 3)) {
		*is_prime = 1;
		goto done;
	}

	if (BN_cmp(n, BN_value_one()) <= 0 || !BN_is_odd(n)) {
		*is_prime = 0;
		goto done;
	}

	if (!BN_sub(n_minus_one, n, BN_value_one()))
		goto err;

	/*
	 * Factorize n - 1 = k * 2^s.
	 */

	s = 0;
	while (!BN_is_bit_set(n_minus_one, s))
		s++;
	if (!BN_rshift(k, n_minus_one, s))
		goto err;

	/*
	 * If 2^k is 1 or -1 (mod n) then n is a 2-pseudoprime.
	 */

	if (!BN_set_word(x, 2))
		goto err;
	if (!BN_mod_exp_ct(x, x, k, n, ctx))
		goto err;

	if (BN_is_one(x) || BN_cmp(x, n_minus_one) == 0) {
		*is_prime = 1;
		goto done;
	}

	/*
	 * If 2^{2^i k} == -1 (mod n) for some 1 <= i < s, then n is a
	 * 2-pseudoprime.
	 */

	for (i = 1; i < s; i++) {
		if (!BN_mod_sqr(x, x, n, ctx))
			goto err;
		if (BN_cmp(x, n_minus_one) == 0) {
			*is_prime = 1;
			goto done;
		}
	}

	/*
	 * If we got here, n is definitely composite.
	 */

	*is_prime = 0;

 done:
	ret = 1;

 err:
	BN_CTX_end(ctx);

	return ret;
}

/*
 * The Baillie-Pomerance-Selfridge-Wagstaff algorithm combines a Miller-Rabin
 * test for base 2 with a Strong Lucas pseudoprime test.
 */

int
bn_is_prime_bpsw(int *is_prime, const BIGNUM *n, BN_CTX *in_ctx)
{
	BN_CTX *ctx = NULL;
	BN_ULONG mod;
	int i;
	int ret = 0;

	if (BN_is_word(n, 2)) {
		*is_prime = 1;
		goto done;
	}

	if (BN_cmp(n, BN_value_one()) <= 0 || !BN_is_odd(n)) {
		*is_prime = 0;
		goto done;
	}

	/* Trial divisions with the first 2048 primes. */
	for (i = 0; i < NUMPRIMES; i++) {
		if ((mod = BN_mod_word(n, primes[i])) == (BN_ULONG)-1)
			goto err;
		if (mod == 0) {
			*is_prime = BN_is_word(n, primes[i]);
			goto done;
		}
	}

	if ((ctx = in_ctx) == NULL)
		ctx = BN_CTX_new();
	if (ctx == NULL)
		goto err;

	if (!bn_miller_rabin_base_2(is_prime, n, ctx))
		goto err;
	if (!*is_prime)
		goto done;

	/* XXX - Miller-Rabin for random bases? See FIPS 186-4, Table C.1. */

	if (!bn_strong_lucas_selfridge(is_prime, n, ctx))
		goto err;

 done:
	ret = 1;

 err:
	if (ctx != in_ctx)
		BN_CTX_free(ctx);

	return ret;
}
