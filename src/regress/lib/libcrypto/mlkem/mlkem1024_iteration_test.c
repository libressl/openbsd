/*	$OpenBSD: mlkem1024_iteration_test.c,v 1.2 2024/12/14 19:16:24 tb Exp $ */
/*
 * Copyright (c) 2024, Google Inc.
 * Copyright (c) 2024, Bob Beck <beck@obtuse.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <openssl/bytestring.h>
#include <openssl/mlkem.h>

#include "mlkem_internal.h"
#include "mlkem_tests_util.h"
#include "sha3_internal.h"

static int
encode_private_key(const struct MLKEM1024_private_key *priv, uint8_t **out_buf,
    size_t *out_len)
{
	CBB cbb;
	if (!CBB_init(&cbb, MLKEM1024_PUBLIC_KEY_BYTES))
		return 0;
	if (!MLKEM1024_marshal_private_key(&cbb, priv))
		return 0;
	if (!CBB_finish(&cbb, out_buf, out_len))
		return 0;
	CBB_cleanup(&cbb);
	return 1;
}

/*
 * The structure of this test is taken from
 *  https://github.com/C2SP/CCTV/blob/main/ML-KEM/README.md?ref=words.filippo.io#accumulated-pq-crystals-vectors
 *  but the final value has been updated to reflect the change from Kyber to
 *  ML-KEM.
 *
 * The deterministic RNG is a single SHAKE-128 instance with an empty input.
 * (The RNG stream starts with 7f9c2ba4e88f827d616045507605853e.)
 */

static void
MlkemIterativeTest()
{
	/* https://github.com/C2SP/CCTV/tree/main/ML-KEM */
	/*
	 * The deterministic RNG is a single SHAKE-128 instance with an empty input.
	 * (The RNG stream starts with 7f9c2ba4e88f827d616045507605853e.)
	 */
	const uint8_t kExpectedSeedStart[16] = {
		0x7f, 0x9c, 0x2b, 0xa4, 0xe8, 0x8f, 0x82, 0x7d, 0x61, 0x60, 0x45,
		0x50, 0x76, 0x05, 0x85, 0x3e
	};

	/*
	 * Filippo says:
	 * ML-KEM-1024: 47ac888fe61544efc0518f46094b4f8a600965fc89822acb06dc7169d24f3543
	 * but Boring believes this:
	 */
	const uint8_t kExpectedAdam[32] = {
		0xe3, 0xbf, 0x82, 0xb0, 0x13, 0x30, 0x7b, 0x2e, 0x9d, 0x47, 0xdd,
		0xe7, 0x91, 0xff, 0x6d, 0xfc, 0x82, 0xe6, 0x94, 0xe6, 0x38, 0x24,
		0x04, 0xab, 0xdb, 0x94, 0x8b, 0x90, 0x8b, 0x75, 0xba, 0xd5
	};
	uint8_t encoded_public_key[MLKEM1024_PUBLIC_KEY_BYTES];
	uint8_t invalid_ciphertext[MLKEM1024_CIPHERTEXT_BYTES];
	uint8_t shared_secret[MLKEM_SHARED_SECRET_BYTES];
	uint8_t ciphertext[MLKEM1024_CIPHERTEXT_BYTES];
	uint8_t encap_entropy[MLKEM_ENCAP_ENTROPY];
	uint8_t seed[MLKEM_SEED_BYTES] = {0};
	struct MLKEM1024_private_key priv;
	struct MLKEM1024_public_key pub;
	sha3_ctx drng, results;
	uint8_t out[32];
	int i;

	shake128_init(&drng);
	shake128_init(&results);

	shake_xof(&drng);
	for (i = 0; i < 10000; i++) {
		uint8_t *encoded_private_key = NULL;
		size_t encoded_private_key_len;

		/*
		 * This should draw both d and z from DRNG concatenating in
		 * seed.
		 */
		shake_out(&drng, seed, sizeof(seed));
		if (i == 0) {
			TEST_DATAEQ(seed, kExpectedSeedStart,
			    sizeof(kExpectedSeedStart), "seed start");
		}

		/* generate ek as encoded_public_key */
		MLKEM1024_generate_key_external_entropy(encoded_public_key,
		    &priv, seed);
		MLKEM1024_public_from_private(&pub, &priv);

		/* hash in ek */
		shake_update(&results, encoded_public_key,
		    sizeof(encoded_public_key));

		/* marshal priv to dk as encoded_private_key */
		TEST(!encode_private_key(&priv, &encoded_private_key,
		    &encoded_private_key_len), "encode_private_key");

		/* hash in dk */
		shake_update(&results, encoded_private_key,
		    encoded_private_key_len);

		free(encoded_private_key);

		/* draw m as encap entropy from DRNG */
		shake_out(&drng, encap_entropy, sizeof(encap_entropy));

		/* generate ct as ciphertext, k as shared_secret */
		MLKEM1024_encap_external_entropy(ciphertext, shared_secret,
		    &pub, encap_entropy);

		/* hash in ct */
		shake_update(&results, ciphertext, sizeof(ciphertext));
		/* hash in k */
		shake_update(&results, shared_secret, sizeof(shared_secret));

		/* draw ct as invalid_ciphertxt from DRNG */
		shake_out(&drng, invalid_ciphertext,
		    sizeof(invalid_ciphertext));

		/* generte k as shared secret from invalid ciphertext */
		TEST(!MLKEM1024_decap(shared_secret, invalid_ciphertext,
		    sizeof(invalid_ciphertext), &priv), "decap failed!");

		/* hash in k */
		shake_update(&results, shared_secret, sizeof(shared_secret));
	}
	shake_xof(&results);
	shake_out(&results, out, 32);

	TEST_DATAEQ(out, kExpectedAdam, 32, "final result hash");
}

int
main(int argc, char **argv)
{
	MlkemIterativeTest();
	exit(failure);
}
