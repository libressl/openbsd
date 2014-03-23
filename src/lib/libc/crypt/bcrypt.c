/*	$OpenBSD: bcrypt.c,v 1.33 2014/03/23 23:20:12 tedu Exp $	*/

/*
 * Copyright (c) 2014 Ted Unangst <tedu@openbsd.org>
 * Copyright (c) 1997 Niels Provos <provos@umich.edu>
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
/* This password hashing algorithm was designed by David Mazieres
 * <dm@lcs.mit.edu> and works as follows:
 *
 * 1. state := InitState ()
 * 2. state := ExpandKey (state, salt, password)
 * 3. REPEAT rounds:
 *      state := ExpandKey (state, 0, password)
 *	state := ExpandKey (state, 0, salt)
 * 4. ctext := "OrpheanBeholderScryDoubt"
 * 5. REPEAT 64:
 * 	ctext := Encrypt_ECB (state, ctext);
 * 6. RETURN Concatenate (salt, ctext);
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <pwd.h>
#include <blf.h>

/* This implementation is adaptable to current computing power.
 * You can have up to 2^31 rounds which should be enough for some
 * time to come.
 */

#define BCRYPT_VERSION '2'
#define BCRYPT_MAXSALT 16	/* Precomputation is just so nice */
#define BCRYPT_BLOCKS 6		/* Ciphertext blocks */
#define BCRYPT_MINLOGROUNDS 4	/* we have log2(rounds) in salt */

#define	BCRYPT_SALTSPACE	(7 + (BCRYPT_MAXSALT * 4 + 2) / 3 + 1)

char   *bcrypt_gensalt(u_int8_t);

static void encode_base64(u_int8_t *, u_int8_t *, u_int16_t);
static void decode_base64(u_int8_t *, u_int16_t, u_int8_t *);

/*
 * Generates a salt for this version of crypt.
 */
static int
bcrypt_initsalt(int log_rounds, uint8_t *salt, size_t saltbuflen)
{
	uint8_t csalt[BCRYPT_MAXSALT];

	if (saltbuflen < BCRYPT_SALTSPACE)
		return -1;

	arc4random_buf(csalt, sizeof(csalt));

	if (log_rounds < 4)
		log_rounds = 4;
	else if (log_rounds > 31)
		log_rounds = 31;

	snprintf(salt, 4, "$2a$%2.2u$", log_rounds);
	encode_base64((uint8_t *)salt + 7, csalt, sizeof(csalt));

	return 0;
}

/*
 * the core bcrypt function
 */
static int
bcrypt_hashpass(const char *key, const char *salt, char *encrypted,
    size_t encryptedlen)
{
	blf_ctx state;
	u_int32_t rounds, i, k;
	u_int16_t j;
	size_t key_len;
	u_int8_t salt_len, logr, minor;
	u_int8_t ciphertext[4 * BCRYPT_BLOCKS] = "OrpheanBeholderScryDoubt";
	u_int8_t csalt[BCRYPT_MAXSALT];
	u_int32_t cdata[BCRYPT_BLOCKS];
	char arounds[3];

	/* Discard "$" identifier */
	salt++;

	if (*salt > BCRYPT_VERSION) {
		return -1;
	}

	/* Check for minor versions */
	if (salt[1] != '$') {
		 switch (salt[1]) {
		 case 'a':	/* 'ab' should not yield the same as 'abab' */
		 case 'b':	/* cap input length at 72 bytes */
			 minor = salt[1];
			 salt++;
			 break;
		 default:
			 return -1;
		 }
	} else
		 minor = 0;

	/* Discard version + "$" identifier */
	salt += 2;

	if (salt[2] != '$')
		/* Out of sync with passwd entry */
		return -1;

	memcpy(arounds, salt, sizeof(arounds));
	if (arounds[sizeof(arounds) - 1] != '$')
		return -1;
	arounds[sizeof(arounds) - 1] = 0;
	logr = strtonum(arounds, BCRYPT_MINLOGROUNDS, 31, NULL);
	if (logr == 0)
		return -1;
	/* Computer power doesn't increase linearly, 2^x should be fine */
	rounds = 1U << logr;

	/* Discard num rounds + "$" identifier */
	salt += 3;

	if (strlen(salt) * 3 / 4 < BCRYPT_MAXSALT)
		return -1;

	/* We dont want the base64 salt but the raw data */
	decode_base64(csalt, BCRYPT_MAXSALT, (u_int8_t *) salt);
	salt_len = BCRYPT_MAXSALT;
	if (minor <= 'a')
		key_len = (u_int8_t)(strlen(key) + (minor >= 'a' ? 1 : 0));
	else {
		/* strlen() returns a size_t, but the function calls
		 * below result in implicit casts to a narrower integer
		 * type, so cap key_len at the actual maximum supported
		 * length here to avoid integer wraparound */
		key_len = strlen(key);
		if (key_len > 72)
			key_len = 72;
		key_len++; /* include the NUL */
	}

	/* Setting up S-Boxes and Subkeys */
	Blowfish_initstate(&state);
	Blowfish_expandstate(&state, csalt, salt_len,
	    (u_int8_t *) key, key_len);
	for (k = 0; k < rounds; k++) {
		Blowfish_expand0state(&state, (u_int8_t *) key, key_len);
		Blowfish_expand0state(&state, csalt, salt_len);
	}

	/* This can be precomputed later */
	j = 0;
	for (i = 0; i < BCRYPT_BLOCKS; i++)
		cdata[i] = Blowfish_stream2word(ciphertext, 4 * BCRYPT_BLOCKS, &j);

	/* Now do the encryption */
	for (k = 0; k < 64; k++)
		blf_enc(&state, cdata, BCRYPT_BLOCKS / 2);

	for (i = 0; i < BCRYPT_BLOCKS; i++) {
		ciphertext[4 * i + 3] = cdata[i] & 0xff;
		cdata[i] = cdata[i] >> 8;
		ciphertext[4 * i + 2] = cdata[i] & 0xff;
		cdata[i] = cdata[i] >> 8;
		ciphertext[4 * i + 1] = cdata[i] & 0xff;
		cdata[i] = cdata[i] >> 8;
		ciphertext[4 * i + 0] = cdata[i] & 0xff;
	}


	i = 0;
	encrypted[i++] = '$';
	encrypted[i++] = BCRYPT_VERSION;
	if (minor)
		encrypted[i++] = minor;
	encrypted[i++] = '$';

	snprintf(encrypted + i, 4, "%2.2u$", logr);

	encode_base64((u_int8_t *) encrypted + i + 3, csalt, BCRYPT_MAXSALT);
	encode_base64((u_int8_t *) encrypted + strlen(encrypted), ciphertext,
	    4 * BCRYPT_BLOCKS - 1);
	memset(&state, 0, sizeof(state));
	memset(ciphertext, 0, sizeof(ciphertext));
	memset(csalt, 0, sizeof(csalt));
	memset(cdata, 0, sizeof(cdata));
	return 0;
}

/*
 * user friendly functions
 */
int
bcrypt_newhash(const char *pass, int log_rounds, char *hash, size_t hashlen)
{
	char salt[BCRYPT_SALTSPACE];

	if (bcrypt_initsalt(log_rounds, salt, sizeof(salt)) != 0)
		return -1;

	if (bcrypt_hashpass(pass, salt, hash, hashlen) != 0)
		return -1;

	return 0;
}

int
bcrypt_checkpass(const char *pass, const char *goodhash)
{
	char hash[_PASSWORD_LEN];

	if (bcrypt_hashpass(pass, goodhash, hash, sizeof(hash)) != 0)
		return -1;
	if (strcmp(hash, goodhash) != 0)
		return -1;
	return 0;
}

/*
 * internal utilities
 */
const static u_int8_t Base64Code[] =
"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

const static u_int8_t index_64[128] = {
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 0, 1, 54, 55,
	56, 57, 58, 59, 60, 61, 62, 63, 255, 255,
	255, 255, 255, 255, 255, 2, 3, 4, 5, 6,
	7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
	17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
	255, 255, 255, 255, 255, 255, 28, 29, 30,
	31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
	51, 52, 53, 255, 255, 255, 255, 255
};
#define CHAR64(c)  ( (c) > 127 ? 255 : index_64[(c)])

static void
decode_base64(u_int8_t *buffer, u_int16_t len, u_int8_t *data)
{
	u_int8_t *bp = buffer;
	u_int8_t *p = data;
	u_int8_t c1, c2, c3, c4;
	while (bp < buffer + len) {
		c1 = CHAR64(*p);
		c2 = CHAR64(*(p + 1));

		/* Invalid data */
		if (c1 == 255 || c2 == 255)
			break;

		*bp++ = (c1 << 2) | ((c2 & 0x30) >> 4);
		if (bp >= buffer + len)
			break;

		c3 = CHAR64(*(p + 2));
		if (c3 == 255)
			break;

		*bp++ = ((c2 & 0x0f) << 4) | ((c3 & 0x3c) >> 2);
		if (bp >= buffer + len)
			break;

		c4 = CHAR64(*(p + 3));
		if (c4 == 255)
			break;
		*bp++ = ((c3 & 0x03) << 6) | c4;

		p += 4;
	}
}

static void
encode_base64(u_int8_t *buffer, u_int8_t *data, u_int16_t len)
{
	u_int8_t *bp = buffer;
	u_int8_t *p = data;
	u_int8_t c1, c2;
	while (p < data + len) {
		c1 = *p++;
		*bp++ = Base64Code[(c1 >> 2)];
		c1 = (c1 & 0x03) << 4;
		if (p >= data + len) {
			*bp++ = Base64Code[c1];
			break;
		}
		c2 = *p++;
		c1 |= (c2 >> 4) & 0x0f;
		*bp++ = Base64Code[c1];
		c1 = (c2 & 0x0f) << 2;
		if (p >= data + len) {
			*bp++ = Base64Code[c1];
			break;
		}
		c2 = *p++;
		c1 |= (c2 >> 6) & 0x03;
		*bp++ = Base64Code[c1];
		*bp++ = Base64Code[c2 & 0x3f];
	}
	*bp = '\0';
}

/*
 * classic interface
 */
char *
bcrypt_gensalt(u_int8_t log_rounds)
{
	static char    gsalt[7 + (BCRYPT_MAXSALT * 4 + 2) / 3 + 1];

	bcrypt_initsalt(log_rounds, gsalt, sizeof(gsalt));

	return gsalt;
}

char *
bcrypt(const char *pass, const char *salt)
{
	static char    gencrypted[_PASSWORD_LEN];
	static char    gerror[] = ":";

	/* How do I handle errors ? Return ':' */
	if (bcrypt_hashpass(pass, salt, gencrypted, sizeof(gencrypted)) != 0)
		return gerror;

	return gencrypted;
}

