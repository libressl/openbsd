/*	$OpenBSD: bytestringtest.c,v 1.5 2015/06/16 06:37:58 doug Exp $	*/
/*
 * Copyright (c) 2014, Google Inc.
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
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>

#include "bytestring.h"

/* This is from <openssl/base.h> in boringssl */
#define OPENSSL_U64(x) x##ULL

static int
test_skip(void)
{
	static const uint8_t kData[] = {1, 2, 3};
	CBS data;

	CBS_init(&data, kData, sizeof(kData));
	return CBS_len(&data) == 3 &&
	    CBS_skip(&data, 1) &&
	    CBS_len(&data) == 2 &&
	    CBS_skip(&data, 2) &&
	    CBS_len(&data) == 0 &&
	    !CBS_skip(&data, 1);
}

static int
test_get_u(void)
{
	static const uint8_t kData[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
	uint8_t u8;
	uint16_t u16;
	uint32_t u32;
	CBS data;

	CBS_init(&data, kData, sizeof(kData));
	return CBS_get_u8(&data, &u8) &&
	    u8 == 1 &&
	    CBS_get_u16(&data, &u16) &&
	    u16 == 0x203 &&
	    CBS_get_u24(&data, &u32) &&
	    u32 == 0x40506 &&
	    CBS_get_u32(&data, &u32) &&
	    u32 == 0x708090a &&
	    !CBS_get_u8(&data, &u8);
}

static int
test_get_prefixed(void)
{
	static const uint8_t kData[] = {1, 2, 0, 2, 3, 4, 0, 0, 3, 3, 2, 1};
	uint8_t u8;
	uint16_t u16;
	uint32_t u32;
	CBS data, prefixed;

	CBS_init(&data, kData, sizeof(kData));
	return CBS_get_u8_length_prefixed(&data, &prefixed) &&
	    CBS_len(&prefixed) == 1 &&
	    CBS_get_u8(&prefixed, &u8) &&
	    u8 == 2 &&
	    CBS_get_u16_length_prefixed(&data, &prefixed) &&
	    CBS_len(&prefixed) == 2 &&
	    CBS_get_u16(&prefixed, &u16) &&
	    u16 == 0x304 &&
	    CBS_get_u24_length_prefixed(&data, &prefixed) &&
	    CBS_len(&prefixed) == 3 &&
	    CBS_get_u24(&prefixed, &u32) &&
	    u32 == 0x30201;
}

static int
test_get_prefixed_bad(void)
{
	static const uint8_t kData1[] = {2, 1};
	static const uint8_t kData2[] = {0, 2, 1};
	static const uint8_t kData3[] = {0, 0, 2, 1};
	CBS data, prefixed;

	CBS_init(&data, kData1, sizeof(kData1));
	if (CBS_get_u8_length_prefixed(&data, &prefixed))
		return 0;

	CBS_init(&data, kData2, sizeof(kData2));
	if (CBS_get_u16_length_prefixed(&data, &prefixed))
		return 0;

	CBS_init(&data, kData3, sizeof(kData3));
	if (CBS_get_u24_length_prefixed(&data, &prefixed))
		return 0;

	return 1;
}

static int
test_get_asn1(void)
{
	static const uint8_t kData1[] = {0x30, 2, 1, 2};
	static const uint8_t kData2[] = {0x30, 3, 1, 2};
	static const uint8_t kData3[] = {0x30, 0x80};
	static const uint8_t kData4[] = {0x30, 0x81, 1, 1};
	static const uint8_t kData5[] = {0x30, 0x82, 0, 1, 1};
	static const uint8_t kData6[] = {0xa1, 3, 0x4, 1, 1};
	static const uint8_t kData7[] = {0xa1, 3, 0x4, 2, 1};
	static const uint8_t kData8[] = {0xa1, 3, 0x2, 1, 1};
	static const uint8_t kData9[] = {0xa1, 3, 0x2, 1, 0xff};

	CBS data, contents;
	int present;
	uint64_t value;

	CBS_init(&data, kData1, sizeof(kData1));
	if (CBS_peek_asn1_tag(&data, 0x1) || !CBS_peek_asn1_tag(&data, 0x30))
		return 0;

	if (!CBS_get_asn1(&data, &contents, 0x30) ||
	    CBS_len(&contents) != 2 ||
	    memcmp(CBS_data(&contents), "\x01\x02", 2) != 0)
		return 0;

	CBS_init(&data, kData2, sizeof(kData2));
	/* data is truncated */
	if (CBS_get_asn1(&data, &contents, 0x30))
		return 0;

	CBS_init(&data, kData3, sizeof(kData3));
	/* zero byte length of length */
	if (CBS_get_asn1(&data, &contents, 0x30))
		return 0;

	CBS_init(&data, kData4, sizeof(kData4));
	/* long form mistakenly used. */
	if (CBS_get_asn1(&data, &contents, 0x30))
		return 0;

	CBS_init(&data, kData5, sizeof(kData5));
	/* length takes too many bytes. */
	if (CBS_get_asn1(&data, &contents, 0x30))
		return 0;

	CBS_init(&data, kData1, sizeof(kData1));
	/* wrong tag. */
	if (CBS_get_asn1(&data, &contents, 0x31))
		return 0;

	CBS_init(&data, NULL, 0);
	/* peek at empty data. */
	if (CBS_peek_asn1_tag(&data, 0x30))
		return 0;

	CBS_init(&data, NULL, 0);
	/* optional elements at empty data. */
	if (!CBS_get_optional_asn1(&data, &contents, &present, 0xa0) ||
	    present ||
	    !CBS_get_optional_asn1_octet_string(&data, &contents, &present,
	    0xa0) ||
	    present ||
	    CBS_len(&contents) != 0 ||
	    !CBS_get_optional_asn1_octet_string(&data, &contents, NULL, 0xa0) ||
	    CBS_len(&contents) != 0 ||
	    !CBS_get_optional_asn1_uint64(&data, &value, 0xa0, 42) ||
	    value != 42)
		return 0;

	CBS_init(&data, kData6, sizeof(kData6));
	/* optional element. */
	if (!CBS_get_optional_asn1(&data, &contents, &present, 0xa0) ||
	    present ||
	    !CBS_get_optional_asn1(&data, &contents, &present, 0xa1) ||
	    !present ||
	    CBS_len(&contents) != 3 ||
	    memcmp(CBS_data(&contents), "\x04\x01\x01", 3) != 0)
		return 0;

	CBS_init(&data, kData6, sizeof(kData6));
	/* optional octet string. */
	if (!CBS_get_optional_asn1_octet_string(&data, &contents, &present,
	    0xa0) ||
	    present ||
	    CBS_len(&contents) != 0 ||
	    !CBS_get_optional_asn1_octet_string(&data, &contents, &present,
	    0xa1) ||
	    !present ||
	    CBS_len(&contents) != 1 ||
	    CBS_data(&contents)[0] != 1)
		return 0;

	CBS_init(&data, kData7, sizeof(kData7));
	/* invalid optional octet string. */
	if (CBS_get_optional_asn1_octet_string(&data, &contents, &present,
	    0xa1))
		return 0;

	CBS_init(&data, kData8, sizeof(kData8));
	/* optional octet string. */
	if (!CBS_get_optional_asn1_uint64(&data, &value, 0xa0, 42) ||
	    value != 42 ||
	    !CBS_get_optional_asn1_uint64(&data, &value, 0xa1, 42) ||
	    value != 1)
		return 0;

	CBS_init(&data, kData9, sizeof(kData9));
	/* invalid optional integer. */
	if (CBS_get_optional_asn1_uint64(&data, &value, 0xa1, 42))
		return 0;

	return 1;
}

static int
test_get_optional_asn1_bool(void)
{
	CBS data;
	int val;

	static const uint8_t kTrue[] = {0x0a, 3, CBS_ASN1_BOOLEAN, 1, 0xff};
	static const uint8_t kFalse[] = {0x0a, 3, CBS_ASN1_BOOLEAN, 1, 0x00};
	static const uint8_t kInvalid[] = {0x0a, 3, CBS_ASN1_BOOLEAN, 1, 0x01};

	CBS_init(&data, NULL, 0);
	val = 2;
	if (!CBS_get_optional_asn1_bool(&data, &val, 0x0a, 0) || val != 0)
		return 0;

	CBS_init(&data, kTrue, sizeof(kTrue));
	val = 2;
	if (!CBS_get_optional_asn1_bool(&data, &val, 0x0a, 0) || val != 1)
		return 0;

	CBS_init(&data, kFalse, sizeof(kFalse));
	val = 2;
	if (!CBS_get_optional_asn1_bool(&data, &val, 0x0a, 1) || val != 0)
		return 0;

	CBS_init(&data, kInvalid, sizeof(kInvalid));
	if (CBS_get_optional_asn1_bool(&data, &val, 0x0a, 1))
		return 0;

	return 1;
}

static int
test_cbb_basic(void)
{
	static const uint8_t kExpected[] = {1, 2, 3, 4, 5, 6, 7, 8};
	uint8_t *buf;
	size_t buf_len;
	int ok;
	CBB cbb;

	if (!CBB_init(&cbb, 100))
		return 0;

	CBB_cleanup(&cbb);

	if (!CBB_init(&cbb, 0) ||
	    !CBB_add_u8(&cbb, 1) ||
	    !CBB_add_u16(&cbb, 0x203) ||
	    !CBB_add_u24(&cbb, 0x40506) ||
	    !CBB_add_bytes(&cbb, (const uint8_t*) "\x07\x08", 2) ||
	    !CBB_finish(&cbb, &buf, &buf_len))
		return 0;

	ok = buf_len == sizeof(kExpected) && memcmp(buf, kExpected, buf_len)
	    == 0;
	free(buf);
	return ok;
}

static int
test_cbb_fixed(void)
{
	CBB cbb;
	uint8_t buf[1];
	uint8_t *out_buf;
	size_t out_size;

	if (!CBB_init_fixed(&cbb, NULL, 0) ||
	    CBB_add_u8(&cbb, 1) ||
	    !CBB_finish(&cbb, &out_buf, &out_size) ||
	    out_buf != NULL ||
	    out_size != 0)
		return 0;

	if (!CBB_init_fixed(&cbb, buf, 1) ||
	    !CBB_add_u8(&cbb, 1) ||
	    CBB_add_u8(&cbb, 2) ||
	    !CBB_finish(&cbb, &out_buf, &out_size) ||
	    out_buf != buf ||
	    out_size != 1 ||
	    buf[0] != 1)
		return 0;

	return 1;
}

static int
test_cbb_finish_child(void)
{
	CBB cbb, child;
	uint8_t *out_buf = NULL;
	size_t out_size;
	int ret = 0;

	if (!CBB_init(&cbb, 16) ||
	    !CBB_add_u8_length_prefixed(&cbb, &child) ||
	    CBB_finish(&child, &out_buf, &out_size) ||
	    !CBB_finish(&cbb, &out_buf, &out_size) ||
	    out_size != 1 ||
	    out_buf[0] != 0)
		goto err;

	ret = 1;

err:
	free(out_buf);
	return ret;
}

static int
test_cbb_prefixed(void)
{
	static const uint8_t kExpected[] = {0, 1, 1, 0, 2, 2, 3, 0, 0, 3,
	    4, 5, 6, 5, 4, 1, 0, 1, 2};
	uint8_t *buf = NULL;
	size_t buf_len;
	CBB cbb, contents, inner_contents, inner_inner_contents;
	int ok = 0;

	if (!CBB_init(&cbb, 0) ||
	    !CBB_add_u8_length_prefixed(&cbb, &contents) ||
	    !CBB_add_u8_length_prefixed(&cbb, &contents) ||
	    !CBB_add_u8(&contents, 1) ||
	    !CBB_add_u16_length_prefixed(&cbb, &contents) ||
	    !CBB_add_u16(&contents, 0x203) ||
	    !CBB_add_u24_length_prefixed(&cbb, &contents) ||
	    !CBB_add_u24(&contents, 0x40506) ||
	    !CBB_add_u8_length_prefixed(&cbb, &contents) ||
	    !CBB_add_u8_length_prefixed(&contents, &inner_contents) ||
	    !CBB_add_u8(&inner_contents, 1) ||
	    !CBB_add_u16_length_prefixed(&inner_contents,
	    &inner_inner_contents) ||
	    !CBB_add_u8(&inner_inner_contents, 2) ||
	    !CBB_finish(&cbb, &buf, &buf_len))
		goto err;

	ok = buf_len == sizeof(kExpected) && memcmp(buf, kExpected, buf_len)
	    == 0;

err:
	free(buf);
	return ok;
}

static int
test_cbb_misuse(void)
{
	CBB cbb, child, contents;
	uint8_t *buf = NULL;
	size_t buf_len;
	int ret = 0;

	if (!CBB_init(&cbb, 0) ||
	    !CBB_add_u8_length_prefixed(&cbb, &child) ||
	    !CBB_add_u8(&child, 1) ||
	    !CBB_add_u8(&cbb, 2))
		return 0;

	/*
	 * Since we wrote to |cbb|, |child| is now invalid and attempts to write
	 * to it should fail.
	 */
	if (CBB_add_u8(&child, 1) ||
	    CBB_add_u16(&child, 1) ||
	    CBB_add_u24(&child, 1) ||
	    CBB_add_u8_length_prefixed(&child, &contents) ||
	    CBB_add_u16_length_prefixed(&child, &contents) ||
	    CBB_add_asn1(&child, &contents, 1) ||
	    CBB_add_bytes(&child, (const uint8_t*) "a", 1)) {
		fprintf(stderr, "CBB operation on invalid CBB did not fail.\n");
		return 0;
	}

	if (!CBB_finish(&cbb, &buf, &buf_len) || buf_len != 3 ||
	    memcmp(buf, "\x01\x01\x02", 3) != 0)
		goto err;

	ret = 1;

err:
	free(buf);
	return ret;
}

static int
test_cbb_asn1(void)
{
	static const uint8_t kExpected[] = {0x30, 3, 1, 2, 3};
	uint8_t *buf = NULL, *test_data = NULL;
	size_t buf_len;
	CBB cbb, contents, inner_contents;
	int ret = 0;

	if (!CBB_init(&cbb, 0) ||
	    !CBB_add_asn1(&cbb, &contents, 0x30) ||
	    !CBB_add_bytes(&contents, (const uint8_t*) "\x01\x02\x03", 3) ||
	    !CBB_finish(&cbb, &buf, &buf_len))
		goto err;

	if (buf_len != sizeof(kExpected) || memcmp(buf, kExpected, buf_len)
	    != 0)
		goto err;

	free(buf);
	buf = NULL;

	if ((test_data = malloc(100000)) == NULL)
		goto err;
	memset(test_data, 0x42, 100000);

	if (!CBB_init(&cbb, 0) ||
	    !CBB_add_asn1(&cbb, &contents, 0x30) ||
	    !CBB_add_bytes(&contents, test_data, 130) ||
	    !CBB_finish(&cbb, &buf, &buf_len))
		goto err;

	if (buf_len != 3 + 130 ||
	    memcmp(buf, "\x30\x81\x82", 3) != 0 ||
	    memcmp(buf + 3, test_data, 130) != 0) {
		goto err;
	}
	free(buf);
	buf = NULL;

	if (!CBB_init(&cbb, 0) ||
	    !CBB_add_asn1(&cbb, &contents, 0x30) ||
	    !CBB_add_bytes(&contents, test_data, 1000) ||
	    !CBB_finish(&cbb, &buf, &buf_len))
		goto err;

	if (buf_len != 4 + 1000 ||
	    memcmp(buf, "\x30\x82\x03\xe8", 4) != 0 ||
	    memcmp(buf + 4, test_data, 1000)) {
		goto err;
	}
	free(buf);
	buf = NULL;

	if (!CBB_init(&cbb, 0) ||
	    !CBB_add_asn1(&cbb, &contents, 0x30) ||
	    !CBB_add_asn1(&contents, &inner_contents, 0x30) ||
	    !CBB_add_bytes(&inner_contents, test_data, 100000) ||
	    !CBB_finish(&cbb, &buf, &buf_len))
		goto err;

	if (buf_len != 5 + 5 + 100000 ||
	    memcmp(buf, "\x30\x83\x01\x86\xa5\x30\x83\x01\x86\xa0", 10) != 0 ||
	    memcmp(buf + 10, test_data, 100000))
		goto err;

	ret = 1;

err:
	free(buf);
	free(test_data);

	return ret;
}

static int
do_indefinite_convert(const char *name, const uint8_t *definite_expected,
    size_t definite_len, const uint8_t *indefinite, size_t indefinite_len)
{
	CBS in;
	uint8_t *out = NULL;
	size_t out_len;
	int ret = 0;

	CBS_init(&in, indefinite, indefinite_len);
	if (!CBS_asn1_indefinite_to_definite(&in, &out, &out_len)) {
		fprintf(stderr, "%s: CBS_asn1_indefinite_to_definite failed.\n",
		    name);
		goto end;
	}

	if (out == NULL) {
		if (indefinite_len != definite_len ||
		    memcmp(definite_expected, indefinite, indefinite_len)
		    != 0) {
			fprintf(stderr, "%s: incorrect unconverted result.\n",
			    name);
			return 0;
		}

		return 1;
	}

	if (out_len != definite_len || memcmp(out, definite_expected,
	    definite_len) != 0) {
		fprintf(stderr, "%s: incorrect converted result.\n", name);
		goto end;
	}

	ret = 1;

end:
	free(out);
	return ret;
}

static int
test_indefinite_convert(void)
{
	static const uint8_t kSimpleBER[] = {0x01, 0x01, 0x00};

	/* kIndefBER contains a SEQUENCE with an indefinite length. */
	static const uint8_t kIndefBER[] = {0x30, 0x80, 0x01, 0x01, 0x02, 0x00,
	    0x00};
	static const uint8_t kIndefDER[] = {0x30, 0x03, 0x01, 0x01, 0x02};

	/*
	 * kOctetStringBER contains an indefinite length OCTETSTRING with two
	 * parts.  These parts need to be concatenated in DER form.
	 */
	static const uint8_t kOctetStringBER[] = {0x24, 0x80, 0x04, 0x02, 0,
	    1, 0x04, 0x02, 2,    3,    0x00, 0x00};
	static const uint8_t kOctetStringDER[] = {0x04, 0x04, 0, 1, 2, 3};

	/*
	 * kNSSBER is part of a PKCS#12 message generated by NSS that uses
	 * indefinite length elements extensively.
	 */
	static const uint8_t kNSSBER[] = {
	    0x30, 0x80, 0x02, 0x01, 0x03, 0x30, 0x80, 0x06, 0x09, 0x2a, 0x86,
	    0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01, 0xa0, 0x80, 0x24, 0x80,
	    0x04, 0x04, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
	    0x00, 0x30, 0x39, 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
	    0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14, 0x84, 0x98, 0xfc, 0x66,
	    0x33, 0xee, 0xba, 0xe7, 0x90, 0xc1, 0xb6, 0xe8, 0x8f, 0xfe, 0x1d,
	    0xc5, 0xa5, 0x97, 0x93, 0x3e, 0x04, 0x10, 0x38, 0x62, 0xc6, 0x44,
	    0x12, 0xd5, 0x30, 0x00, 0xf8, 0xf2, 0x1b, 0xf0, 0x6e, 0x10, 0x9b,
	    0xb8, 0x02, 0x02, 0x07, 0xd0, 0x00, 0x00,
	};

	static const uint8_t kNSSDER[] = {
	    0x30, 0x53, 0x02, 0x01, 0x03, 0x30, 0x13, 0x06, 0x09, 0x2a, 0x86,
	    0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01, 0xa0, 0x06, 0x04, 0x04,
	    0x01, 0x02, 0x03, 0x04, 0x30, 0x39, 0x30, 0x21, 0x30, 0x09, 0x06,
	    0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14, 0x84,
	    0x98, 0xfc, 0x66, 0x33, 0xee, 0xba, 0xe7, 0x90, 0xc1, 0xb6, 0xe8,
	    0x8f, 0xfe, 0x1d, 0xc5, 0xa5, 0x97, 0x93, 0x3e, 0x04, 0x10, 0x38,
	    0x62, 0xc6, 0x44, 0x12, 0xd5, 0x30, 0x00, 0xf8, 0xf2, 0x1b, 0xf0,
	    0x6e, 0x10, 0x9b, 0xb8, 0x02, 0x02, 0x07, 0xd0,
	};

	return do_indefinite_convert("kSimpleBER", kSimpleBER, sizeof(kSimpleBER),
	    kSimpleBER, sizeof(kSimpleBER)) &&
	    do_indefinite_convert("kIndefBER", kIndefDER, sizeof(kIndefDER), kIndefBER,
	    sizeof(kIndefBER)) &&
	    do_indefinite_convert("kOctetStringBER", kOctetStringDER,
	    sizeof(kOctetStringDER), kOctetStringBER,
	    sizeof(kOctetStringBER)) &&
	    do_indefinite_convert("kNSSBER", kNSSDER, sizeof(kNSSDER), kNSSBER,
	    sizeof(kNSSBER));
}

typedef struct {
	uint64_t value;
	const char *encoding;
	size_t encoding_len;
} ASN1_UINT64_TEST;

static const ASN1_UINT64_TEST kAsn1Uint64Tests[] = {
	{0, "\x02\x01\x00", 3},
	{1, "\x02\x01\x01", 3},
	{127, "\x02\x01\x7f", 3},
	{128, "\x02\x02\x00\x80", 4},
	{0xdeadbeef, "\x02\x05\x00\xde\xad\xbe\xef", 7},
	{OPENSSL_U64(0x0102030405060708),
	    "\x02\x08\x01\x02\x03\x04\x05\x06\x07\x08", 10},
	{OPENSSL_U64(0xffffffffffffffff),
	    "\x02\x09\x00\xff\xff\xff\xff\xff\xff\xff\xff", 11},
};

typedef struct {
	const char *encoding;
	size_t encoding_len;
} ASN1_INVALID_UINT64_TEST;

static const ASN1_INVALID_UINT64_TEST kAsn1InvalidUint64Tests[] = {
	/* Bad tag. */
	{"\x03\x01\x00", 3},
	/* Empty contents. */
	{"\x02\x00", 2},
	/* Negative number. */
	{"\x02\x01\x80", 3},
	/* Overflow. */
	{"\x02\x09\x01\x00\x00\x00\x00\x00\x00\x00\x00", 11},
	/* Leading zeros. */
	{"\x02\x02\x00\x01", 4},
};

static int
test_asn1_uint64(void)
{
	size_t i;

	for (i = 0; i < sizeof(kAsn1Uint64Tests) / sizeof(kAsn1Uint64Tests[0]);
	     i++) {
		const ASN1_UINT64_TEST *test = &kAsn1Uint64Tests[i];
		CBS cbs;
		uint64_t value;
		CBB cbb;
		uint8_t *out;
		size_t len;

		CBS_init(&cbs, (const uint8_t *)test->encoding,
		    test->encoding_len);

		if (!CBS_get_asn1_uint64(&cbs, &value) ||
		    CBS_len(&cbs) != 0 ||
		    value != test->value)
			return 0;

		if (!CBB_init(&cbb, 0))
			return 0;

		if (!CBB_add_asn1_uint64(&cbb, test->value) ||
		    !CBB_finish(&cbb, &out, &len)) {
			CBB_cleanup(&cbb);
			return 0;
		}

		if (len != test->encoding_len || memcmp(out, test->encoding,
		    len) != 0) {
			free(out);
			return 0;
		}
		free(out);
	}

	for (i = 0; i < sizeof(kAsn1InvalidUint64Tests)
	    / sizeof(kAsn1InvalidUint64Tests[0]); i++) {
		const ASN1_INVALID_UINT64_TEST *test =
		    &kAsn1InvalidUint64Tests[i];
		CBS cbs;
		uint64_t value;

		CBS_init(&cbs, (const uint8_t *)test->encoding,
		    test->encoding_len);
		if (CBS_get_asn1_uint64(&cbs, &value))
			return 0;
	}

	return 1;
}

int
main(void)
{
	if (!test_skip() ||
	    !test_get_u() ||
	    !test_get_prefixed() ||
	    !test_get_prefixed_bad() ||
	    !test_get_asn1() ||
	    !test_cbb_basic() ||
	    !test_cbb_fixed() ||
	    !test_cbb_finish_child() ||
	    !test_cbb_misuse() ||
	    !test_cbb_prefixed() ||
	    !test_cbb_asn1() ||
	    !test_indefinite_convert() ||
	    !test_asn1_uint64() ||
	    !test_get_optional_asn1_bool())
		return 1;

	printf("PASS\n");
	return 0;
}
