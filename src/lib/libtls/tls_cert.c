/* $OpenBSD: tls_verify.c,v 1.7 2015/02/11 06:46:33 jsing Exp $ */
/*
 * Copyright (c) 2014 Jeremie Courreges-Anglas <jca@openbsd.org>
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

#include <sys/socket.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <string.h>

#include <openssl/x509v3.h>
#include <openssl/evp.h>

#include <tls.h>
#include "tls_internal.h"

/*
 * Load cert data from X509 cert.
 */

/* Convert ASN1_INTEGER to decimal string string */
static int
tls_parse_bigint(struct tls *ctx, const ASN1_INTEGER *asn1int, const char **dst_p)
{
	long small;
	BIGNUM *big;
	char *tmp, buf[64];

	*dst_p = NULL;
	small = ASN1_INTEGER_get(asn1int);
	if (small < 0) {
		big = ASN1_INTEGER_to_BN(asn1int, NULL);
		if (big) {
			tmp = BN_bn2dec(big);
			if (tmp)
				*dst_p = strdup(tmp);
			OPENSSL_free(tmp);
		}
		BN_free(big);
	} else {
		snprintf(buf, sizeof buf, "%lu", small);
		*dst_p = strdup(buf);
	}
	if (*dst_p)
		return 0;

	tls_set_error(ctx, "cannot parse serial");
	return -1;
}

/* Convert ASN1_TIME to ISO 8601 string */
static int
tls_parse_time(struct tls *ctx, const ASN1_TIME *asn1time, const char **dst_p)
{
	static const char months[12][4] = {
		"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
	};
	char buf[128], *tmp, *mon, *day, *time, *year, *tz;
	char buf2[128];
	BIO *bio;
	int ret, i;

	*dst_p = NULL;

	memset(buf, 0, sizeof buf);
	bio = BIO_new(BIO_s_mem());
	if (!bio)
		goto nomem;

	/* result: Aug 18 20:51:52 2015 GMT */
	ret = ASN1_TIME_print(bio, asn1time);
	if (!ret) {
		BIO_free(bio);
		goto nomem;
	}
	BIO_read(bio, buf, sizeof(buf) - 1);
	BIO_free(bio);
	memcpy(buf2, buf, 128);

	/* "Jan  1" */
	if (buf[3] == ' ' && buf[4] == ' ')
		buf[4] = '0';

	tmp = buf;
	mon = strsep(&tmp, " ");
	day = strsep(&tmp, " ");
	time = strsep(&tmp, " ");
	year = strsep(&tmp, " ");
	tz = strsep(&tmp, " ");

	if (!year || tmp) {
		tls_set_error(ctx, "invalid time format: no year: %s", buf2);
		return -1;
		goto invalid;
	}
	if (tz && strcmp(tz, "GMT") != 0)
		goto invalid;

	for (i = 0; i < 12; i++) {
		if (memcmp(months[i], mon, 4) == 0)
			break;
	}
	if (i > 11)
		goto invalid;

	ret = asprintf(&tmp, "%s-%02d-%sT%sZ", year, i+1, day, time);
	if (ret < 0)
		goto nomem;
	*dst_p = tmp;
	return 0;

invalid:
	tls_set_error(ctx, "invalid time format");
	return -1;
nomem:
	tls_set_error(ctx, "no mem to parse time");
	return -1;
}

/*
 * Decode all string types used in RFC5280.
 *
 * OpenSSL used (before Jun 1 2014 commit) to pick between PrintableString,
 * T61String, BMPString and UTF8String, depending on data.  This code
 * tries to match that.
 *
 * Disallow any ancient ASN.1 escape sequences.
 */

static int
tls_parse_asn1string(struct tls *ctx, ASN1_STRING *a1str, const char **dst_p, int minchars, int maxchars)
{
	int format, len, i, ret = -1;
	unsigned char *data, c;
	ASN1_STRING *a1utf = NULL;
	int ascii_only = 0;
	char *cstr = NULL;
	int mbres, mbconvert = -1;

	*dst_p = NULL;

	format = ASN1_STRING_type(a1str);
	data = ASN1_STRING_data(a1str);
	len = ASN1_STRING_length(a1str);
	if (len < minchars) {
		tls_set_error(ctx, "invalid length");
		goto failed;
	}

	switch (format) {
	case V_ASN1_NUMERICSTRING:
	case V_ASN1_VISIBLESTRING:
	case V_ASN1_PRINTABLESTRING:
	case V_ASN1_IA5STRING:
		/* Ascii */
		if (len > maxchars) {
			tls_set_error(ctx, "invalid length");
			goto failed;
		}
		ascii_only = 1;
		break;
	case V_ASN1_T61STRING:
		/* Latin1 */
		mbconvert = MBSTRING_ASC;
		break;
	case V_ASN1_BMPSTRING:
		/* UCS-16BE */
		mbconvert = MBSTRING_BMP;
		break;
	case V_ASN1_UNIVERSALSTRING:
		/* UCS-32BE */
		mbconvert = MBSTRING_UNIV;
		break;
	case V_ASN1_UTF8STRING:
		/*
		 * UTF-8 - could be used directly if OpenSSL has already
		 * validated the data.  ATM be safe and validate here.
		 */
		mbconvert = MBSTRING_UTF8;
		break;
	default:
		tls_set_error(ctx, "invalid string type");
		goto failed;
	}

	/* Convert to UTF-8 */
	if (mbconvert != -1) {
		mbres = ASN1_mbstring_ncopy(&a1utf, data, len, mbconvert, B_ASN1_UTF8STRING, minchars, maxchars);
		if (mbres < 0) {
			tls_set_error(ctx, "multibyte conversion failed");
			goto failed;
		}
		data = ASN1_STRING_data(a1utf);
		len = ASN1_STRING_length(a1utf);
	}

	/* Now we have utf8 string, check for crap */
	for (i = 0; i < len; i++) {
		c = data[i];

		/* ascii control chars, inluding NUL */
		if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') {
			tls_set_error(ctx, "invalid C0 control char");
			goto failed;
		}

		/* C1 control chars in UTF-8: \xc2\x80 - \xc2\x9f */
		if (c == 0xC2 && data[i+1] >= 0x80 && data[i+1] <= 0x9F) {
			tls_set_error(ctx, "invalid C1 control char");
			goto failed;
		}

		/* ascii DEL */
		if (c == 0x7F) {
			tls_set_error(ctx, "invalid DEL char");
			goto failed;
		}

		/* non-ascii */
		if (ascii_only && (c & 0x80) != 0) {
			tls_set_error(ctx, "8-bit chars not allowed");
			goto failed;
		}
	}

	/* copy to new string */
	cstr = malloc(len + 1);
	if (!cstr) {
		tls_set_error(ctx, "no mem");
		goto failed;
	}
	memcpy(cstr, data, len);
	cstr[len] = 0;
	*dst_p = cstr;
	ret = len;
failed:
	ASN1_STRING_free(a1utf);
	return ret;
}

static int
tls_cert_get_dname_string(struct tls *ctx, X509_NAME *name, int nid, const char **str_p, int minchars, int maxchars)
{
	int loc, len;
	X509_NAME_ENTRY *ne;
	ASN1_STRING *a1str;

	*str_p = NULL;

	loc = X509_NAME_get_index_by_NID(name, nid, -1);
	if (loc < 0)
		return 0;
	ne = X509_NAME_get_entry(name, loc);
	if (!ne)
		return 0;
	a1str = X509_NAME_ENTRY_get_data(ne);
	if (!a1str)
		return 0;
	len = tls_parse_asn1string(ctx, a1str, str_p, minchars, maxchars);
	if (len < 0)
		return -1;
	return 0;
}

static int
tls_load_alt_ia5string(struct tls *ctx, ASN1_IA5STRING *ia5str, struct tls_cert *cert, int slot_type, int minchars, int maxchars)
{
	struct tls_cert_alt_name *slot;
	const char *data;
	int len;

	slot = &cert->subject_alt_names[cert->subject_alt_name_count];

	len = tls_parse_asn1string(ctx, ia5str, &data, minchars, maxchars);
	if (len < 0)
		return 0;

	/*
	 * Per RFC 5280 section 4.2.1.6:
	 * " " is a legal domain name, but that
	 * dNSName must be rejected.
	 */
	if (len == 1 && data[0] == ' ') {
		tls_set_error(ctx, "single space as name");
		return -1;
	}

	slot->alt_name = data;
	slot->alt_name_type = slot_type;

	cert->subject_alt_name_count++;
	return 0;
}

static int
tls_load_alt_ipaddr(struct tls *ctx, ASN1_OCTET_STRING *bin, struct tls_cert *cert)
{
	struct tls_cert_alt_name *slot;
	void *data;
	int len;

	slot = &cert->subject_alt_names[cert->subject_alt_name_count];
	len = ASN1_STRING_length(bin);
	data = ASN1_STRING_data(bin);
	if (len < 0) {
		tls_set_error(ctx, "negative length for ipaddress");
		return -1;
	}

	/*
	 * Per RFC 5280 section 4.2.1.6:
	 * IPv4 must use 4 octets and IPv6 must use 16 octets.
	 */
	if (len == 4) {
		slot->alt_name_type = TLS_CERT_NAME_IPv4;
	} else if (len == 16) {
		slot->alt_name_type = TLS_CERT_NAME_IPv6;
	} else {
		tls_set_error(ctx, "invalid length for ipaddress");
		return -1;
	}

	slot->alt_name = malloc(len);
	if (slot->alt_name == NULL) {
		tls_set_error(ctx, "no mem");
		return -1;
	}

	memcpy((void *)slot->alt_name, data, len);
	cert->subject_alt_name_count++;
	return 0;
}

/* See RFC 5280 section 4.2.1.6 for SubjectAltName details. */
static int
tls_cert_get_altnames(struct tls *ctx, struct tls_cert *cert, X509 *x509_cert)
{
	STACK_OF(GENERAL_NAME) *altname_stack = NULL;
	GENERAL_NAME *altname;
	int count, i;
	int rv = -1;

	altname_stack = X509_get_ext_d2i(x509_cert, NID_subject_alt_name, NULL, NULL);
	if (altname_stack == NULL)
		return 0;

	count = sk_GENERAL_NAME_num(altname_stack);
	if (count == 0) {
		rv = 0;
		goto out;
	}

	cert->subject_alt_names = calloc(sizeof (struct tls_cert_alt_name), count);
	if (cert->subject_alt_names == NULL) {
		tls_set_error(ctx, "no mem");
		goto out;
	}

	for (i = 0; i < count; i++) {
		altname = sk_GENERAL_NAME_value(altname_stack, i);

		if (altname->type == GEN_DNS) {
			rv = tls_load_alt_ia5string(ctx, altname->d.dNSName, cert, TLS_CERT_NAME_DNS, 1, 64);
		} else if (altname->type == GEN_EMAIL) {
			rv = tls_load_alt_ia5string(ctx, altname->d.rfc822Name, cert, TLS_CERT_NAME_EMAIL, 1, 255);
		} else if (altname->type == GEN_URI) {
			rv = tls_load_alt_ia5string(ctx, altname->d.uniformResourceIdentifier, cert, TLS_CERT_NAME_URI, 1, 255);
		} else if (altname->type == GEN_IPADD) {
			rv = tls_load_alt_ipaddr(ctx, altname->d.iPAddress, cert);
		} else {
			/* ignore unknown types */
		}
		if (rv < 0)
			goto out;
	}
	rv = 0;
out:
	sk_GENERAL_NAME_pop_free(altname_stack, GENERAL_NAME_free);
	return rv;
}

static int
tls_get_dname(struct tls *ctx, X509_NAME *name, struct tls_cert_dname *dname)
{
	int ret;
	ret = tls_cert_get_dname_string(ctx, name, NID_commonName, &dname->common_name, 1, 64);
	if (ret == 0)
		ret = tls_cert_get_dname_string(ctx, name, NID_countryName, &dname->country_name, 2, 2);
	if (ret == 0)
		ret = tls_cert_get_dname_string(ctx, name, NID_stateOrProvinceName, &dname->state_or_province_name, 1, 128);
	if (ret == 0)
		ret = tls_cert_get_dname_string(ctx, name, NID_localityName, &dname->locality_name, 1, 128);
	if (ret == 0)
		ret = tls_cert_get_dname_string(ctx, name, NID_streetAddress, &dname->street_address, 1, 128);
	if (ret == 0)
		ret = tls_cert_get_dname_string(ctx, name, NID_organizationName, &dname->organization_name, 1, 64);
	if (ret == 0)
		ret = tls_cert_get_dname_string(ctx, name, NID_organizationalUnitName, &dname->organizational_unit_name, 1, 64);
	return ret;
}

static void *
tls_calc_fingerprint(struct tls *ctx, X509 *x509, const char *algo, size_t *outlen)
{
	const EVP_MD *md;
	void *res;
	int ret;
	unsigned int tmplen, mdlen;

	if (outlen)
		*outlen = 0;

	if (strcasecmp(algo, "sha1") == 0) {
		md = EVP_sha1();
	} else if (strcasecmp(algo, "sha256") == 0) {
		md = EVP_sha256();
	} else {
		tls_set_error(ctx, "invalid fingerprint algorithm");
		return NULL;
	}

	mdlen = EVP_MD_size(md);
	res = malloc(mdlen);
	if (!res) {
		tls_set_error(ctx, "no mem");
		return NULL;
	}

	ret = X509_digest(x509, md, res, &tmplen);
	if (ret != 1 || tmplen != mdlen) {
		free(res);
		tls_set_error(ctx, "X509_digest failed");
		return NULL;
	}

	if (outlen)
		*outlen = mdlen;

	return res;
}

static void
check_verify_error(struct tls *ctx, struct tls_cert *cert)
{
	long vres = SSL_get_verify_result(ctx->ssl_conn);
	if (vres == X509_V_OK) {
		cert->successful_verify = 1;
	} else {
		cert->successful_verify = 0;
	}
}

int
tls_get_peer_cert(struct tls *ctx, struct tls_cert **cert_p, const char *fingerprint_algo)
{
	struct tls_cert *cert = NULL;
	SSL *conn = ctx->ssl_conn;
	X509 *peer;
	X509_NAME *subject, *issuer;
	int ret = -1;
	long version;

	*cert_p = NULL;

	if (!conn) {
		tls_set_error(ctx, "not connected");
		return -1;
	}

	peer = SSL_get_peer_certificate(conn);
	if (!peer) {
		tls_set_error(ctx, "peer does not have cert");
		return TLS_NO_CERT;
	}

	version = X509_get_version(peer);
	if (version < 0) {
		tls_set_error(ctx, "invalid version");
		return -1;
	}

	subject = X509_get_subject_name(peer);
	if (!subject) {
		tls_set_error(ctx, "cert does not have subject");
		return -1;
	}

	issuer = X509_get_issuer_name(peer);
	if (!issuer) {
		tls_set_error(ctx, "cert does not have issuer");
		return -1;
	}

	cert = calloc(sizeof *cert, 1);
	if (!cert) {
		tls_set_error(ctx, "calloc failed");
		goto failed;
	}
	cert->version = version;

	if (fingerprint_algo) {
		cert->fingerprint = tls_calc_fingerprint(ctx, peer, fingerprint_algo, &cert->fingerprint_size);
		if (!cert->fingerprint)
			goto failed;
	}

	ret = tls_get_dname(ctx, subject, &cert->subject);
	if (ret == 0)
		ret = tls_get_dname(ctx, issuer, &cert->issuer);
	if (ret == 0)
		ret = tls_cert_get_altnames(ctx, cert, peer);
	if (ret == 0)
		ret = tls_parse_time(ctx, X509_get_notBefore(peer), &cert->not_before);
	if (ret == 0)
		ret = tls_parse_time(ctx, X509_get_notAfter(peer), &cert->not_after);
	if (ret == 0)
		ret = tls_parse_bigint(ctx, X509_get_serialNumber(peer), &cert->serial);
	if (ret == 0) {
		check_verify_error(ctx, cert);
		*cert_p = cert;
		return 0;
	}
failed:
	tls_cert_free(cert);
	return ret;
}

static void
tls_cert_free_dname(struct tls_cert_dname *dname)
{
	free((void*)dname->common_name);
	free((void*)dname->country_name);
	free((void*)dname->state_or_province_name);
	free((void*)dname->locality_name);
	free((void*)dname->street_address);
	free((void*)dname->organization_name);
	free((void*)dname->organizational_unit_name);
}

void
tls_cert_free(struct tls_cert *cert)
{
	int i;
	if (!cert)
		return;

	tls_cert_free_dname(&cert->issuer);
	tls_cert_free_dname(&cert->subject);

	if (cert->subject_alt_name_count) {
		for (i = 0; i < cert->subject_alt_name_count; i++)
			free((void*)cert->subject_alt_names[i].alt_name);
	}
	free(cert->subject_alt_names);

	free((void*)cert->serial);
	free((void*)cert->not_before);
	free((void*)cert->not_after);
	free((void*)cert->fingerprint);
	free(cert);
}

