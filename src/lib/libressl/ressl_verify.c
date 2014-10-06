/* $OpenBSD: ressl_verify.c,v 1.4 2014/10/06 11:53:18 jca Exp $ */
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

#include "ressl_internal.h"

int ressl_match_hostname(const char *cert_hostname, const char *hostname);
int ressl_check_subject_altname(X509 *cert, const char *host);
int ressl_check_common_name(X509 *cert, const char *host);

int
ressl_match_hostname(const char *cert_hostname, const char *hostname)
{
	const char *cert_domain, *domain, *next_dot;

	if (strcasecmp(cert_hostname, hostname) == 0)
		return 0;

	/* Wildcard match? */
	if (cert_hostname[0] == '*') {
		/*
		 * Valid wildcards:
		 * - "*.domain.tld"
		 * - "*.sub.domain.tld"
		 * - etc.
		 * Reject "*.tld".
		 * No attempt to prevent the use of eg. "*.co.uk".
		 */
		cert_domain = &cert_hostname[1];
		/* Disallow "*"  */
		if (cert_domain[0] == '\0')
			return -1;
		/* Disallow "*foo" */
		if (cert_domain[0] != '.')
			return -1;
		/* Disallow "*.." */
		if (cert_domain[1] == '.')
			return -1;
		next_dot = strchr(&cert_domain[1], '.');
		/* Disallow "*.bar" */
		if (next_dot == NULL)
			return -1;
		/* Disallow "*.bar.." */
		if (next_dot[1] == '.')
			return -1;

		domain = strchr(hostname, '.');

		/* No wildcard match against a hostname with no domain part. */
		if (domain == NULL || strlen(domain) == 1)
			return -1;

		if (strcasecmp(cert_domain, domain) == 0)
			return 0;
	}

	return -1;
}

int
ressl_check_subject_altname(X509 *cert, const char *host)
{
	STACK_OF(GENERAL_NAME) *altname_stack = NULL;
	union { struct in_addr ip4; struct in6_addr ip6; } addrbuf;
	int addrlen, type;
	int count, i;
	int rv = -1;

	altname_stack = X509_get_ext_d2i(cert, NID_subject_alt_name,
	    NULL, NULL);
	if (altname_stack == NULL)
		return -1;

	if (inet_pton(AF_INET, host, &addrbuf) == 1) {
		type = GEN_IPADD;
		addrlen = 4;
	} else if (inet_pton(AF_INET6, host, &addrbuf) == 1) {
		type = GEN_IPADD;
		addrlen = 16;
	} else {
		type = GEN_DNS;
		addrlen = 0;
	}

	count = sk_GENERAL_NAME_num(altname_stack);
	for (i = 0; i < count; i++) {
		GENERAL_NAME	*altname;

		altname = sk_GENERAL_NAME_value(altname_stack, i);

		if (altname->type != type)
			continue;

		if (type == GEN_DNS) {
			unsigned char	*data;
			int		 format;

			format = ASN1_STRING_type(altname->d.dNSName);
			if (format == V_ASN1_IA5STRING) {
				data = ASN1_STRING_data(altname->d.dNSName);

				if (ASN1_STRING_length(altname->d.dNSName) !=
				    (int)strlen(data)) {
					fprintf(stdout, "%s: NUL byte in "
					    "subjectAltName, probably a "
					    "malicious certificate.\n",
					    getprogname());
					rv = -2;
					break;
				}

				if (ressl_match_hostname(data, host) == 0) {
					rv = 0;
					break;
				}
			} else
				fprintf(stdout, "%s: unhandled subjectAltName "
				    "dNSName encoding (%d)\n", getprogname(),
				    format);

		} else if (type == GEN_IPADD) {
			unsigned char	*data;
			int		 datalen;

			datalen = ASN1_STRING_length(altname->d.iPAddress);
			data = ASN1_STRING_data(altname->d.iPAddress);

			if (datalen == addrlen &&
			    memcmp(data, &addrbuf, addrlen) == 0) {
				rv = 0;
				break;
			}
		}
	}

	sk_GENERAL_NAME_free(altname_stack);
	return rv;
}

int
ressl_check_common_name(X509 *cert, const char *host)
{
	X509_NAME *name;
	char *common_name = NULL;
	int common_name_len;
	int rv = -1;

	name = X509_get_subject_name(cert);
	if (name == NULL)
		goto out;

	common_name_len = X509_NAME_get_text_by_NID(name, NID_commonName,
	    NULL, 0);
	if (common_name_len < 0)
		goto out;

	common_name = calloc(common_name_len + 1, 1);
	if (common_name == NULL)
		goto out;

	X509_NAME_get_text_by_NID(name, NID_commonName, common_name,
	    common_name_len + 1);

	/* NUL bytes in CN? */
	if (common_name_len != (int)strlen(common_name)) {
		fprintf(stdout, "%s: NUL byte in Common Name field, "
		    "probably a malicious certificate.\n", getprogname());
		rv = -2;
		goto out;
	}

	if (ressl_match_hostname(common_name, host) == 0)
		rv = 0;
out:
	free(common_name);
	return rv;
}

int
ressl_check_hostname(X509 *cert, const char *host)
{
	int	rv;

	rv = ressl_check_subject_altname(cert, host);
	if (rv == 0 || rv == -2)
		return rv;

	return ressl_check_common_name(cert, host);
}
