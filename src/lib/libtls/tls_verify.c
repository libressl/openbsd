/* $OpenBSD: tls_verify.c,v 1.9 2015/08/27 07:15:39 jsing Exp $ */
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

#include <limits.h>
#include <string.h>

#include <openssl/x509v3.h>

#include <tls.h>
#include "tls_internal.h"

static int tls_match_name(const char *cert_name, const char *name);
static int tls_check_subject_altname(struct tls *ctx, struct tls_cert *cert,
    const char *name);
static int tls_check_common_name(struct tls *ctx, struct tls_cert *cert, const char *name);

static int
tls_match_name(const char *cert_name, const char *name)
{
	const char *cert_domain, *domain, *next_dot;

	if (strcasecmp(cert_name, name) == 0)
		return 0;

	/* Wildcard match? */
	if (cert_name[0] == '*') {
		/*
		 * Valid wildcards:
		 * - "*.domain.tld"
		 * - "*.sub.domain.tld"
		 * - etc.
		 * Reject "*.tld".
		 * No attempt to prevent the use of eg. "*.co.uk".
		 */
		cert_domain = &cert_name[1];
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

		domain = strchr(name, '.');

		/* No wildcard match against a name with no domain part. */
		if (domain == NULL || strlen(domain) == 1)
			return -1;

		if (strcasecmp(cert_domain, domain) == 0)
			return 0;
	}

	return -1;
}

/* See RFC 5280 section 4.2.1.6 for SubjectAltName details. */
static int
tls_check_subject_altname(struct tls *ctx, struct tls_cert *cert, const char *name)
{
	union { struct in_addr ip4; struct in6_addr ip6; } addrbuf;
	struct tls_cert_general_name *altname;
	int addrlen, type;
	int i;

	if (cert->subject_alt_name_count == 0)
		return -1;

	if (inet_pton(AF_INET, name, &addrbuf) == 1) {
		type = TLS_CERT_GNAME_IPv4;
		addrlen = 4;
	} else if (inet_pton(AF_INET6, name, &addrbuf) == 1) {
		type = TLS_CERT_GNAME_IPv6;
		addrlen = 16;
	} else {
		type = TLS_CERT_GNAME_DNS;
		addrlen = 0;
	}

	for (i = 0; i < cert->subject_alt_name_count; i++) {
		altname = &cert->subject_alt_names[i];
		if (altname->name_type != type)
			continue;

		if (type == TLS_CERT_GNAME_DNS) {
			if (tls_match_name(altname->name_value, name) == 0)
				return 0;
		} else {
			if (memcmp(altname->name_value, &addrbuf, addrlen) == 0)
				return 0;
		}
	}

	return -1;
}

static int
tls_check_common_name(struct tls *ctx, struct tls_cert *cert, const char *name)
{
	union { struct in_addr ip4; struct in6_addr ip6; } addrbuf;

	if (cert->subject.common_name == NULL)
		return -1;

	if (inet_pton(AF_INET,  name, &addrbuf) == 1 ||
	    inet_pton(AF_INET6, name, &addrbuf) == 1) {
		/*
		 * We don't want to attempt wildcard matching against IP
		 * addresses, so perform a simple comparison here.
		 */
		if (strcmp(cert->subject.common_name, name) == 0)
			return 0;
	} else {
		if (tls_match_name(cert->subject.common_name, name) == 0)
			return 0;
	}
	return -1;
}

int
tls_check_servername(struct tls *ctx, struct tls_cert *cert, const char *servername)
{
	int	rv;

	rv = tls_check_subject_altname(ctx, cert, servername);
	if (rv == 0)
		return rv;
	rv = tls_check_common_name(ctx, cert, servername);
	if (rv != 0)
		tls_set_errorx(ctx, "name '%s' does not match cert", servername);
	return rv;
}

int
tls_configure_verify(struct tls *ctx)
{
	if (ctx->config->verify_cert) {
		SSL_CTX_set_verify(ctx->ssl_ctx, SSL_VERIFY_PEER, NULL);

		if (ctx->config->ca_mem != NULL) {
			if (ctx->config->ca_len > INT_MAX) {
				tls_set_errorx(ctx, "ca too long");
				goto err;
			}

			if (SSL_CTX_load_verify_mem(ctx->ssl_ctx,
			    ctx->config->ca_mem, ctx->config->ca_len) != 1) {
				tls_set_errorx(ctx,
				    "ssl verify memory setup failure");
				goto err;
			}
		} else if (SSL_CTX_load_verify_locations(ctx->ssl_ctx,
		    ctx->config->ca_file, ctx->config->ca_path) != 1) {
			tls_set_errorx(ctx, "ssl verify setup failure");
			goto err;
		}
		if (ctx->config->verify_depth >= 0)
			SSL_CTX_set_verify_depth(ctx->ssl_ctx,
			    ctx->config->verify_depth);
	}
	return 0;
err:
	return -1;
}

