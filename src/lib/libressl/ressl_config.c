/* $OpenBSD: ressl_config.c,v 1.8 2014/08/27 10:46:53 reyk Exp $ */
/*
 * Copyright (c) 2014 Joel Sing <jsing@openbsd.org>
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

#include <errno.h>
#include <stdlib.h>

#include <ressl.h>
#include "ressl_internal.h"

/*
 * Default configuration.
 */
struct ressl_config ressl_config_default = {
	.ca_file = _PATH_SSL_CA_FILE,
	.ca_path = NULL,
	.ciphers = NULL,
	.ecdhcurve = NID_X9_62_prime256v1,
	.verify = 1,
	.verify_depth = 6,
};

struct ressl_config *
ressl_config_new(void)
{
	struct ressl_config *config;

	if ((config = malloc(sizeof(*config))) == NULL)
		return (NULL);

	memcpy(config, &ressl_config_default, sizeof(*config));
	
	return (config);
}

void
ressl_config_free(struct ressl_config *config)
{
	free(config);
}

void
ressl_config_set_ca_file(struct ressl_config *config, char *ca_file)
{
	config->ca_file = ca_file;
}

void
ressl_config_set_ca_path(struct ressl_config *config, char *ca_path)
{
	config->ca_path = ca_path;
}

void
ressl_config_set_cert_file(struct ressl_config *config, char *cert_file)
{
	config->cert_file = cert_file;
}

void
ressl_config_set_cert_mem(struct ressl_config *config, char *cert, size_t len)
{
	config->cert_mem = cert;
	config->cert_len = len;
}

void
ressl_config_set_ciphers(struct ressl_config *config, char *ciphers)
{
	config->ciphers = ciphers;
}

int
ressl_config_set_ecdhcurve(struct ressl_config *config, const char *name)
{
	int nid = NID_undef;

	if (name != NULL && (nid = OBJ_txt2nid(name)) == NID_undef)
		return (-1);

	config->ecdhcurve = nid;
	return (0);
}

void
ressl_config_set_key_file(struct ressl_config *config, char *key_file)
{
	config->key_file = key_file;
}

void
ressl_config_set_key_mem(struct ressl_config *config, char *key, size_t len)
{
	config->key_mem = key;
	config->key_len = len;
}

void
ressl_config_set_verify_depth(struct ressl_config *config, int verify_depth)
{
	config->verify_depth = verify_depth;
}

void
ressl_config_insecure_no_verify(struct ressl_config *config)
{
	config->verify = 0;
}

void
ressl_config_verify(struct ressl_config *config)
{
	config->verify = 1;
}
