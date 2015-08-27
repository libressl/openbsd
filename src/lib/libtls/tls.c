/* $OpenBSD: tls.c,v 1.14 2015/08/27 14:34:46 jsing Exp $ */
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

#include <sys/socket.h>

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <tls.h>
#include "tls_internal.h"

static struct tls_config *tls_config_default;

int
tls_init(void)
{
	static int tls_initialised = 0;

	if (tls_initialised)
		return (0);

	SSL_load_error_strings();
	SSL_library_init();

	if ((tls_config_default = tls_config_new()) == NULL)
		return (-1);

	tls_initialised = 1;

	return (0);
}

const char *
tls_error(struct tls *ctx)
{
	return ctx->errmsg;
}

int
tls_set_error(struct tls *ctx, char *fmt, ...)
{
	va_list ap;
	int rv;

	ctx->err = errno;
	free(ctx->errmsg);
	ctx->errmsg = NULL;

	va_start(ap, fmt);
	rv = vasprintf(&ctx->errmsg, fmt, ap);
	va_end(ap);

	return (rv);
}

struct tls *
tls_new(void)
{
	struct tls *ctx;

	if ((ctx = calloc(1, sizeof(*ctx))) == NULL)
		return (NULL);

	ctx->config = tls_config_default;

	tls_reset(ctx);

	return (ctx);
}

int
tls_configure(struct tls *ctx, struct tls_config *config)
{
	if (config == NULL)
		config = tls_config_default;

	ctx->config = config;

	if ((ctx->flags & TLS_SERVER) != 0)
		return (tls_configure_server(ctx));

	return (0);
}

int
tls_configure_keypair(struct tls *ctx)
{
	EVP_PKEY *pkey = NULL;
	X509 *cert = NULL;
	BIO *bio = NULL;

	if (ctx->config->cert_mem != NULL) {
		if (ctx->config->cert_len > INT_MAX) {
			tls_set_error(ctx, "certificate too long");
			goto err;
		}

		if (SSL_CTX_use_certificate_chain_mem(ctx->ssl_ctx,
		    ctx->config->cert_mem, ctx->config->cert_len) != 1) {
			tls_set_error(ctx, "failed to load certificate");
			goto err;
		}
		cert = NULL;
	}
	if (ctx->config->key_mem != NULL) {
		if (ctx->config->key_len > INT_MAX) {
			tls_set_error(ctx, "key too long");
			goto err;
		}

		if ((bio = BIO_new_mem_buf(ctx->config->key_mem,
		    ctx->config->key_len)) == NULL) {
			tls_set_error(ctx, "failed to create buffer");
			goto err;
		}
		if ((pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL,
		    NULL)) == NULL) {
			tls_set_error(ctx, "failed to read private key");
			goto err;
		}
		if (SSL_CTX_use_PrivateKey(ctx->ssl_ctx, pkey) != 1) {
			tls_set_error(ctx, "failed to load private key");
			goto err;
		}
		BIO_free(bio);
		bio = NULL;
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}

	if (ctx->config->cert_file != NULL) {
		if (SSL_CTX_use_certificate_chain_file(ctx->ssl_ctx,
		    ctx->config->cert_file) != 1) {
			tls_set_error(ctx, "failed to load certificate file");
			goto err;
		}
	}
	if (ctx->config->key_file != NULL) {
		if (SSL_CTX_use_PrivateKey_file(ctx->ssl_ctx,
		    ctx->config->key_file, SSL_FILETYPE_PEM) != 1) {
			tls_set_error(ctx, "failed to load private key file");
			goto err;
		}
	}

	if (SSL_CTX_check_private_key(ctx->ssl_ctx) != 1) {
		tls_set_error(ctx, "private/public key mismatch");
		goto err;
	}

	return (0);

err:
	EVP_PKEY_free(pkey);
	X509_free(cert);
	BIO_free(bio);

	return (1);
}

int
tls_configure_ssl(struct tls *ctx)
{
	SSL_CTX_set_mode(ctx->ssl_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);
	SSL_CTX_set_mode(ctx->ssl_ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

	SSL_CTX_set_options(ctx->ssl_ctx, SSL_OP_NO_SSLv2);
	SSL_CTX_set_options(ctx->ssl_ctx, SSL_OP_NO_SSLv3);

	SSL_CTX_clear_options(ctx->ssl_ctx, SSL_OP_NO_TLSv1);
	SSL_CTX_clear_options(ctx->ssl_ctx, SSL_OP_NO_TLSv1_1);
	SSL_CTX_clear_options(ctx->ssl_ctx, SSL_OP_NO_TLSv1_2);

	if ((ctx->config->protocols & TLS_PROTOCOL_TLSv1_0) == 0)
		SSL_CTX_set_options(ctx->ssl_ctx, SSL_OP_NO_TLSv1);
	if ((ctx->config->protocols & TLS_PROTOCOL_TLSv1_1) == 0)
		SSL_CTX_set_options(ctx->ssl_ctx, SSL_OP_NO_TLSv1_1);
	if ((ctx->config->protocols & TLS_PROTOCOL_TLSv1_2) == 0)
		SSL_CTX_set_options(ctx->ssl_ctx, SSL_OP_NO_TLSv1_2);

	if (ctx->config->ciphers != NULL) {
		if (SSL_CTX_set_cipher_list(ctx->ssl_ctx,
		    ctx->config->ciphers) != 1) {
			tls_set_error(ctx, "failed to set ciphers");
			goto err;
		}
	}

	return (0);

err:
	return (-1);
}

void
tls_free(struct tls *ctx)
{
	if (ctx == NULL)
		return;
	tls_reset(ctx);
	free(ctx);
}

void
tls_reset(struct tls *ctx)
{
	SSL_CTX_free(ctx->ssl_ctx);
	SSL_free(ctx->ssl_conn);

	ctx->ssl_conn = NULL;
	ctx->ssl_ctx = NULL;

	ctx->socket = -1;
	ctx->state = 0;

	ctx->err = 0;
	free(ctx->errmsg);
	ctx->errmsg = NULL;
}

int
tls_ssl_error(struct tls *ctx, SSL *ssl_conn, int ssl_ret, const char *prefix)
{
	const char *errstr = "unknown error";
	unsigned long err;
	int ssl_err;

	ssl_err = SSL_get_error(ssl_conn, ssl_ret);
	switch (ssl_err) {
	case SSL_ERROR_NONE:
	case SSL_ERROR_ZERO_RETURN:
		return (0);

	case SSL_ERROR_WANT_READ:
		return (TLS_READ_AGAIN);

	case SSL_ERROR_WANT_WRITE:
		return (TLS_WRITE_AGAIN);

	case SSL_ERROR_SYSCALL:
		if ((err = ERR_peek_error()) != 0) {
			errstr = ERR_error_string(err, NULL);
		} else if (ssl_ret == 0) {
			errstr = "EOF";
		} else if (ssl_ret == -1) {
			errstr = strerror(errno);
		}
		tls_set_error(ctx, "%s failed: %s", prefix, errstr);
		return (-1);

	case SSL_ERROR_SSL:
		if ((err = ERR_peek_error()) != 0) {
			errstr = ERR_error_string(err, NULL);
		}
		tls_set_error(ctx, "%s failed: %s", prefix, errstr);
		return (-1);

	case SSL_ERROR_WANT_CONNECT:
	case SSL_ERROR_WANT_ACCEPT:
	case SSL_ERROR_WANT_X509_LOOKUP:
	default:
		tls_set_error(ctx, "%s failed (%i)", prefix, ssl_err);
		return (-1);
	}
}

int
tls_read(struct tls *ctx, void *buf, size_t buflen, size_t *outlen)
{
	int ssl_ret;

	*outlen = 0;

	if (buflen > INT_MAX) {
		tls_set_error(ctx, "buflen too long");
		return (-1);
	}

	ssl_ret = SSL_read(ctx->ssl_conn, buf, buflen);
	if (ssl_ret > 0) {
		*outlen = (size_t)ssl_ret;
		return (0);
	}

	return tls_ssl_error(ctx, ctx->ssl_conn, ssl_ret, "read"); 
}

int
tls_write(struct tls *ctx, const void *buf, size_t buflen, size_t *outlen)
{
	int ssl_ret;

	*outlen = 0;

	if (buflen > INT_MAX) {
		tls_set_error(ctx, "buflen too long");
		return (-1);
	}

	ssl_ret = SSL_write(ctx->ssl_conn, buf, buflen);
	if (ssl_ret > 0) {
		*outlen = (size_t)ssl_ret;
		return (0);
	}

	return tls_ssl_error(ctx, ctx->ssl_conn, ssl_ret, "write"); 
}

int
tls_close(struct tls *ctx)
{
	int ssl_ret;
	int rv = 0;

	if (ctx->ssl_conn != NULL) {
		ssl_ret = SSL_shutdown(ctx->ssl_conn);
		if (ssl_ret < 0) {
			rv = tls_ssl_error(ctx, ctx->ssl_conn, ssl_ret,
			    "shutdown");
			if (rv == TLS_READ_AGAIN || rv == TLS_WRITE_AGAIN)
				return (rv);
		}
	}

	if (ctx->socket != -1) {
		if (shutdown(ctx->socket, SHUT_RDWR) != 0) {
			if (rv == 0 &&
			    errno != ENOTCONN && errno != ECONNRESET) {
				tls_set_error(ctx, "shutdown");
				rv = -1;
			}
		}
		if (close(ctx->socket) != 0) {
			if (rv == 0) {
				tls_set_error(ctx, "close");
				rv = -1;
			}
		}
		ctx->socket = -1;
	}

	return (rv);
}
