/* $OpenBSD: tls.c,v 1.4 2014/12/17 17:51:33 doug Exp $ */
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
#include <netinet/in.h>

#include <openssl/bio.h>
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

	SSL_CTX_clear_options(ctx->ssl_ctx, SSL_OP_COOKIE_EXCHANGE);

	if (tls_config_is_dtls(ctx->config)) {
		SSL_CTX_set_read_ahead(ctx->ssl_ctx, 1);

		SSL_CTX_set_options(ctx->ssl_ctx, SSL_OP_COOKIE_EXCHANGE);
		SSL_CTX_set_cookie_generate_cb(ctx->ssl_ctx, tls_generate_cookie);
		SSL_CTX_set_cookie_verify_cb(ctx->ssl_ctx, tls_verify_cookie);
	}

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

	ctx->err = 0;
	free(ctx->errmsg);
	ctx->errmsg = NULL;
}

int
tls_read(struct tls *ctx, void *buf, size_t buflen, size_t *outlen)
{
	int ret, ssl_err;

	if (buflen > INT_MAX) {
		tls_set_error(ctx, "buflen too long");
		return (-1);
	}

	ret = SSL_read(ctx->ssl_conn, buf, buflen);
	if (ret > 0) {
		*outlen = (size_t)ret;
		return (0);
	}

	ssl_err = SSL_get_error(ctx->ssl_conn, ret);
	switch (ssl_err) {
	case SSL_ERROR_WANT_READ:
		return (TLS_READ_AGAIN);
	case SSL_ERROR_WANT_WRITE:
		return (TLS_WRITE_AGAIN);
	default:
		tls_set_error(ctx, "read failed (%i)", ssl_err);
		return (-1);
	}
}

int
tls_write(struct tls *ctx, const void *buf, size_t buflen, size_t *outlen)
{
	int ret, ssl_err;

	if (buflen > INT_MAX) {
		tls_set_error(ctx, "buflen too long");
		return (-1);
	}

	ret = SSL_write(ctx->ssl_conn, buf, buflen);
	if (ret > 0) {
		*outlen = (size_t)ret;
		return (0);
	}

	ssl_err = SSL_get_error(ctx->ssl_conn, ret);
	switch (ssl_err) {
	case SSL_ERROR_WANT_READ:
		return (TLS_READ_AGAIN);
	case SSL_ERROR_WANT_WRITE:
		return (TLS_WRITE_AGAIN);
	default:
		tls_set_error(ctx, "write failed (%i)", ssl_err);
		return (-1);
	}
}

int
tls_close(struct tls *ctx)
{
	/* XXX - handle case where multiple calls are required. */
	if (ctx->ssl_conn != NULL) {
		if (SSL_shutdown(ctx->ssl_conn) == -1) {
			tls_set_error(ctx, "SSL shutdown failed");
			goto err;
		}
	}

	if (ctx->socket != -1) {
		if (shutdown(ctx->socket, SHUT_RDWR) != 0) {
			tls_set_error(ctx, "shutdown");
			goto err;
		}
		if (close(ctx->socket) != 0) {
			tls_set_error(ctx, "close");
			goto err;
		}
		ctx->socket = -1;
	}

	return (0);

err:
	return (-1);
}

int
tls_generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len) {
	const size_t COOKIE_SECRET_LENGTH = 48;
	static unsigned char *cookie_secret = NULL;
    HMAC_CTX hmac = {};
	struct tls *conn_ctx;
	int res = 0;
	size_t peer_len;

	union {
		struct sockaddr sa;
		struct sockaddr_in s4;
		struct sockaddr_in6 s6;
	} peer = {.s6 = {}};

	conn_ctx = SSL_get_app_data(ssl);
	if (conn_ctx == NULL) {
		goto out;
	}

	/* initialize cookie secret */
	if (cookie_secret == NULL) {
		if ((cookie_secret = calloc(1, COOKIE_SECRET_LENGTH)) == NULL) {
			goto out;
		}

		if (RAND_bytes(cookie_secret, COOKIE_SECRET_LENGTH) != 1) {
			free(cookie_secret);
			cookie_secret = NULL;

			tls_set_error(conn_ctx, "RAND_bytes");
			goto out;
		}
	}

	peer_len = BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

	HMAC_CTX_init(&hmac);
	if (HMAC_Init_ex(&hmac, cookie_secret, COOKIE_SECRET_LENGTH,
			EVP_sha256(), NULL) != 1) {
		tls_set_error(conn_ctx, "HMAC_Init_ex");
		goto out;
	}

	switch (peer.sa.sa_family) {
	default:
		tls_set_error(conn_ctx, "unkown sa_family");
		goto cleanup;

	case AF_INET:
		if (peer_len != sizeof(peer.s4))
			goto cleanup;
		if (HMAC_Update(&hmac, (unsigned char*) &peer.s4.sin_addr, sizeof(peer.s4.sin_addr)) != 1)
			goto cleanup;
		if (HMAC_Update(&hmac, (unsigned char*) &peer.s4.sin_port, sizeof(peer.s4.sin_port)) != 1)
			goto cleanup;
    	break;

	case AF_INET6:
		if (peer_len != sizeof(peer.s6))
			goto cleanup;
		if (HMAC_Update(&hmac, (unsigned char*) &peer.s6.sin6_addr, sizeof(peer.s6.sin6_addr)) != 1)
			goto cleanup;
		if (HMAC_Update(&hmac, (unsigned char*) &peer.s6.sin6_port, sizeof(peer.s6.sin6_port)) != 1)
			goto cleanup;
		break;
	}

	if (HMAC_Final(&hmac, cookie, cookie_len) != 1) {
		tls_set_error(conn_ctx, "HMAC_Final");
		goto cleanup;
	}

	res = 1;

cleanup:
	HMAC_CTX_cleanup(&hmac);

out:
	return (res);
}

int
tls_verify_cookie(SSL *ssl, unsigned char *actual_cookie, unsigned int actual_cookie_len) {
	unsigned int expected_cookie_len;
	unsigned char expected_cookie[EVP_MAX_MD_SIZE];

	if (tls_generate_cookie(ssl, expected_cookie, &expected_cookie_len) != 1) {
		goto err;
	}

	if (actual_cookie_len != expected_cookie_len) {
		goto err;
	}

	if (timingsafe_memcmp(actual_cookie, expected_cookie, expected_cookie_len) == 0) {
		return (1);
	}

err:
	return (0);
}
