/*	$OpenBSD: ssl.h,v 1.2 2023/07/05 21:14:54 bcook Exp $	*/
/*
 * Copyright (c) 2022 Philip Guenther <guenther@openbsd.org>
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

#ifndef _LIBSSL_SSL_H_
#define _LIBSSL_SSL_H_

#ifndef _MSC_VER
#include_next <openssl/ssl.h>
#else
#include "../include/openssl/ssl.h"
#endif
#include "ssl_namespace.h"

LSSL_USED(BIO_f_ssl);
LSSL_USED(BIO_new_ssl);
LSSL_USED(BIO_new_ssl_connect);
LSSL_UNUSED(BIO_new_buffer_ssl_connect);
LSSL_UNUSED(BIO_ssl_copy_session_id);
LSSL_UNUSED(BIO_ssl_shutdown);

#endif /* _LIBSSL_SSL_H_ */
