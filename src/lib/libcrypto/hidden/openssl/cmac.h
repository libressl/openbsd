/* $OpenBSD: cmac.h,v 1.2 2024/03/02 09:30:21 tb Exp $ */
/*
 * Copyright (c) 2023 Bob Beck <beck@openbsd.org>
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

#ifndef _LIBCRYPTO_CMAC_H
#define _LIBCRYPTO_CMAC_H

#ifndef _MSC_VER
#include_next <openssl/cmac.h>
#else
#include "../include/openssl/cmac.h"
#endif
#include "crypto_namespace.h"

LCRYPTO_USED(CMAC_CTX_new);
LCRYPTO_USED(CMAC_CTX_cleanup);
LCRYPTO_USED(CMAC_CTX_free);
LCRYPTO_USED(CMAC_CTX_get0_cipher_ctx);
LCRYPTO_USED(CMAC_CTX_copy);
LCRYPTO_USED(CMAC_Init);
LCRYPTO_USED(CMAC_Update);
LCRYPTO_USED(CMAC_Final);

#endif /* _LIBCRYPTO_CMAC_H */
