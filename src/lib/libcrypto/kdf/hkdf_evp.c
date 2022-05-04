/*	$OpenBSD: hkdf_evp.c,v 1.4 2022/05/04 18:49:50 tb Exp $ */
/* ====================================================================
 * Copyright (c) 2016-2018 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdlib.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/evp.h>
#include "internal/cryptlib.h"
#include "crypto/evp.h"

#define HKDF_MAXBUF 1024

static unsigned char *HKDF(const EVP_MD *evp_md,
                           const unsigned char *salt, size_t salt_len,
                           const unsigned char *key, size_t key_len,
                           const unsigned char *info, size_t info_len,
                           unsigned char *okm, size_t okm_len);

static unsigned char *HKDF_Extract(const EVP_MD *evp_md,
                                   const unsigned char *salt, size_t salt_len,
                                   const unsigned char *key, size_t key_len,
                                   unsigned char *prk, size_t *prk_len);

static unsigned char *HKDF_Expand(const EVP_MD *evp_md,
                                  const unsigned char *prk, size_t prk_len,
                                  const unsigned char *info, size_t info_len,
                                  unsigned char *okm, size_t okm_len);

typedef struct {
    int mode;
    const EVP_MD *md;
    unsigned char *salt;
    size_t salt_len;
    unsigned char *key;
    size_t key_len;
    unsigned char info[HKDF_MAXBUF];
    size_t info_len;
} HKDF_PKEY_CTX;

static int pkey_hkdf_init(EVP_PKEY_CTX *ctx)
{
    HKDF_PKEY_CTX *kctx;

    if ((kctx = OPENSSL_zalloc(sizeof(*kctx))) == NULL) {
        KDFerr(KDF_F_PKEY_HKDF_INIT, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    ctx->data = kctx;

    return 1;
}

static void pkey_hkdf_cleanup(EVP_PKEY_CTX *ctx)
{
    HKDF_PKEY_CTX *kctx = ctx->data;
    OPENSSL_clear_free(kctx->salt, kctx->salt_len);
    OPENSSL_clear_free(kctx->key, kctx->key_len);
    OPENSSL_cleanse(kctx->info, kctx->info_len);
    OPENSSL_free(kctx);
}

static int pkey_hkdf_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    HKDF_PKEY_CTX *kctx = ctx->data;

    switch (type) {
    case EVP_PKEY_CTRL_HKDF_MD:
        if (p2 == NULL)
            return 0;

        kctx->md = p2;
        return 1;

    case EVP_PKEY_CTRL_HKDF_MODE:
        kctx->mode = p1;
        return 1;

    case EVP_PKEY_CTRL_HKDF_SALT:
        if (p1 == 0 || p2 == NULL)
            return 1;

        if (p1 < 0)
            return 0;

        if (kctx->salt != NULL)
            OPENSSL_clear_free(kctx->salt, kctx->salt_len);

        kctx->salt = OPENSSL_memdup(p2, p1);
        if (kctx->salt == NULL)
            return 0;

        kctx->salt_len = p1;
        return 1;

    case EVP_PKEY_CTRL_HKDF_KEY:
        if (p1 < 0)
            return 0;

        if (kctx->key != NULL)
            OPENSSL_clear_free(kctx->key, kctx->key_len);

        kctx->key = OPENSSL_memdup(p2, p1);
        if (kctx->key == NULL)
            return 0;

        kctx->key_len  = p1;
        return 1;

    case EVP_PKEY_CTRL_HKDF_INFO:
        if (p1 == 0 || p2 == NULL)
            return 1;

        if (p1 < 0 || p1 > (int)(HKDF_MAXBUF - kctx->info_len))
            return 0;

        memcpy(kctx->info + kctx->info_len, p2, p1);
        kctx->info_len += p1;
        return 1;

    default:
        return -2;

    }
}

static int pkey_hkdf_ctrl_str(EVP_PKEY_CTX *ctx, const char *type,
                              const char *value)
{
    if (strcmp(type, "mode") == 0) {
        int mode;

        if (strcmp(value, "EXTRACT_AND_EXPAND") == 0)
            mode = EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND;
        else if (strcmp(value, "EXTRACT_ONLY") == 0)
            mode = EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY;
        else if (strcmp(value, "EXPAND_ONLY") == 0)
            mode = EVP_PKEY_HKDEF_MODE_EXPAND_ONLY;
        else
            return 0;

        return EVP_PKEY_CTX_hkdf_mode(ctx, mode);
    }

    if (strcmp(type, "md") == 0)
        return EVP_PKEY_CTX_md(ctx, EVP_PKEY_OP_DERIVE,
                               EVP_PKEY_CTRL_HKDF_MD, value);

    if (strcmp(type, "salt") == 0)
        return EVP_PKEY_CTX_str2ctrl(ctx, EVP_PKEY_CTRL_HKDF_SALT, value);

    if (strcmp(type, "hexsalt") == 0)
        return EVP_PKEY_CTX_hex2ctrl(ctx, EVP_PKEY_CTRL_HKDF_SALT, value);

    if (strcmp(type, "key") == 0)
        return EVP_PKEY_CTX_str2ctrl(ctx, EVP_PKEY_CTRL_HKDF_KEY, value);

    if (strcmp(type, "hexkey") == 0)
        return EVP_PKEY_CTX_hex2ctrl(ctx, EVP_PKEY_CTRL_HKDF_KEY, value);

    if (strcmp(type, "info") == 0)
        return EVP_PKEY_CTX_str2ctrl(ctx, EVP_PKEY_CTRL_HKDF_INFO, value);

    if (strcmp(type, "hexinfo") == 0)
        return EVP_PKEY_CTX_hex2ctrl(ctx, EVP_PKEY_CTRL_HKDF_INFO, value);

    KDFerr(KDF_F_PKEY_HKDF_CTRL_STR, KDF_R_UNKNOWN_PARAMETER_TYPE);
    return -2;
}

static int pkey_hkdf_derive_init(EVP_PKEY_CTX *ctx)
{
    HKDF_PKEY_CTX *kctx = ctx->data;

    OPENSSL_clear_free(kctx->key, kctx->key_len);
    OPENSSL_clear_free(kctx->salt, kctx->salt_len);
    OPENSSL_cleanse(kctx->info, kctx->info_len);
    memset(kctx, 0, sizeof(*kctx));

    return 1;
}

static int pkey_hkdf_derive(EVP_PKEY_CTX *ctx, unsigned char *key,
                            size_t *keylen)
{
    HKDF_PKEY_CTX *kctx = ctx->data;

    if (kctx->md == NULL) {
        KDFerr(KDF_F_PKEY_HKDF_DERIVE, KDF_R_MISSING_MESSAGE_DIGEST);
        return 0;
    }
    if (kctx->key == NULL) {
        KDFerr(KDF_F_PKEY_HKDF_DERIVE, KDF_R_MISSING_KEY);
        return 0;
    }

    switch (kctx->mode) {
    case EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND:
        return HKDF(kctx->md, kctx->salt, kctx->salt_len, kctx->key,
                    kctx->key_len, kctx->info, kctx->info_len, key,
                    *keylen) != NULL;

    case EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY:
        if (key == NULL) {
            *keylen = EVP_MD_size(kctx->md);
            return 1;
        }
        return HKDF_Extract(kctx->md, kctx->salt, kctx->salt_len, kctx->key,
                            kctx->key_len, key, keylen) != NULL;

    case EVP_PKEY_HKDEF_MODE_EXPAND_ONLY:
        return HKDF_Expand(kctx->md, kctx->key, kctx->key_len, kctx->info,
                           kctx->info_len, key, *keylen) != NULL;

    default:
        return 0;
    }
}

const EVP_PKEY_METHOD hkdf_pkey_meth = {
    EVP_PKEY_HKDF,
    0,
    pkey_hkdf_init,
    0,
    pkey_hkdf_cleanup,

    0, 0,
    0, 0,

    0,
    0,

    0,
    0,

    0, 0,

    0, 0, 0, 0,

    0, 0,

    0, 0,

    pkey_hkdf_derive_init,
    pkey_hkdf_derive,
    pkey_hkdf_ctrl,
    pkey_hkdf_ctrl_str
};

static unsigned char *HKDF(const EVP_MD *evp_md,
                           const unsigned char *salt, size_t salt_len,
                           const unsigned char *key, size_t key_len,
                           const unsigned char *info, size_t info_len,
                           unsigned char *okm, size_t okm_len)
{
    unsigned char prk[EVP_MAX_MD_SIZE];
    unsigned char *ret;
    size_t prk_len;

    if (!HKDF_Extract(evp_md, salt, salt_len, key, key_len, prk, &prk_len))
        return NULL;

    ret = HKDF_Expand(evp_md, prk, prk_len, info, info_len, okm, okm_len);
    OPENSSL_cleanse(prk, sizeof(prk));

    return ret;
}

static unsigned char *HKDF_Extract(const EVP_MD *evp_md,
                                   const unsigned char *salt, size_t salt_len,
                                   const unsigned char *key, size_t key_len,
                                   unsigned char *prk, size_t *prk_len)
{
    unsigned int tmp_len;

    if (!HMAC(evp_md, salt, salt_len, key, key_len, prk, &tmp_len))
        return NULL;

    *prk_len = tmp_len;
    return prk;
}

static unsigned char *HKDF_Expand(const EVP_MD *evp_md,
                                  const unsigned char *prk, size_t prk_len,
                                  const unsigned char *info, size_t info_len,
                                  unsigned char *okm, size_t okm_len)
{
    HMAC_CTX *hmac;
    unsigned char *ret = NULL;

    unsigned int i;

    unsigned char prev[EVP_MAX_MD_SIZE];

    size_t done_len = 0, dig_len = EVP_MD_size(evp_md);

    size_t n = okm_len / dig_len;
    if (okm_len % dig_len)
        n++;

    if (n > 255 || okm == NULL)
        return NULL;

    if ((hmac = HMAC_CTX_new()) == NULL)
        return NULL;

    if (!HMAC_Init_ex(hmac, prk, prk_len, evp_md, NULL))
        goto err;

    for (i = 1; i <= n; i++) {
        size_t copy_len;
        const unsigned char ctr = i;

        if (i > 1) {
            if (!HMAC_Init_ex(hmac, NULL, 0, NULL, NULL))
                goto err;

            if (!HMAC_Update(hmac, prev, dig_len))
                goto err;
        }

        if (!HMAC_Update(hmac, info, info_len))
            goto err;

        if (!HMAC_Update(hmac, &ctr, 1))
            goto err;

        if (!HMAC_Final(hmac, prev, NULL))
            goto err;

        copy_len = (done_len + dig_len > okm_len) ?
                       okm_len - done_len :
                       dig_len;

        memcpy(okm + done_len, prev, copy_len);

        done_len += copy_len;
    }
    ret = okm;

 err:
    OPENSSL_cleanse(prev, sizeof(prev));
    HMAC_CTX_free(hmac);
    return ret;
}
