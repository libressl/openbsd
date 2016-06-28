/* $ID$ */
/*
 * Copyright (c) 2016 Tobias Pape <tobias@netshed.de>
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

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#include "tls.h"
#include "tls_internal.h"

#include <openssl/bio.h>

static int cb_write(BIO *b, const char *buf, int num);
static int cb_read(BIO *b, char *buf, int size);
static int cb_puts(BIO *b, const char *str);
static long cb_ctrl(BIO *b, int cmd, long num, void *ptr);
static int cb_new(BIO *b);
static int cb_free(BIO *data);

struct bio_cb_st {
	int (*cb_write)(BIO *h, const char *buf, int num, void *payload);
	int (*cb_read)(BIO *h, char *buf, int size, void *payload);
	void *payload;
};

static BIO_METHOD cb_method = {
	.type = BIO_TYPE_MEM,
	.name = "callbacks",
	.bwrite = cb_write,
	.bread = cb_read,
	.bputs = cb_puts,
	.ctrl = cb_ctrl,
	.create = cb_new,
	.destroy = cb_free
};



BIO_METHOD *
BIO_s_cb(void)
{
	return (&cb_method);
}

int
BIO_set_cb_write(BIO *bi, int (*cb_write)(BIO *h, const char *buf, int num, void *payload))
{
	struct bio_cb_st *b;
	b = (struct bio_cb_st *)bi->ptr;
	b->cb_write = cb_write;
	return (0);
}

int
BIO_set_cb_read(BIO *bi, int (*cb_read)(BIO *h, char *buf, int size, void *payload))
{
	struct bio_cb_st *b;
	b = (struct bio_cb_st *)bi->ptr;
	b->cb_read = cb_read;
	return (0);
}

int
BIO_set_cb_payload(BIO *bi, void *payload)
{
	struct bio_cb_st *b;
	b = (struct bio_cb_st *)bi->ptr;
	b->payload = payload;
	return (0);
}

void *
BIO_get_cb_payload(BIO *bi)
{
	struct bio_cb_st *b;
	b = (struct bio_cb_st *)bi->ptr;
	return (b->payload);
}



static int
cb_new(BIO *bi)
{
	struct bio_cb_st *bcb;

	bcb = calloc(1, sizeof(struct bio_cb_st));
	if (bcb == NULL)
		return (0);
	bi->shutdown = 1;
	bi->init = 1;
	bi->num = -1;
	bi->ptr = (char *)bcb;
	return (1);
}

static int
cb_free(BIO *bi)
{
	if (bi == NULL)
		return (0);
	if (bi->shutdown) {
		if ((bi->init) && (bi->ptr != NULL)) {
			struct bio_cb_st *b;
			b = (struct bio_cb_st *)bi->ptr;
			free(b);
			bi->ptr = NULL;
		}
	}
	return (1);
}

static int
cb_read(BIO *b, char *buf, int size)
{
	int ret = -1;
	struct bio_cb_st *bcb;

	bcb = (struct bio_cb_st *)b->ptr;
	ret = (bcb->cb_read)(b, buf, size, bcb->payload);
	return (ret);
}



static int
cb_write(BIO *b, const char *buf, int num)
{
	int ret = -1;
	struct bio_cb_st *bcb;

	bcb = (struct bio_cb_st *)b->ptr;
	ret = (bcb->cb_write)(b, buf, num, bcb->payload);
	return (ret);
}

static int
cb_puts(BIO *b, const char *str)
{
	int n, ret;

	n = strlen(str);
	ret = cb_write(b, str, n);
	return (ret);
}

static long
cb_ctrl(BIO *b, int cmd, long num, void *ptr)
{
	long ret = 1;
	switch (cmd) {
	case BIO_CTRL_GET_CLOSE:
		ret = (long)b->shutdown;
		break;
	case BIO_CTRL_SET_CLOSE:
		b->shutdown = (int)num;
		break;
	case BIO_CTRL_DUP:
		break;
	case BIO_CTRL_INFO:
	case BIO_CTRL_GET:
	case BIO_CTRL_SET:
	default:
		ret = BIO_ctrl(b->next_bio, cmd, num, ptr);
	}
	return (ret);

}
