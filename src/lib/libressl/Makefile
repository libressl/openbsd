#	$OpenBSD: Makefile,v 1.1 2014/07/12 01:20:24 jsing Exp $

CFLAGS+= -Wall -Werror -Wimplicit
CFLAGS+= -DLIBRESSL_INTERNAL

LIB=	ressl

DPADD=	${LIBCRYPTO} ${LIBSSL}

HDRS=	ressl.h

SRCS=	ressl.c \
	ressl_config.c \
	ressl_util.c \
	ressl_verify.c

includes:
	@cd ${.CURDIR}; for i in $(HDRS); do \
	    j="cmp -s $$i ${DESTDIR}/usr/include/$$i || \
	    ${INSTALL} ${INSTALL_COPY} -o ${BINOWN} -g ${BINGRP} -m 444 $$i\
		${DESTDIR}/usr/include/"; \
	    echo $$j; \
	    eval "$$j"; \
	done;

.include <bsd.lib.mk>
