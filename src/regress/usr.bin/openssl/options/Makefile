#	$OpenBSD: Makefile,v 1.1 2014/11/01 11:55:27 jsing Exp $

PROG=	optionstest
SRCS=	optionstest.c

LDADD=	-lcrypto -lssl
DPADD=	${LIBCRYPTO} ${LIBSSL}

OSSLSRC= ${.CURDIR}/../../../../usr.bin/openssl/
CFLAGS+= -I${OSSLSRC}

.PATH:	${OSSLSRC}
SRCS+=	apps.c

CFLAGS+= -Werror

.include <bsd.regress.mk>
