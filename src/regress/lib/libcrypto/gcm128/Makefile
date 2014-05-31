#	$OpenBSD: Makefile,v 1.1 2014/04/17 18:33:22 miod Exp $

PROG=	gcm128test
SRC=	${.CURDIR}/../../../../lib/libssl/src/crypto/modes
CFLAGS+=-I${SRC}

LDADD=	-lcrypto
DPADD=	${LIBCRYPTO}

.include <bsd.regress.mk>
