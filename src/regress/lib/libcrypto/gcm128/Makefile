#	$OpenBSD: Makefile,v 1.1.1.1 2014/04/15 18:01:18 miod Exp $

PROG=	gcm128
SRC=	${.CURDIR}/../../../../lib/libssl/src/crypto/modes
CFLAGS+=	-DSELFTEST
CFLAGS+=	-I${SRC}
.PATH:	${SRC}

LDADD=	-lcrypto
DPADD=	${LIBCRYPTO}

.include <bsd.regress.mk>
