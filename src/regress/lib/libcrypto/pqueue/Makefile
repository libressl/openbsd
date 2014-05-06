#	$OpenBSD: Makefile,v 1.1 2014/04/17 18:33:22 miod Exp $

PROG=	pq_test
CRYPTO=	${.CURDIR}/../../../../lib/libssl/src/crypto
CFLAGS+= -I${CRYPTO}/pqueue

LDADD=	-lcrypto
DPADD=	${LIBCRYPTO}

.include <bsd.regress.mk>
