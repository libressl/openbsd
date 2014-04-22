#	$OpenBSD: Makefile,v 1.1 2014/04/17 18:33:22 miod Exp $

PROG=	aes_wrap
CRYPTO=	${.CURDIR}/../../../../lib/libssl/src/crypto
CFLAGS+=	-DAES_WRAP_TEST
CFLAGS+=	-I${CRYPTO} -I${CRYPTO}/aes
.PATH:	${CRYPTO}/aes

LDADD=	-lcrypto
DPADD=	${LIBCRYPTO}

.include <bsd.regress.mk>
