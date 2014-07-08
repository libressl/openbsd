#	$OpenBSD: Makefile,v 1.3 2014/06/01 11:11:46 miod Exp $

PROG=	utf8test
CPPFLAGS+=-I${.CURDIR}/../../../../lib/libssl/src/crypto/asn1
LDADD=	-lcrypto
DPADD=	${LIBCRYPTO}
WARNINGS=Yes
CFLAGS+=	-DLIBRESSL_INTERNAL -Werror

.include <bsd.regress.mk>
