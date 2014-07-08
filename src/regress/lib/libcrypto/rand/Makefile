#	$OpenBSD: Makefile,v 1.2 2014/06/01 11:11:46 miod Exp $

PROG=	randtest
LDADD=	-lcrypto
DPADD=	${LIBCRYPTO}
WARNINGS=	Yes
CFLAGS+=	-DLIBRESSL_INTERNAL -Werror

.include <bsd.regress.mk>
