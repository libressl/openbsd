#	$OpenBSD: Makefile,v 1.1 2014/06/22 14:30:52 jsing Exp $

PROG=	biotest
LDADD=	-lcrypto
DPADD=	${LIBCRYPTO}
WARNINGS=	Yes
CFLAGS+=	-DLIBRESSL_INTERNAL -Werror

.include <bsd.regress.mk>
