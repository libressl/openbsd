#	$OpenBSD: Makefile,v 1.3 2014/07/08 15:53:52 jsing Exp $

PROG=	exptest
LDADD=	${CRYPTO_INT}
DPADD=	${LIBCRYPTO}
WARNINGS=	Yes
CFLAGS+=	-Werror

.include <bsd.regress.mk>
