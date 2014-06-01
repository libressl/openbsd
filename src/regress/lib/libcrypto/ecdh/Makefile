#	$OpenBSD: Makefile,v 1.1.1.1 2014/04/15 18:01:16 miod Exp $

PROG=	ecdhtest
LDADD=	-lcrypto
DPADD=	${LIBCRYPTO}
WARNINGS=	Yes
CFLAGS+=	-Werror

.include <bsd.regress.mk>
