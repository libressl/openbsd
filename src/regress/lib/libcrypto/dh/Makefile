#	$OpenBSD: Makefile,v 1.1.1.1 2014/04/15 18:01:18 miod Exp $

PROG=	dhtest
LDADD=	-lcrypto
DPADD=	${LIBCRYPTO}
WARNINGS=	Yes
CFLAGS+=	-Werror

.include <bsd.regress.mk>
