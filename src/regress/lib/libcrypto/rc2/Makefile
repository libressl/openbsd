#	$OpenBSD: Makefile,v 1.1.1.1 2014/04/15 18:01:17 miod Exp $

PROG=	rc2test
LDADD=	-lcrypto
DPADD=	${LIBCRYPTO}
WARNINGS=	Yes
CFLAGS+=	-Werror

.include <bsd.regress.mk>
