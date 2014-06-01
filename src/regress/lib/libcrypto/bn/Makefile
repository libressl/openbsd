#	$OpenBSD: Makefile,v 1.1.1.1 2014/04/15 18:01:15 miod Exp $

PROG=	bntest
LDADD=	-lcrypto
DPADD=	${LIBCRYPTO}
WARNINGS=	Yes
CFLAGS+=	-Werror

.include <bsd.regress.mk>
