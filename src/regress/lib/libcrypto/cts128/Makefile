#	$OpenBSD: Makefile,v 1.1 2014/05/31 14:39:06 jsing Exp $

PROG=	cts128test
LDADD=	-lcrypto
DPADD=	${LIBCRYPTO}
WARNINGS=	Yes
CFLAGS+=	-Werror

.include <bsd.regress.mk>
