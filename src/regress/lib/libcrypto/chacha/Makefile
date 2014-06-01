#	$OpenBSD: Makefile,v 1.1 2014/05/01 13:15:22 jsing Exp $

PROG=	chachatest
LDADD=	-lcrypto
DPADD=	${LIBCRYPTO}
WARNINGS=	Yes
CFLAGS+=	-Werror

.include <bsd.regress.mk>
