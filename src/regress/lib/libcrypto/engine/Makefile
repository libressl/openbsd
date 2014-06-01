#	$OpenBSD: Makefile,v 1.1 2014/04/17 07:52:08 jsg Exp $

PROG=	enginetest
LDADD=	-lcrypto
DPADD=	${LIBCRYPTO}
WARNINGS=	Yes
CFLAGS+=	-Werror

.include <bsd.regress.mk>
