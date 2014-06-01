#	$OpenBSD: Makefile,v 1.1 2014/05/14 14:46:35 jsing Exp $

PROG=	poly1305test
LDADD=	-lcrypto
DPADD=	${LIBCRYPTO}
WARNINGS=	Yes
CFLAGS+=	-Werror

.include <bsd.regress.mk>
