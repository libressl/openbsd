#	$OpenBSD: Makefile,v 1.1 2014/05/03 15:07:46 jsing Exp $

PROG=	base64test
LDADD=	-lcrypto
DPADD=	${LIBCRYPTO}
WARNINGS=	Yes
CFLAGS+=	-Werror

.include <bsd.regress.mk>
