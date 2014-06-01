#	$OpenBSD: Makefile,v 1.1 2014/05/30 15:38:28 jsing Exp $

PROG=	sha256test
LDADD=	-lcrypto
DPADD=	${LIBCRYPTO}
WARNINGS=	Yes
CFLAGS+=	-Werror

.include <bsd.regress.mk>
