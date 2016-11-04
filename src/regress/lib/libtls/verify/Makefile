#	$OpenBSD: Makefile,v 1.1 2014/11/01 11:55:27 jsing Exp $

PROG=	verifytest
LDADD=	-lcrypto -lssl -Wl,-Bstatic -ltls -Wl,-Bdynamic
DPADD=	${LIBCRYPTO} ${LIBSSL} ${LIBTLS}

WARNINGS=	Yes
CFLAGS+=	-Werror

.include <bsd.regress.mk>
