#	$OpenBSD: Makefile,v 1.2 2016/11/04 17:51:54 guenther Exp $

PROG=	verifytest
LDADD=	-lcrypto -lssl ${TLS_INT}
DPADD=	${LIBCRYPTO} ${LIBSSL} ${LIBTLS}

WARNINGS=	Yes
CFLAGS+=	-Werror

.include <bsd.regress.mk>
