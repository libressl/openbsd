#	$OpenBSD: Makefile,v 1.1 2015/02/06 09:36:16 doug Exp $

PROG=	bytestringtest
LDADD=	-lcrypto -lssl
DPADD=	${LIBCRYPTO} ${LIBSSL}
WARNINGS=	Yes
CFLAGS+=	-DLIBRESSL_INTERNAL -Wundef -Werror -I/usr/src/lib/libssl/src/ssl

.include <bsd.regress.mk>
