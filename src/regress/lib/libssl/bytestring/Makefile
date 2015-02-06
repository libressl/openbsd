#	$OpenBSD$

PROG=	bytestringtest
LDADD=	-lcrypto -lssl
DPADD=	${LIBCRYPTO} ${LIBSSL}
WARNINGS=	Yes
CFLAGS+=	-DLIBRESSL_INTERNAL -Werror -I/usr/src/lib/libssl/src/ssl

REGRESS_TARGETS=regress-bytestringtest

regress-bytestringtest: ${PROG}
	./${PROG}

.include <bsd.regress.mk>
