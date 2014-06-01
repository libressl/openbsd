#	$OpenBSD: Makefile,v 1.1 2014/05/15 13:56:14 jsing Exp $

PROG=	aeadtest
LDADD=	-lcrypto
DPADD=	${LIBCRYPTO}
WARNINGS=	Yes
CFLAGS+=	-Werror

REGRESS_TARGETS=regress-aeadtest

regress-aeadtest: ${PROG}
	./${PROG} ${.CURDIR}/aeadtests.txt

.include <bsd.regress.mk>
