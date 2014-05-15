#	$OpenBSD$

PROG=	aeadtest
LDADD=	-lcrypto
DPADD=	${LIBCRYPTO}

REGRESS_TARGETS=regress-aeadtest

regress-aeadtest: ${PROG}
	./${PROG} ${.CURDIR}/aeadtests.txt

.include <bsd.regress.mk>
