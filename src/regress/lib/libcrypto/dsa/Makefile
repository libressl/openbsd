#	$OpenBSD$

PROG=	dsatest
LDADD=	-lcrypto
DPADD=	${LIBCRYPTO}

REGRESS_TARGETS=regress-dsatest

regress-dsatest:	${PROG}
	./${PROG}
	./${PROG} -app2_1

.include <bsd.regress.mk>
