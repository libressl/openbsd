#	$OpenBSD$

PROG=	evptest
LDADD=	-lcrypto
DPADD=	${LIBCRYPTO}

REGRESS_TARGETS=regress-evptest

regress-evptest:	${PROG}
	./${PROG} ${.CURDIR}/evptests.txt

.include <bsd.regress.mk>
