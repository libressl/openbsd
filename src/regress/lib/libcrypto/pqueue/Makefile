#	$OpenBSD: Makefile,v 1.2 2014/05/06 20:40:26 miod Exp $

PROG=	pq_test

LDADD=	-lssl -lcrypto
DPADD=	${LIBSSL} ${LIBCRYPTO}

REGRESS_TARGETS= regress-pq_test

regress-pq_test: ${PROG}
	${.OBJDIR}/pq_test | cmp -s ${.CURDIR}/expected.txt /dev/stdin

.include <bsd.regress.mk>
