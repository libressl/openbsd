#	$OpenBSD: Makefile,v 1.1 2008/10/01 23:04:58 millert Exp $

PROG=	fnm_test
LDADD+=	-lutil
DPADD+=	${LIBUTIL}

run-regress-${PROG}:
	./${PROG} ${.CURDIR}/${PROG}.in

.include <bsd.regress.mk>
