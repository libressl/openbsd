#	$OpenBSD: Makefile,v 1.4 2002/10/21 20:40:50 mickey Exp $

NOMAN=
PROG=sprintf_test
CPPFLAGS+=-I${.CURDIR}/../../../../lib/libc

run-regress-atexit_test: ${PROG}
	./${PROG}

.include <bsd.regress.mk>
