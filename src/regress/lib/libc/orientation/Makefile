#	$OpenBSD$

NOMAN=
PROG=orientation_test
CPPFLAGS+=-I${.CURDIR}/../../../../lib/libc

run-regress-atexit_test: ${PROG}
	./${PROG}

.include <bsd.regress.mk>
