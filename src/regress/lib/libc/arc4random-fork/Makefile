#	$OpenBSD$

PROG=	arc4random-fork

REGRESS_TARGETS=	\
	run		\
	run-buf		\
	run-prefork	\
	run-buf-prefork

run: ${PROG}
	./${PROG}

run-buf: ${PROG}
	./${PROG} -b

run-prefork: ${PROG}
	./${PROG} -p

run-buf-prefork: ${PROG}
	./${PROG} -bp

.PHONY: ${REGRESS_TARGETS}

.include <bsd.regress.mk>
