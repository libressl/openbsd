#	$OpenBSD: Makefile,v 1.3 2002/01/01 23:00:52 art Exp $

PROG=	sigsetjmptest
SRCS=	jmptest.c

CFLAGS+= -DTEST_SIGSETJMP

.PATH:	${.CURDIR}/../setjmp

REGRESSTARGETS=sigsetjmp-save sigsetjmp-nosave

sigsetjmp-save: ${PROG}
	./${PROG} save
sigsetjmp-nosave: ${PROG}
	./${PROG} nosave

.PHONY: ${REGRESSTARGETS}

.include <bsd.regress.mk>
