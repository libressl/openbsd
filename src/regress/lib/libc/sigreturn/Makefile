# $OpenBSD$

PROG=	sigret
SRCS=	sigret.c
NOMAN=	noman

DEBUG+= -ggdb

.PATH:	${.CURDIR}/../sigret

install:

regress: ${PROG}
	./${PROG}

.include <bsd.prog.mk>
