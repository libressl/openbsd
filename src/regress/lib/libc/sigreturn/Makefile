# $OpenBSD: Makefile,v 1.2 2002/01/01 23:00:51 art Exp $

PROG=	sigret

DEBUG+= -ggdb

REGRESSTARGETS+= sigret-normal sigret-indirect sigret-altstack

sigret-normal:
	./${PROG}

sigret-indirect: ${PROG}
	./${PROG} -i

sigret-altstack: ${PROG}
	./${PROG} -a

.include <bsd.regress.mk>
