#	$OpenBSD: Makefile,v 1.4 2002/02/18 11:22:26 art Exp $

PROG=except

REGRESS_TARGETS+= fltdiv fltinv fltovf fltund

fltdiv: ${PROG}
	./${PROG} fltdiv

fltinv: ${PROG}
	./${PROG} fltinv

fltovf: ${PROG}
	./${PROG} fltovf

fltund: ${PROG}
	./${PROG} fltund

.include <bsd.regress.mk>
