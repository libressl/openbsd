#	$OpenBSD: Makefile,v 1.1 2004/08/03 20:38:36 otto Exp $

PROG=	vis_test
CLEANFILES+= valid.out

run-regress-vis_test: ${PROG}
	./${PROG} >${.OBJDIR}/valid.out
	cmp -s ${.OBJDIR}/valid.out ${.CURDIR}/valid.ok

.include <bsd.regress.mk>
