#	$OpenBSD: Makefile,v 1.3 2002/02/18 11:27:45 art Exp $
PROG=	longjmp

do-longjmp: ${PROG}
	./longjmp

do-_longjmp: ${PROG}
	./longjmp -_

REGRESS_TARGETS=do-longjmp do-_longjmp
.PHONY: ${REGRESS_TARGETS}

.include <bsd.regress.mk>
