#	$OpenBSD$
PROG=	longjmp

do-longjmp: ${PROG}
	./longjmp

do-_longjmp: ${PROG}
	./longjmp -_

REGRESSTARGETS=do-longjmp do-_longjmp
.PHONY: ${REGRESSTARGETS}

.include <bsd.regress.mk>
