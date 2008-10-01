#	$OpenBSD$

PROG=	globtest

run-regress-${PROG}:
	mkdir -p `sed 's@/[^/]*$$@@' ${.CURDIR}/files | sort -u`
	touch `cat files`
	./${PROG} ${.CURDIR}/${PROG}.in

clean:
	rm -rf fake ${PROG} ${OBJS} *.core

.include <bsd.regress.mk>
