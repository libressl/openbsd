#	$OpenBSD: Makefile,v 1.3 2010/09/24 13:32:55 djm Exp $

PROG=	globtest

run-regress-${PROG}:
	mkdir -m 755 -p `sed 's@/[^/]*$$@@' ${.CURDIR}/files | sort -u`
	umask 022; touch `cat ${.CURDIR}/files`
	chmod 0755 `grep '/r[^/]*$$' ${.CURDIR}/files`
	chmod 0444 `grep '/s[^/]*$$' ${.CURDIR}/files`
	chmod 0711 `grep '/t[^/]*$$' ${.CURDIR}/files`
	./${PROG} ${.CURDIR}/${PROG}.in

clean:
	rm -rf fake ${PROG} ${OBJS} *.core

.include <bsd.regress.mk>
