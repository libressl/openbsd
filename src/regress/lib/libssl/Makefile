#	$OpenBSD: Makefile,v 1.4 2001/02/07 20:27:08 todd Exp $

CLEANFILES+= testdsa.key testdsa.pem rsakey.pem rsacert.pem dsa512.pem

REGRESSTARGETS=ssl-enc ssl-dsa ssl-rsa

ssl-enc:
	sh ${.CURDIR}/testenc.sh ${.OBJDIR} ${.CURDIR}
ssl-dsa:
	sh ${.CURDIR}/testdsa.sh ${.OBJDIR} ${.CURDIR}
ssl-rsa:
	sh ${.CURDIR}/testrsa.sh ${.OBJDIR} ${.CURDIR}

.include <bsd.regress.mk>
