# $OpenBSD: Makefile,v 1.18 2011/05/26 13:52:55 jasper Exp $

SUBDIR=ssl man
PC_FILES=openssl.pc libssl.pc

CLEANFILES=${PC_FILES}

beforeinstall:
	/bin/sh ${.CURDIR}/generate_pkgconfig.sh -c ${.CURDIR} -o ${.OBJDIR}
.for p in ${PC_FILES}
	${INSTALL} ${INSTALL_COPY} -o root -g ${SHAREGRP} \
	    -m ${SHAREMODE} ${.OBJDIR}/$p ${DESTDIR}/usr/lib/pkgconfig/
.endfor

.include <bsd.prog.mk>
.include <bsd.subdir.mk>
