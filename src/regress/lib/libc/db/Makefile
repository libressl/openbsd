#	$OpenBSD: Makefile,v 1.4 2001/01/29 02:05:40 niklas Exp $
#	$NetBSD: Makefile,v 1.11 1995/12/12 01:54:15 cgd Exp $

PROG=	dbtest

# add -DSTATISTICS to CFLAGS to get usage statistics.  Note that
# for this to work, libc must be compiled with -DSTATISTICS as well
CFLAGS+= -g -D__DBINTERFACE_PRIVATE -DDEBUG
CLEANFILES+= t1 t2 t3

REGRESSTARGETS=do-db

# XXX - should be split into sub-tests here, not in the script.
do-db: ${PROG}
	sh ${.CURDIR}/run.test

.include <bsd.regress.mk>
