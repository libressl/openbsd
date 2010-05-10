# $OpenBSD: Makefile,v 1.1 2007/09/03 14:42:44 millert Exp $

.include <bsd.own.mk>


.if ${COMPILER_VERSION:L} == "gcc3" || ${COMPILER_VERSION:L} == "gcc4" 
SUBDIR+= libgd1 libgd2 test1
.endif

install:

.include <bsd.subdir.mk>
