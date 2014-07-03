# $OpenBSD: Makefile,v 1.2 2013/08/01 21:26:30 kettenis Exp $

.if defined(REGRESS_FULL) || make(clean) || make(cleandir) || make(obj)
SUBDIR+= check_isw
.endif

install:

.include <bsd.subdir.mk>
