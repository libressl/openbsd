#	$OpenBSD: Makefile,v 1.5 2002/02/16 01:58:33 art Exp $

SUBDIR+= _setjmp db regex setjmp sigsetjmp malloc sigreturn popen
SUBDIR+= longjmp
.if (${MACHINE_ARCH} != "vax")
SUBDIR+= ieeefp
.endif

.if exists(arch/${MACHINE_ARCH})
SUBDIR+= arch/${MACHINE_ARCH}
.endif

regress: _SUBDIRUSE

install:

.include <bsd.subdir.mk>
