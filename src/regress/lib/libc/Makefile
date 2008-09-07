#	$OpenBSD: Makefile,v 1.26 2007/09/03 14:42:43 millert Exp $

SUBDIR+= _setjmp alloca atexit basename cxa-atexit db dirname fpclassify 
SUBDIR+= getaddrinfo getcap getopt_long hsearch longjmp locale malloc
SUBDIR+= netdb popen printf regex setjmp setjmp-signal sigreturn sigsetjmp
SUBDIR+= sprintf strerror strtod strtonum telldir time vis

.if (${MACHINE_ARCH} != "vax")
SUBDIR+= ieeefp
.endif

.if exists(arch/${MACHINE_ARCH})
SUBDIR+= arch/${MACHINE_ARCH}
.endif

install:

.include <bsd.subdir.mk>
