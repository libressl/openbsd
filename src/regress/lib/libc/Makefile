#	$OpenBSD: Makefile,v 1.33 2011/07/02 18:12:48 martynas Exp $

SUBDIR+= _setjmp alloca atexit basename cephes cxa-atexit db dirname env
SUBDIR+= fnmatch fpclassify getaddrinfo getcap getopt_long glob hsearch
SUBDIR+= longjmp locale malloc mkstemp netdb orientation popen printf
SUBDIR+= regex setjmp setjmp-signal sigreturn sigsetjmp sprintf
SUBDIR+= stdio_threading stpncpy strerror strtod strtol strtonum
SUBDIR+= telldir time vis

.if (${MACHINE_ARCH} != "vax")
SUBDIR+= ieeefp
.endif

.if exists(arch/${MACHINE_ARCH})
SUBDIR+= arch/${MACHINE_ARCH}
.endif

install:

.include <bsd.subdir.mk>
