#	$OpenBSD$

PROG=		strptime_test
SRCS=		main.c
CLEANFILES+=	got

REGRESS_TARGETS=do-reg
do-reg:
	./${PROG} < ${.CURDIR}/tests > got
	diff ${.CURDIR}/expected got

.include <bsd.regress.mk>
