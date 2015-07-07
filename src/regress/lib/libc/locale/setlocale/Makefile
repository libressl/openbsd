#	$OpenBSD$

NOMAN =
PROG =	setlocale

run-regress-setlocale: ${PROG}
	env -i LC_ALL=fr_FR.UTF-8 ./${PROG}

.include <bsd.regress.mk>
