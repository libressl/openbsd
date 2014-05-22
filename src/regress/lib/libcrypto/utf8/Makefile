#	$OpenBSD: Makefile,v 1.1 2014/05/18 22:04:14 guenther Exp $

PROG=	utf8test
CPPFLAGS+=-I${.CURDIR}/../../../../lib/libssl/src/crypto/asn1
LDADD=	-lcrypto
DPADD=	${LIBCRYPTO}
WARNINGS=Yes

.include <bsd.regress.mk>
