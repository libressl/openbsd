#	$OpenBSD: Makefile,v 1.3 2016/12/21 15:51:05 jsing Exp $

.include "../../Makefile.inc"

PROG=	bntest
LDADD=	${CRYPTO_INT}
DPADD=	${LIBCRYPTO}
WARNINGS=	Yes
CFLAGS+=	-Werror

.include <bsd.regress.mk>
