#	$OpenBSD: Makefile,v 1.5 2026/04/25 14:36:12 jsing Exp $

PROGS +=	dtlstest
PROGS +=	dtls_wire_test

LDADD=		${SSL_INT} -lcrypto
DPADD=		${LIBSSL} ${LIBCRYPTO}
WARNINGS=	Yes
CFLAGS+=	-DLIBRESSL_INTERNAL -Werror
CFLAGS+=	-I${.CURDIR}/../../../../lib/libcrypto/bio
CFLAGS+=	-I${.CURDIR}/../../../../lib/libssl

REGRESS_TARGETS= \
	regress-dtlstest \
	regress-dtls_wire_test

# XXX(jsing): use CA root and chain
regress-dtlstest: dtlstest
	./dtlstest \
	    ${.CURDIR}/../../libssl/certs/server1-rsa.pem \
	    ${.CURDIR}/../../libssl/certs/server1-rsa.pem \
	    ${.CURDIR}/../../libssl/certs/ca-int-rsa.pem

regress-dtls_wire_test: dtls_wire_test
	./dtls_wire_test

.include <bsd.regress.mk>
