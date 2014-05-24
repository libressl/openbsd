#	$OpenBSD$

PROG=	ssltest
LDADD=	-lcrypto -lssl
DPADD=	${LIBCRYPTO} ${LIBSSL}

REGRESS_TARGETS=regress-ssltest

regress-ssltest: ${PROG}
	sh ${.CURDIR}/testssl \
	  ${.CURDIR}/../certs/server.pem ${.CURDIR}/../certs/server.pem \
	  ${.CURDIR}/../certs/ca.pem

.include <bsd.regress.mk>
