#	$OpenBSD: Makefile,v 1.2 2015/09/29 04:54:23 beck Exp $

TESTS = \
	doit.sh

REGRESS_TARGETS= all_tests

CLEANFILES += \
1000.pem client.cert.pem intermediate.cert.pem root.cert.pem  server.csr.pem \
1001.pem client.csr.pem intermediate.csr.pem  root.key.pem  server.key.pem \
chain.pem client.key.pem intermediate.key.pem  server.cert.pem \
int.txt  int.txt.attr int.txt.old int.txt.attr.old  \
root.txt root.txt.attr root.txt.old root.txt.attr.old \
intserial rootserial intserial.old rootserial.old

all_tests: ${TESTS}
	@for test in $>; do \
		./$$test; \
	done

.include <bsd.regress.mk>
