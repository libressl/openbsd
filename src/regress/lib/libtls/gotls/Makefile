#	$OpenBSD: Makefile,v 1.1 2014/10/31 14:10:55 jsing Exp $

GO_VERSION != sh -c "(go version) 2>/dev/null || true"

.if empty(GO_VERSION)
regress:
	@echo package go is required for this regress
	@echo SKIPPED
.endif

REGRESS_TARGETS=regress-gotls

regress-gotls:
	cd ${.CURDIR} && go test -test.v .

.include <bsd.regress.mk>
