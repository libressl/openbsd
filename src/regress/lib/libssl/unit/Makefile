#	$OpenBSD$

TEST_CASES+= cipher_list

REGRESS_TARGETS= all_tests

LDADD=	-lcrypto -lssl
DPADD=	${LIBCRYPTO} ${LIBSSL}
WARNINGS=	Yes
LDFLAGS+=	-lcrypto -lssl
CFLAGS+=	-DLIBRESSL_INTERNAL -Wall -Wundef -Werror -I../../../../lib/libssl/src/ssl

CLEANFILES+= ${TEST_CASES}

all_tests: ${TEST_CASES}
	@for test in $>; do \
		./$$test; \
	done

.include <bsd.regress.mk>
