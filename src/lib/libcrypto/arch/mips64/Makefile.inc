# $OpenBSD: Makefile.inc,v 1.11 2024/03/28 01:57:00 jsing Exp $

# mips64-specific libcrypto build rules

# aes
SRCS+= aes_cbc.c 
CFLAGS+= -DAES_ASM
SSLASM+= aes aes-mips aes-mips
# bn
SSLASM+= bn mips bn-mips
SSLASM+= bn mips-mont mips-mont
CFLAGS+= -DOPENSSL_BN_ASM_MONT
# camellia
SRCS+= camellia.c cmll_cbc.c cmll_misc.c
# sha
SSLASM+= sha sha1-mips sha1-mips
CFLAGS+= -DSHA1_ASM
SSLASM+= sha sha512-mips sha256-mips
CFLAGS+= -DSHA256_ASM
SSLASM+= sha sha512-mips sha512-mips
CFLAGS+= -DSHA512_ASM
# whrlpool
SRCS+= wp_block.c

.for dir src dst in ${SSLASM}
SRCS+=	${dst}.S
GENERATED+=${dst}.S
${dst}.S: ${LCRYPTO_SRC}/${dir}/asm/${src}.pl
	/usr/bin/env CC=${CC} /usr/bin/perl \
		${LCRYPTO_SRC}/${dir}/asm/${src}.pl 64 ${.TARGET} > ${.TARGET}
.endfor
