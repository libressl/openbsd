# $OpenBSD: Makefile.inc,v 1.13 2024/03/28 01:57:00 jsing Exp $

# sparc64-specific libcrypto build rules

# aes
SRCS+= aes_core.c aes_cbc.c 
CFLAGS+= -DAES_ASM
SSLASM+= aes aes-sparcv9 aes-sparcv9
# bn
# camellia
SRCS+= camellia.c cmll_cbc.c cmll_misc.c
# modes
CFLAGS+= -DGHASH_ASM
SSLASM+= modes ghash-sparcv9 ghash-sparcv9
# sha
SSLASM+= sha sha1-sparcv9 sha1-sparcv9
CFLAGS+= -DSHA1_ASM
SSLASM+= sha sha512-sparcv9 sha256-sparcv9
CFLAGS+= -DSHA256_ASM
SSLASM+= sha sha512-sparcv9 sha512-sparcv9
CFLAGS+= -DSHA512_ASM
# whrlpool
SRCS+= wp_block.c

.for dir src dst in ${SSLASM}
SRCS+=	${dst}.S
GENERATED+=${dst}.S
${dst}.S: ${LCRYPTO_SRC}/${dir}/asm/${src}.pl
	/usr/bin/env CC=${CC} /usr/bin/perl \
		${LCRYPTO_SRC}/${dir}/asm/${src}.pl ${.TARGET} -m64 > ${.TARGET}
.endfor

# not until Montgomery code enabled
#CFLAGS+= -DOPENSSL_CPUID_OBJ
#SRCS+=	sparccpuid.S sparcv9cap.c
