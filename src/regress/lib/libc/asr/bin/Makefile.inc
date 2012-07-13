#	$OpenBSD: Makefile,v 1.4 2009/07/25 08:44:26 ratchov Exp $

NOMAN=	noman

SRCS+=		common.c
CFLAGS+=	-Wall -Wstrict-prototypes -Werror -Wundef -g
LDFLAGS+=	-static
PROG:=		${PROG}${EXT}
