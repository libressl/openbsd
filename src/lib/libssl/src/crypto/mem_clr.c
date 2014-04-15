/* $OpenBSD$ */
/* Ted Unangst places this file in the public domain. */
#include <string.h>
#include <openssl/crypto.h>

void
OPENSSL_cleanse(void *ptr, size_t len)
{
	explicit_bzero(ptr, len);
}
