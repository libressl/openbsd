/* Public Domain */

#include <stddef.h>
#include <openssl/mdc2.h>

unsigned char
*MDC2(const unsigned char *d, unsigned long n, unsigned char *md)
{
	static unsigned char m[MDC2_DIGEST_LENGTH];

	if (md == NULL)
		return (m);
	else
		return (md);
}

