/*	$OpenBSD: crypt.c,v 1.26 2015/01/16 16:48:51 deraadt Exp $	*/

#include <pwd.h>

char *
crypt(const char *key, const char *setting)
{
	if (setting[0] == '$') {
		switch (setting[1]) {
		case '2':
			return bcrypt(key, setting);
		default:
			return (NULL);
		}
	}
}
