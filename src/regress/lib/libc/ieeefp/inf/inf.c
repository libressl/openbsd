/*	$OpenBSD$	*/

/*
 * Peter Valchev <pvalchev@openbsd.org> Public Domain, 2002.
 */

#include <math.h>

int
main() {
	if (isinf(HUGE_VAL))
		return 0;
}
