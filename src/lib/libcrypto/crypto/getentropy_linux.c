/*	$OpenBSD: getentropy_linux.c,v 1.40 2015/08/25 17:26:43 deraadt Exp $	*/

/*
 * Copyright (c) 2014 Theo de Raadt <deraadt@openbsd.org>
 * Copyright (c) 2014 Bob Beck <beck@obtuse.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * Emulation of getentropy(2) as documented at:
 * http://www.openbsd.org/cgi-bin/man.cgi/OpenBSD-current/man2/getentropy.2
 */

#define	_POSIX_C_SOURCE	199309L
#define	_GNU_SOURCE	1
#include <sys/types.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#ifdef SYS__sysctl
#include <linux/sysctl.h>
#endif
#include <sys/statvfs.h>
#include <sys/socket.h>
#include <sys/mount.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <link.h>
#include <termios.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <openssl/sha.h>

#include <linux/types.h>
#include <linux/random.h>
#ifdef HAVE_GETAUXVAL
#include <sys/auxv.h>
#endif
#include <sys/vfs.h>

#define REPEAT 5
#define min(a, b) (((a) < (b)) ? (a) : (b))

#define HX(a, b) \
	do { \
		if ((a)) \
			HD(errno); \
		else \
			HD(b); \
	} while (0)

#define HR(x, l) (SHA512_Update(&ctx, (char *)(x), (l)))
#define HD(x)	 (SHA512_Update(&ctx, (char *)&(x), sizeof (x)))
#define HF(x)    (SHA512_Update(&ctx, (char *)&(x), sizeof (void*)))

int	getentropy(void *buf, size_t len);

static int gotdata(char *buf, size_t len);
#ifdef SYS_getrandom
static int getentropy_getrandom(void *buf, size_t len);
#endif
static int getentropy_urandom(void *buf, size_t len);
#ifdef SYS__sysctl
static int getentropy_sysctl(void *buf, size_t len);
#endif
static int getentropy_fallback(void *buf, size_t len);
static int getentropy_phdr(struct dl_phdr_info *info, size_t size, void *data);

int
getentropy(void *buf, size_t len)
{
	int ret = -1;

	if (len > 256) {
		errno = EIO;
		return (-1);
	}

#ifdef SYS_getrandom
	/*
	 * Try descriptor-less getrandom()
	 */
	ret = getentropy_getrandom(buf, len);
	if (ret != -1)
		return (ret);
	if (errno != ENOSYS)
		return (-1);
#endif

	/*
	 * Try to get entropy with /dev/urandom
	 *
	 * This can fail if the process is inside a chroot or if file
	 * descriptors are exhausted.
	 */
	ret = getentropy_urandom(buf, len);
	if (ret != -1)
		return (ret);

#ifdef SYS__sysctl
	/*
	 * Try to use sysctl CTL_KERN, KERN_RANDOM, RANDOM_UUID.
	 * sysctl is a failsafe API, so it guarantees a result.  This
	 * should work inside a chroot, or when file descriptors are
	 * exhuasted.
	 *
	 * However this can fail if the Linux kernel removes support
	 * for sysctl.  Starting in 2007, there have been efforts to
	 * deprecate the sysctl API/ABI, and push callers towards use
	 * of the chroot-unavailable fd-using /proc mechanism --
	 * essentially the same problems as /dev/urandom.
	 *
	 * Numerous setbacks have been encountered in their deprecation
	 * schedule, so as of June 2014 the kernel ABI still exists on
	 * most Linux architectures. The sysctl() stub in libc is missing
	 * on some systems.  There are also reports that some kernels
	 * spew messages to the console.
	 */
	ret = getentropy_sysctl(buf, len);
	if (ret != -1)
		return (ret);
#endif /* SYS__sysctl */

	/*
	 * Entropy collection via /dev/urandom and sysctl have failed.
	 *
	 * No other API exists for collecting entropy.  See the large
	 * comment block above.
	 *
	 * We have very few options:
	 *     - Even syslog_r is unsafe to call at this low level, so
	 *	 there is no way to alert the user or program.
	 *     - Cannot call abort() because some systems have unsafe
	 *	 corefiles.
	 *     - Could raise(SIGKILL) resulting in silent program termination.
	 *     - Return EIO, to hint that arc4random's stir function
	 *       should raise(SIGKILL)
	 *     - Do the best under the circumstances....
	 *
	 * This code path exists to bring light to the issue that Linux
	 * does not provide a failsafe API for entropy collection.
	 *
	 * We hope this demonstrates that Linux should either retain their
	 * sysctl ABI, or consider providing a new failsafe API which
	 * works in a chroot or when file descriptors are exhausted.
	 */
#ifdef FAIL_INSTEAD_OF_TRYING_FALLBACK
	raise(SIGKILL);
#endif
	ret = getentropy_fallback(buf, len);
	if (ret != -1)
		return (ret);

	errno = EIO;
	return (ret);
}

/*
 * Basic sanity checking; wish we could do better.
 */
static int
gotdata(char *buf, size_t len)
{
	char	any_set = 0;
	size_t	i;

	for (i = 0; i < len; ++i)
		any_set |= buf[i];
	if (any_set == 0)
		return (-1);
	return (0);
}

#ifdef SYS_getrandom
static int
getentropy_getrandom(void *buf, size_t len)
{
	int pre_errno = errno;
	int ret;
	if (len > 256)
		return (-1);
	do {
		ret = syscall(SYS_getrandom, buf, len, 0);
	} while (ret == -1 && errno == EINTR);

	if (ret != len)
		return (-1);
	errno = pre_errno;
	return (0);
}
#endif

static int
getentropy_urandom(void *buf, size_t len)
{
	struct stat st;
	size_t i;
	int fd, cnt, flags;
	int save_errno = errno;

start:

	flags = O_RDONLY;
#ifdef O_NOFOLLOW
	flags |= O_NOFOLLOW;
#endif
#ifdef O_CLOEXEC
	flags |= O_CLOEXEC;
#endif
	fd = open("/dev/urandom", flags, 0);
	if (fd == -1) {
		if (errno == EINTR)
			goto start;
		goto nodevrandom;
	}
#ifndef O_CLOEXEC
	fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);
#endif

	/* Lightly verify that the device node looks sane */
	if (fstat(fd, &st) == -1 || !S_ISCHR(st.st_mode)) {
		close(fd);
		goto nodevrandom;
	}
	if (ioctl(fd, RNDGETENTCNT, &cnt) == -1) {
		close(fd);
		goto nodevrandom;
	}
	for (i = 0; i < len; ) {
		size_t wanted = len - i;
		ssize_t ret = read(fd, (char *)buf + i, wanted);

		if (ret == -1) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			close(fd);
			goto nodevrandom;
		}
		i += ret;
	}
	close(fd);
	if (gotdata(buf, len) == 0) {
		errno = save_errno;
		return (0);		/* satisfied */
	}
nodevrandom:
	errno = EIO;
	return (-1);
}

#ifdef SYS__sysctl
static int
getentropy_sysctl(void *buf, size_t len)
{
	static int mib[] = { CTL_KERN, KERN_RANDOM, RANDOM_UUID };
	size_t i;
	int save_errno = errno;

	for (i = 0; i < len; ) {
		size_t chunk = min(len - i, 16);

		/* SYS__sysctl because some systems already removed sysctl() */
		struct __sysctl_args args = {
			.name = mib,
			.nlen = 3,
			.oldval = (char *)buf + i,
			.oldlenp = &chunk,
		};
		if (syscall(SYS__sysctl, &args) != 0)
			goto sysctlfailed;
		i += chunk;
	}
	if (gotdata(buf, len) == 0) {
		errno = save_errno;
		return (0);			/* satisfied */
	}
sysctlfailed:
	errno = EIO;
	return (-1);
}
#endif /* SYS__sysctl */

static const int cl[] = {
	CLOCK_REALTIME,
#ifdef CLOCK_MONOTONIC
	CLOCK_MONOTONIC,
#endif
#ifdef CLOCK_MONOTONIC_RAW
	CLOCK_MONOTONIC_RAW,
#endif
#ifdef CLOCK_TAI
	CLOCK_TAI,
#endif
#ifdef CLOCK_VIRTUAL
	CLOCK_VIRTUAL,
#endif
#ifdef CLOCK_UPTIME
	CLOCK_UPTIME,
#endif
#ifdef CLOCK_PROCESS_CPUTIME_ID
	CLOCK_PROCESS_CPUTIME_ID,
#endif
#ifdef CLOCK_THREAD_CPUTIME_ID
	CLOCK_THREAD_CPUTIME_ID,
#endif
};

static int
getentropy_phdr(struct dl_phdr_info *info, size_t size, void *data)
{
	SHA512_CTX *ctx = data;

	SHA512_Update(ctx, &info->dlpi_addr, sizeof (info->dlpi_addr));
	return (0);
}
