/* crypto/rc5/rc5speed.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 * 
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from 
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

/* 11-Sep-92 Andrew Daviel   Support for Silicon Graphics IRIX added */
/* 06-Apr-92 Luke Brennan    Support for VMS and add extra signal calls */

#include <sys/types.h>
#include <sys/times.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include <openssl/rc5.h>

#define HZ ((double)CLK_TCK)

#define BUFSIZE	((long)1024)
long run=0;

double Time_F(int s);

void sig_done(int sig);
void sig_done(int sig)
	{
	signal(SIGALRM,sig_done);
	run=0;
	}

#define START	0
#define STOP	1

double Time_F(int s)
	{
	double ret;
	static struct tms tstart,tend;

	if (s == START)
		{
		times(&tstart);
		return(0);
		}
	else
		{
		times(&tend);
		ret=((double)(tend.tms_utime-tstart.tms_utime))/HZ;
		return((ret == 0.0)?1e-6:ret);
		}
	}

int main(int argc, char **argv)
	{
	long count;
	static unsigned char buf[BUFSIZE];
	static unsigned char key[] ={
			0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0,
			0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,
			};
	RC5_32_KEY sch;
	double a,b,c,d;
#ifndef SIGALRM
	long ca,cb,cc;
#endif

#ifndef TIMES
	printf("To get the most accurate results, try to run this\n");
	printf("program when this computer is idle.\n");
#endif

#ifndef SIGALRM
	printf("First we calculate the approximate speed ...\n");
	RC5_32_set_key(&sch,16,key,12);
	count=10;
	do	{
		long i;
		unsigned long data[2];

		count*=2;
		Time_F(START);
		for (i=count; i; i--)
			RC5_32_encrypt(data,&sch);
		d=Time_F(STOP);
		} while (d < 3.0);
	ca=count/512;
	cb=count;
	cc=count*8/BUFSIZE+1;
	printf("Doing RC5_32_set_key %ld times\n",ca);
#define COND(d)	(count != (d))
#define COUNT(d) (d)
#else
#define COND(c)	(run)
#define COUNT(d) (count)
	signal(SIGALRM,sig_done);
	printf("Doing RC5_32_set_key for 10 seconds\n");
	alarm(10);
#endif

	Time_F(START);
	for (count=0,run=1; COND(ca); count+=4)
		{
		RC5_32_set_key(&sch,16,key,12);
		RC5_32_set_key(&sch,16,key,12);
		RC5_32_set_key(&sch,16,key,12);
		RC5_32_set_key(&sch,16,key,12);
		}
	d=Time_F(STOP);
	printf("%ld RC5_32_set_key's in %.2f seconds\n",count,d);
	a=((double)COUNT(ca))/d;

	printf("Doing RC5_32_encrypt's for 10 seconds\n");
	alarm(10);

	Time_F(START);
	for (count=0,run=1; COND(cb); count+=4)
		{
		unsigned long data[2];

		RC5_32_encrypt(data,&sch);
		RC5_32_encrypt(data,&sch);
		RC5_32_encrypt(data,&sch);
		RC5_32_encrypt(data,&sch);
		}
	d=Time_F(STOP);
	printf("%ld RC5_32_encrypt's in %.2f second\n",count,d);
	b=((double)COUNT(cb)*8)/d;

	printf("Doing RC5_32_cbc_encrypt on %ld byte blocks for 10 seconds\n",
		BUFSIZE);
	alarm(10);

	Time_F(START);
	for (count=0,run=1; COND(cc); count++)
		RC5_32_cbc_encrypt(buf,buf,BUFSIZE,&sch,
			&(key[0]),RC5_ENCRYPT);
	d=Time_F(STOP);
	printf("%ld RC5_32_cbc_encrypt's of %ld byte blocks in %.2f second\n",
		count,BUFSIZE,d);
	c=((double)COUNT(cc)*BUFSIZE)/d;

	printf("RC5_32/12/16 set_key       per sec = %12.2f (%9.3fuS)\n",a,1.0e6/a);
	printf("RC5_32/12/16 raw ecb bytes per sec = %12.2f (%9.3fuS)\n",b,8.0e6/b);
	printf("RC5_32/12/16 cbc     bytes per sec = %12.2f (%9.3fuS)\n",c,8.0e6/c);
	exit(0);
	}
