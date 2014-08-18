/* $OpenBSD: rc5_locl.h,v 1.6 2014/08/18 19:15:34 bcook Exp $ */
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

#include <stdint.h>
#include <stdlib.h>

#include <openssl/opensslconf.h>

#undef c2l
#define c2l(c,l)	(l =((unsigned long)(*((c)++)))    , \
			 l|=((unsigned long)(*((c)++)))<< 8L, \
			 l|=((unsigned long)(*((c)++)))<<16L, \
			 l|=((unsigned long)(*((c)++)))<<24L)

/* NOTE - c is not incremented as per c2l */
#undef c2ln
#define c2ln(c,l1,l2,n)	{ \
			c+=n; \
			l1=l2=0; \
			switch (n) { \
			case 8: l2 =((unsigned long)(*(--(c))))<<24L; \
			case 7: l2|=((unsigned long)(*(--(c))))<<16L; \
			case 6: l2|=((unsigned long)(*(--(c))))<< 8L; \
			case 5: l2|=((unsigned long)(*(--(c))));     \
			case 4: l1 =((unsigned long)(*(--(c))))<<24L; \
			case 3: l1|=((unsigned long)(*(--(c))))<<16L; \
			case 2: l1|=((unsigned long)(*(--(c))))<< 8L; \
			case 1: l1|=((unsigned long)(*(--(c))));     \
				} \
			}

#undef l2c
#define l2c(l,c)	(*((c)++)=(unsigned char)(((l)     )&0xff), \
			 *((c)++)=(unsigned char)(((l)>> 8L)&0xff), \
			 *((c)++)=(unsigned char)(((l)>>16L)&0xff), \
			 *((c)++)=(unsigned char)(((l)>>24L)&0xff))

/* NOTE - c is not incremented as per l2c */
#undef l2cn
#define l2cn(l1,l2,c,n)	{ \
			c+=n; \
			switch (n) { \
			case 8: *(--(c))=(unsigned char)(((l2)>>24L)&0xff); \
			case 7: *(--(c))=(unsigned char)(((l2)>>16L)&0xff); \
			case 6: *(--(c))=(unsigned char)(((l2)>> 8L)&0xff); \
			case 5: *(--(c))=(unsigned char)(((l2)     )&0xff); \
			case 4: *(--(c))=(unsigned char)(((l1)>>24L)&0xff); \
			case 3: *(--(c))=(unsigned char)(((l1)>>16L)&0xff); \
			case 2: *(--(c))=(unsigned char)(((l1)>> 8L)&0xff); \
			case 1: *(--(c))=(unsigned char)(((l1)     )&0xff); \
				} \
			}

/* NOTE - c is not incremented as per n2l */
#define n2ln(c,l1,l2,n)	{ \
			c+=n; \
			l1=l2=0; \
			switch (n) { \
			case 8: l2 =((unsigned long)(*(--(c))))    ; \
			case 7: l2|=((unsigned long)(*(--(c))))<< 8; \
			case 6: l2|=((unsigned long)(*(--(c))))<<16; \
			case 5: l2|=((unsigned long)(*(--(c))))<<24; \
			case 4: l1 =((unsigned long)(*(--(c))))    ; \
			case 3: l1|=((unsigned long)(*(--(c))))<< 8; \
			case 2: l1|=((unsigned long)(*(--(c))))<<16; \
			case 1: l1|=((unsigned long)(*(--(c))))<<24; \
				} \
			}

/* NOTE - c is not incremented as per l2n */
#define l2nn(l1,l2,c,n)	{ \
			c+=n; \
			switch (n) { \
			case 8: *(--(c))=(unsigned char)(((l2)    )&0xff); \
			case 7: *(--(c))=(unsigned char)(((l2)>> 8)&0xff); \
			case 6: *(--(c))=(unsigned char)(((l2)>>16)&0xff); \
			case 5: *(--(c))=(unsigned char)(((l2)>>24)&0xff); \
			case 4: *(--(c))=(unsigned char)(((l1)    )&0xff); \
			case 3: *(--(c))=(unsigned char)(((l1)>> 8)&0xff); \
			case 2: *(--(c))=(unsigned char)(((l1)>>16)&0xff); \
			case 1: *(--(c))=(unsigned char)(((l1)>>24)&0xff); \
				} \
			}

#undef n2l
#define n2l(c,l)        (l =((unsigned long)(*((c)++)))<<24L, \
                         l|=((unsigned long)(*((c)++)))<<16L, \
                         l|=((unsigned long)(*((c)++)))<< 8L, \
                         l|=((unsigned long)(*((c)++))))

#undef l2n
#define l2n(l,c)        (*((c)++)=(unsigned char)(((l)>>24L)&0xff), \
                         *((c)++)=(unsigned char)(((l)>>16L)&0xff), \
                         *((c)++)=(unsigned char)(((l)>> 8L)&0xff), \
                         *((c)++)=(unsigned char)(((l)     )&0xff))

static inline uint32_t ROTATE_l32(uint32_t a, uint32_t n)
{
	uint32_t amt = n & 0x1f;
	return (a << amt) | (a >> (32 - amt));
}

static inline uint32_t ROTATE_r32(uint32_t a, uint32_t n)
{
	uint32_t amt = n & 0x1f;
	return (a << (32 - amt)) | (a >> amt);
}

#define RC5_32_MASK	0xffffffffL

#define RC5_16_P	0xB7E1
#define RC5_16_Q	0x9E37
#define RC5_32_P	0xB7E15163L
#define RC5_32_Q	0x9E3779B9L
#define RC5_64_P	0xB7E151628AED2A6BLL
#define RC5_64_Q	0x9E3779B97F4A7C15LL

#define E_RC5_32(a,b,s,n) \
	a^=b; \
	a=ROTATE_l32(a,b); \
	a+=s[n]; \
	a&=RC5_32_MASK; \
	b^=a; \
	b=ROTATE_l32(b,a); \
	b+=s[n+1]; \
	b&=RC5_32_MASK;

#define D_RC5_32(a,b,s,n) \
	b-=s[n+1]; \
	b&=RC5_32_MASK; \
	b=ROTATE_r32(b,a); \
	b^=a; \
	a-=s[n]; \
	a&=RC5_32_MASK; \
	a=ROTATE_r32(a,b); \
	a^=b;



