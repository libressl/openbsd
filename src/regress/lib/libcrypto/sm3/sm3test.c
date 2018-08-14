/*
* Copyright (c) 2018, Ribose Inc
*
* Permission to use, copy, modify, and/or distribute this software for any
* purpose with or without fee is hereby granted, provided that the above
* copyright notice and this permission notice appear in all copies.
*
* THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
* WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
* MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
* SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
* WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
* OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
* CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

#define SM3_TESTS 3

const char* sm3_input[SM3_TESTS] = {
   "",
   "abc",
   "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
};

const char* sm3_expected[SM3_TESTS] = {
   "1AB21D8355CFA17F8E61194831E81A8F22BEC8C728FEFB747ED035EB5082AA2B",
   "66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0",
   "DEBE9FF92275B8A138604889C18E5A4D6FDB70E5387E5765293DCBA39C0C5732"
};

char* hex_encode(const uint8_t *input, size_t len)
   {
   const char* hex = "0123456789ABCDEF";
   char   *out;
   size_t  i;

   out = malloc(len*2+1);
   for (i=0; i<len; i++)
      {
      out[i*2]   = hex[input[i] >> 4];
      out[i*2+1] = hex[input[i] & 0x0F];
      }
   out[len*2] = '\0';

   return out;
   }

int main()
   {
   EVP_MD_CTX* ctx;
   int i;
   uint8_t digest[32];
   char* hexdigest;
   int err = 0;

   ctx = EVP_MD_CTX_new();

   for (i = 0; i != SM3_TESTS; ++i)
      {
      EVP_DigestInit(ctx, EVP_sm3());
      EVP_DigestUpdate(ctx, sm3_input[i], strlen(sm3_input[i]));
      EVP_DigestFinal(ctx, digest, NULL);

      hexdigest = hex_encode(digest, sizeof(digest));

      if (strcmp(hexdigest, sm3_expected[i]) != 0)
         {
         fprintf(stderr, "TEST %d failed\nProduced %s\nExpected %s\n", i, hexdigest, sm3_expected[i]);
         ++err;
         }
      else
         fprintf(stderr, "SM3 test %d ok\n", i);

      free(hexdigest);
      }

   EVP_MD_CTX_free(ctx);

   return (err > 0) ? 1 : 0;
   }
