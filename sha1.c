#include "sha1.h"

#ifdef QSP_NATIVE
#include <assert.h>
  #ifndef ASSERT
    #define ASSERT(x) assert(x);
  #endif
#else
  #define ASSERT(x) 
#endif


#define NUM_ROUNDS 80

u32 leftRotate(u32 val, u32 amount) {
   return (val << amount) | (val >> (32 - amount));
}

void sha1hash(u32 *in, u32 fullblocks, u32 len, u32 *output) {
    u32 W[80];  // Expanded message
    u32 i,j,k,iter;
    u32 tmp;
    u32 a, b, c, d, e;

    // We only want to deal with bits even multiples of 32
    ASSERT(len % 32 == 0)
    
    // Make sure the last block leaves room
    ASSERT(len - (fullblocks << 9) <= 416)
    u32 len_d_32 = (len - (fullblocks << 9)) >> 5;
    
    // Initialize the state variables
    //u32 hash[5];
    u32* hash = output;
    
    hash[0] = 0x67452301;
    hash[1] = 0xEFCDAB89;
    hash[2] = 0x98BADCFE;
    hash[3] = 0x10325476;
    hash[4] = 0xC3D2E1F0;
   
    for (iter = 0; iter <= fullblocks; iter += 1) {
        a = hash[0];
        b = hash[1];
        c = hash[2];
        d = hash[3];
        e = hash[4];

        // Copy the message block into W
        for (i = 0; i < 16; i+=1) {
            W[i] = in[16*iter+i];
        }

        // Pad the last message
        if (iter == fullblocks) {
            W[15] = len; /* set lower len bits (sha length is actually 64 bits) */
            W[len_d_32] = 0x80000000; /* padding starts with a 1 */
        
            /* pad out the message */
            for(i = len_d_32+1; i < 15; i+=1) {
                W[i] = 0;
            }
        }
        
        // Expand the message further
        for (i = 16; i < NUM_ROUNDS; i+=1) {
            u32 tmp = W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16];
            W[i] = leftRotate(tmp, 1);
        }

        /*
        printf("W[%d]:", k);
        for (i = 0; i < 16; i++) {
            printf("%08x", W[i]);
        }
        printf("\n");
        */

        for (i = 0; i < NUM_ROUNDS; i+=1) {
            u32 f;
            u32 k;

            if (i < 20) {
                f = (b & c) | ((~b) & d);
                k = 0x5A827999;
            } else if (i < 40) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            } else if (i < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            } else if (i < 80) {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }

            tmp = leftRotate(a, 5) + f + e + k + W[i];

            e = d;
            d = c;
            c = leftRotate(b, 30);
            b = a;
            a = tmp;
        }
        hash[0] = (hash[0] + a) & 0xffffffff;
        hash[1] = (hash[1] + b) & 0xffffffff;
        hash[2] = (hash[2] + c) & 0xffffffff;
        hash[3] = (hash[3] + d) & 0xffffffff;
        hash[4] = (hash[4] + e) & 0xffffffff;
    }
    /*hash[0] = hash[0] & 0xffffffff;
    hash[1] = hash[1] & 0xffffffff;
    hash[2] = hash[2] & 0xffffffff;
    hash[3] = hash[3] & 0xffffffff;
    hash[4] = hash[4] & 0xffffffff;*/
}





