#ifndef PINOCCHIO
#include <stdio.h>
#include <string.h>
#endif

#include "sha1.h"

#ifndef PINOCCHIO

void print_hex_digest(const digest *d) {
    int i, j;
    for (i = 0; i < 5; i++) {
        printf("%08x", d->d[i]);
    }
}

void strncpy_u32(u32 *dst, const char *src, size_t nwords) {
    // Copy into bigendian
    int i;
    for (i = 0; i < nwords; i++) {
        unsigned char* dstArr = (unsigned char*)&dst[i];
        unsigned char* srcArr = (unsigned char*)&src[i*4];
        dstArr[3] = srcArr[0];
        dstArr[2] = srcArr[1];
        dstArr[1] = srcArr[2];
        dstArr[0] = srcArr[3];
    }
}

int main(int argc, char *argv[]) {
    digest dig;

    sha_block inp[2];
    /*char msg[100];
    int i;
    for (i = 0; i < 100; i++) {
        msg[i] = i;
        }*/
    const char *msg = "https://encrypted.google.com/search?hl=en&q=unix%20pipe%20string#hl=en&q=unx+cycle+cat+loop&safe=off";
    int len = 100*8;
    //char msg[64] = "abcd";

    strncpy_u32((u32*)inp, msg, 25);

    sha1hash((sha_block*) inp, 1, len, dig.d);
    print_hex_digest(&dig);
    printf("\n");
    return 0;
}

#endif
