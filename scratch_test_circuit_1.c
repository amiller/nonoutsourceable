#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "scratch_circuit_1.h"
#include "sha1.h"
#include "assert.h"

void print_hex_digest(const char *name, const u32 *d) {
    int i, j;
    printf("%s:", name);
    for (i = 0; i < 5; i++) {
        printf("%08x", d[i]);
    }
    printf("\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Scratch Circuit1 Native Test\n");
        printf("Usage: ./scratch_test_circuit_1 <wire_input.in>\n");
        exit(1);
    }

    // Load the verifier input and witness
    FILE *vin = fopen(argv[1], "r");
    assert(vin);

    // Copy data directly into input
    struct Input input;
    struct Output output;

    u32 *_input = (u32 *) &input;
    printf("Expecting %ld input rows\n", sizeof(struct Input)/4);
    int i;
    for (i = 0; i < sizeof(struct Input)/4; i++) {
        int i_check;
        fscanf(vin, " %d %8x ", &i_check, &_input[i]);
    }
    fclose(vin);

    outsource(&input, &output);

    print_hex_digest("old_hmac", input.witness.old_hmac);
    print_hex_digest("new_hmac", input.witness.new_hmac);
    print_hex_digest("cblocks", input.witness.cblocks);
    u32 qhere = (input.witness.q1here_qhere_cnum >> 16) & 0xff;
    u32 q1here = (input.witness.q1here_qhere_cnum >> 24) & 0xff;
    u32 cnum = (input.witness.q1here_qhere_cnum >> 8) & 0xff;
    printf("q1here:%d indshere:%d cnum:%d\n", q1here, qhere, cnum);
    for (i = 0; i < 16; i += 1) printf("check_digest[%02d]:%08x\n", i, output.check_digest[i]);
    if (output.output_ok == 0) {
        printf("Output OK!\n");
    } else {
        printf("Output FAILED check\n");
    }

    return 0;
}

