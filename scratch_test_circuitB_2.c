#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "scratch_circuitB_2.h"
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
        printf("Scratch CircuitB_2 Native Test\n");
        printf("Usage: ./scratch_test_circuitB_2 <wire_input_final.in>\n");
        exit(1);
    }

    // Load the verifier input and witness
    FILE *vin = fopen(argv[1], "r");
    assert(vin);

    // Copy data directly into input
    struct {
        struct Input input;   
        struct NIZKInput witness;
    } inputwitness;
    struct Output output;

    u32 *_input = (u32 *) &inputwitness;
    printf("Expecting %ld input rows\n", sizeof(inputwitness)/4);
    int i;
    for (i = 0; i < sizeof(inputwitness)/4; i++) {
        int i_check;
        fscanf(vin, " %d %8x ", &i_check, &_input[i]);
    }
    fclose(vin);

    outsource(&inputwitness.input, &inputwitness.witness, &output);

    //print_hex_digest("hmacG",input.witness.hmacG);
    //for (i = 0; i < 16; i += 1) printf("check_digest[%02d]:%08x\n", i, output.check_digest[i]);
    if (output.output_ok == 0) {
        printf("Output OK!\n");
    } else {
        printf("Output FAILED check\n");
    }

    return 0;
}

