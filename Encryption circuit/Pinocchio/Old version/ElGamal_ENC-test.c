#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "qsp-test.h"
#include "floyd-ifc.h"

RAND_CORE

void outsource_reference(struct Input *input, struct Output *output)
{
	assert(0);
}

const char* test_name() { return "ElGamal_ENC"; }

#define MAX_EDGE 0x3fffffff

uint32_t test_core(int iter)
{
}

void print_output(char* buf, int buflen, struct Output* output)
{
}
