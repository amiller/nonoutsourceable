#pragma once



#define MUE 4            
#define OMEGA 2           // The free term in the irreducible Polynomial
#define EXP_BITS 512     // Number of bits in the exponent ( should be > 1500 ) -- This is temporary [1500 bits will generate a massive circuit]

struct Input {
	// no input here anymore
	int dummy;  // to avoid a bug
};


struct NIZKInput {
	int y[EXP_BITS]; // needed to calculate: g^y, and h^y. 
			 // y is being dealt with as a bit vector for now. 
	int dummy; // to avoid  another bug
};


struct Output {
	int cipher_g_to_y[MUE];
	int cipher_h_to_y[MUE];	
};


void outsource(struct Input *input, struct NIZKInput *nizkinput, struct Output *output);
