#pragma once

#if PARAM==0
#define SIZE	1
#elif PARAM==1
#define SIZE	2
#elif PARAM==2
#define SIZE	3
#elif PARAM==3
#define SIZE	4
#else
#error unknown PARAM
#endif

#define MUE 8            
#define OMEGA 2           // The free term in the irreducible Polynomial
#define BLOCKS 4  // Number of message blocks to be encrypted (To be changed later to 4)
#define EXP_BITS 600     // Number of bits in the exponent ( should be > 1500 ) -- This is temporary [1500 bits will generate a massive circuit]

struct Input {
	int cipherText[MUE*(1+BLOCKS)]; // the ciphertext to verify
	// int puz;  to be added
};


struct NIZKInput {
	int y[EXP_BITS]; // needed to calculate: g^y, and h^y. 
			 // y is being dealt with as a bit vector for now. This's an assumption to be discussed in detail. This is to avoid split gates. Note: having y's as zeros and ones, will not add much effort in the verification stage.
	int ticket[BLOCKS*MUE];
	int dummy; // to solve a bug
};


struct Output {
	int encryptionVerified;
};


void outsource(struct Input *input, struct NIZKInput *nizkinput, struct Output *output);
