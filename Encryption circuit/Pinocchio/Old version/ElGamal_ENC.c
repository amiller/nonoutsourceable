#include "ElGamal_ENC-ifc.h"

void mul(int* a, int* b, int* c){

	int i,j;
	for( i = 0; i < MUE; i+=1){
		c[i] = 0;
	}	
	for( i = 0; i < MUE; i+=1){
		for( j = 0; j < MUE; j+=1){
			int k = i + j;
			if(k < MUE){
				c[k] += a[i]*b[j];		
			}
			k = i+j-MUE;
			if(k >= 0){
				c[k] += OMEGA*a[i]*b[j];	
			}
		}	
	}
}

void exp(int* a, int* exp, int* c){

	int powersTable[MUE*EXP_BITS];
	int i,j;	
	for( i = 0; i < MUE; i+=1){
		powersTable[i] = a[i];
	}
	for( j = 1; j < EXP_BITS; j+=1){
		mul(&powersTable[(j-1)*MUE], &powersTable[(j-1)*MUE], &powersTable[j*MUE]);	
	}

	c[0] = 1;
	for( i = 1; i < MUE; i+=1){
		c[i] = 0;
	}

	for( j = 0; j < EXP_BITS; j+=1){

		if(exp[j] == 1){
			int temp[MUE];
			for( i = 0; i < MUE; i+=1){
				temp[i] = c[i];
			}
			mul(temp, &powersTable[j*MUE], c);
		}		
	}
}

void outsource(struct Input *input, struct Output *output)
{

	exp(input->g, input->y, output->g_to_y);
	
	int h_to_y[MUE];
	exp(input->h, input->y, h_to_y);

	int i;
	for( i = 0; i < MESSAGE_BLOCKS; i+=1){
		mul(&input->message[i*MUE], h_to_y, &output->cipher[i*MUE]);
	}

}
