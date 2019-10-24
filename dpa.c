/*
	Course: Practical cryptology E19
	 			Handin #2 DPA 
	Author:	Christina Juulmann study no. 170735
*/

#include <stdio.h>
#include <inttypes.h>
#include "sbox.h"


#define D 600
#define K 256
//#define TESTPRINT


unsigned char T[D*55]; 		// Traces matrix of size 600x55 - no values exceed the number 256
unsigned char d[D];			// Input/data vector of size 600 (inputs5.dat)

unsigned char V[D*K];		// Hypo intermediate values matrix
unsigned char k[K];			// Key vector with all possible values of k

/* 
	Prototypes
*/
void populate_vector(char * file,  unsigned char * vector, int size);			// Read data into arrays
void subBytes(unsigned char * state, unsigned char * S);				// S-box lookup


int main(){
	int i;
	
	populate_vector("T5.dat", T, D*55);
	populate_vector("inputs5.dat", d, D);
	
	// Calculate all values of the key, where 1 <= k <= 2^8 - or is it? currently 0 <= k <= 2^8-1
	for(i=0; i<K; i++){
		k[i] = i; 
		printf("k[%d]= %x\n", i, k[i]);
	}
	
	// Step 3: Calculate hypothetical intermediate values f(d,k):
	int j;
	for(i=0; i<D; i++){
		for(j=0; j<K; j++){
			
			// For each data input xor with all key values
			V[i*K+j] = d[i] ^ k[j];
			//printf("%x XOR %x = V[%d]=%x\n", d[i], k[j], i*K+j, V[i*K+j]);
			
			// Make S-box lookup with computed value
			subBytes(&V[i*K+j], S);
			//printf("V[%d]=%x\n",i*K+j, V[i*K+j]);
			
		}
	}	

	#ifdef TESTPRINT
		for(i=0; i<(D*55); i++){
			printf("T[%d]= %f\n", i, T[i]);
		}
		puts(" ");
		for(i=0; i<D; i++){
			printf("d[%d]=%f\n", i, d[i]);
		}
		puts(" ");
	#endif
	
	return 0;
}

/*
	Function definitons
*/
void populate_vector(char * file, unsigned char * vector, int size){
	
	int i;
	FILE *fp;
	float temp_arr[size];

	// Read data from file stream
	fp = fopen(file, "r");
	if(fp == NULL){
		perror("Error");
	} else {
		i = 0;
		while(fscanf(fp, "%f %*c", &temp_arr[i]) == 1){	// Skip comma and newlines
			i++;
		}
		fclose(fp);
	}
	
	// Convert to unsigned char of 1 byte
	for(i=0; i<size; i++){
		vector[i] = (unsigned char) temp_arr[i];
		printf("vector[%d]=%x\n", i, vector[i]);
	}
}
void subBytes(unsigned char * state, unsigned char * S){
	
	uint8_t i;
	uint8_t a, b, idx;					//entries to S-box
	
	for(i=0; i<16; i++){
		
		// mask first and last four bits for a,b entries
		a = (uint8_t)(state[i] & 0xf0);
		a = a >> 4;
		
		b = (uint8_t)(state[i] & 0x0f);

		// S-box lookup
		idx = ((16*a)+b);
		state[i] = S[idx];
	}
}


