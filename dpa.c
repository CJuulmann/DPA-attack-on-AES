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


float T[D*55]; 	// Traces matrix of size 600x55 - no values exceed the number 256
float d[D];		// Input/data vector of size 600 (inputs5.dat)

int V[D*K];		// Hypo intermediate values matrix
int k[K];		// Key vector with all possible values of k

/* 
	Prototypes
*/
void populate_vector(char * file, float * vector);			// Read data into arrays
void subBytes(unsigned char * state, unsigned char * S);	// S-box lookup


int main(){
	int i;
	
	populate_vector("T5.dat", T);
	populate_vector("inputs5.dat", d);
	
	// Cast float arrays to int for later processing
	int int_d[D];
	for(i=0; i<D; i++){
		int_d[i] = (int) d[i]; 
	}
	
	// Calculate all values of the key, where 1 <= k <= 2^8
	for(i=0; i<K; i++){
		k[i] = i+1; 
		//printf("k[%d]= %x\n", i, k[i]);
	}
	
	// Step 3: Calculate hypothetical intermediate values f(d,k):
	// 			a) xor'ing inputs with every key values
	//			b) S-box lookup with prev value
	int j;
	for(i=0; i<D; i++){
		for(j=0; j<K; j++){
			
			// for each data input xor with all key values
			V[i*K+j] = ((int) d[i]) ^ k[j];
			
			// make S-box lookup with computed value
			subBytes(V[i*K+j], S);
			
			
			/*printf("d[%d]=%x   ", i, (unsigned int) d[i]);
			printf("k[%d]=%x   ", j, (unsigned int) k[j]);
			printf("V[%d]=%x\n", i*K+j, (unsigned int) V[i*K+j]);*/
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
void populate_vector(char * file, float * vector){
	
	int i;
	FILE *fp;

	fp = fopen(file, "r");
	if(fp == NULL){
		perror("Error");
	} else {
		i = 0;
		while(fscanf(fp, "%f %*c", vector+i) == 1){
			i++;
		}
		fclose(fp);
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


