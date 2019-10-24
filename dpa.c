/*	
	Course: 02255 Practical cryptology E19 @ DTU
	
	Handin #2 DPA 
	Author:	Christina Juulmann study no. 170735
*/

#include <stdio.h>
#include <inttypes.h>
#include "sbox.h"
#include <math.h>


#define D 600
#define K 256
//#define TESTPRINT


float T[D*55]; 				// Traces matrix of size 600x55 - 600 traces with 55 samples each
unsigned char d[D];			// Input/data vector of size 600 (inputs5.dat)

unsigned char V[D*K];		// Hypothetical intermediate values matrix
unsigned char k[K];			// Key vector with all possible values of k
unsigned char H[D*K];		// Hypothetical power consumption values matrix (for HW model)

int R[K*55];				// Correlation coefficient values of H and T
float H_means[K];			// Mean values for all hypo power consumptions of all key choices
float T_means[55];
float H_s[K];				// standard deviation

/* 
	Prototypes
*/
void populate_vector(char * file,  unsigned char * vector, int size);			// Read data into arrays
void subBytes(unsigned char * state, unsigned char * S);				// S-box lookup


int main(){
	int i;
	
	// Retreive input data as unsigned chars (1 byte sizing)
	populate_vector("inputs5.dat", d, D);
	
	// Retreive Power traces
	FILE *fp;
	fp = fopen("T5.dat", "r");
	if(fp == NULL){
		perror("Error");
	} else {
		i = 0;
		while(fscanf(fp, "%f %*c", &T[i]) == 1){	// Skip comma and newlines
			i++;
		}
		fclose(fp);
	}
	
	// Calculate all values of the key
	for(i=0; i<K; i++){
		k[i] = i; 
		//printf("k[%d]= %x\n", i, k[i]);
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

	// Step 4: Mapping intermediate values to power consumptions using the Hamming-weight model
	for(i=0; i<(D*K); i++){
		H[i] = __builtin_popcount(V[i]);
		//printf("H[%d]=%d\n", i, H[i]);
	}
	
	// Step 5: Compare hypothetical power consumption values, H, with prower traces, T using the correlation coefficient
	
	// Calculate mean values of H and T columns 
	float sum;
	for(j=0; j<K; j++){
		sum = 0;
		
		for(i=0; i<D; i++){
			sum += (float) H[i*K+j];
		}
		H_means[j] = sum/D;
		printf("H_means[%d]=%f\n", j, H_means[j]);
	}
	
	for(j=0; j<55; j++){
		sum = 0;
		
		for(i=0; i<D; i++){
			sum += T[i*55+j];
		}
		T_means[j] = sum/D;
		printf("T_means[%d]=%f\n", j, T_means[j]);
	}
	
	// Calculate std deviation of H and T
	double temp;
	for(j=0; j<K; j++){
		sum = 0;
		for(i=0; i<K; i++){
			temp = (double) (H[i*K+j] - H_means[j]);
			sum += (float) pow(temp, 2);	
		}
		H_s[j] = sqrt(sum/(K-1)); 
	}
	
	// Compute correlation coefficient
	// Z_h[i] = (H[i]-H_means[i]) / H_s[i]
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
	
	// Convert to unsigned char for 1 byte sizes
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


