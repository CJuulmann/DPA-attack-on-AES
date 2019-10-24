/*	
	Course: 02255 Practical cryptology E19 @ DTU
	
	Handin #2: DPA attack on AES-128
	Author:	Christina Juulmann study no. 170735

	Found key byte = 161 (base 10) = 0xA1 (base 16)
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

float R[K*55];				// Correlation coefficient values of H,T

float h[D];					// Column buffer of H and T (ith column of H and jth column of T)
float t[D];

/* 
	Prototypes
*/
void populate_vector(char * file,  unsigned char * vector, int size);			// Read data into arrays
void subBytes(unsigned char * state, unsigned char * S);						// S-box lookup
float myCorr(float * h, float * t, int N);										// Correlation coefficent calculation

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
	
	// Compute all values of key to k array
	for(i=0; i<K; i++){
		k[i] = i; 
		//printf("k[%d]= %x\n", i, k[i]);
	}
	
	// Compute hypothetical intermediate values f(d,k):
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

	// Mapping of intermediate values to power consumptions using the Hamming-weight model
	for(i=0; i<(D*K); i++){
		H[i] = __builtin_popcount(V[i]);
		//printf("H[%d]=%d\n", i, H[i]);
	}
	
	// Step 5: Compare hypothetical power consumption values, H, with prower traces, T using the correlation coefficient
	int d;
	for(i=0; i<K; i++){
		for(d=0; d<D; d++){
			h[d] = H[d*K+i];
		}
		for(j=0; j<55; j++){
			for(d=0; d<D; d++){
				t[d] = T[d*55+j];
			}
			R[i*55+j] = myCorr(h,t,D);
		}
	}
	
	// Write correlation coefficients (R) to file
	FILE *ptr;
	ptr = fopen("R.txt", "w");
	
	for(i=0; i<(K*55); i++)
		fprintf(ptr, "%f\n", R[i]);
	
	fclose(ptr);
	
	#ifdef TESTPRINT
		for(i=0; i<(D*55); i++){
			printf("T[%d]= %f\n", i, T[i]);
		}
		puts(" ");
		for(i=0; i<D; i++){
			printf("d[%d]=%f\n", i, d[i]);
		}
		puts(" ");
		for(i=0; i<(K*55); i++){
			printf("R[%d]=%f\n", i, R[i]);
		}
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

float myCorr(float * h, float * t, int N){
	int i;
	float meanh, meant, num, denomh, denomt,corrCoeff;
	meanh = 0;
	meant = 0;
	for (i=0; i<N; i++){
		meanh += h[i];
		meant += t[i];
	}
	meanh /= N;
	meant /= N;
	
	num = 0;
	denomh = 0;
	denomt = 0;
	for (i=0; i<N; i++){
		num += (h[i]-meanh)*(t[i]-meant);
		denomh += (h[i]-meanh)*(h[i]-meanh);
		denomt += (t[i]-meant)*(t[i]-meant);
	}
	
	corrCoeff = num/sqrt(denomh*denomt);
	return corrCoeff;
}

