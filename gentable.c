#include <stdio.h>
#include "aes.h"
#include <math.h>
#include <stdlib.h>

int main(int argc, char* argv[]){
	
	//Converting 2 input arguments to type int.
	int n = atoi(argv[0]);
	int s = atoi(argv[1]);
	
	//Declared variables.
	unsigned long long i;
	unsigned char pass[16] = {};
	int maxpasswordsize = 31;
	aes_context ctx;
	unsigned char ciphertext[16] = {};
	unsigned char plaintext[16] = {};
	int *bitmap = calloc(maxpasswordsize, sizeof(int)); //Creates a bitmap of size maxpassword.
	int *buffer; 
	int count;

	//Create and open a rainbow file.
	FILE *fp;	
	fp = fopen("rainbow","w");
	
	//Memory allocation.
	void memory_allocation(){
	/*  1<<28 = 2^28 = number of bytes for a bitmap with 2^31 entries */
		if (calloc(1<<28, 1))
                	printf("Memory successfully allocated\n");
		 else
                	printf("Memory allocation failed\n");
	}

	//Changing password from integer to 16 byte array.
	void assign (unsigned char *pass, unsigned long long val){	
        	int i;
        	for (i = 15; i >= 8; i--){
                	pass[i] = (unsigned char) val & 0xFF;
                	val >>= 8;
        	}
		for (i =7; i >= 0; i--)
			pass[i] = 0;
	}
	
	//Left fill pass with 0's, retain up to "bits" number of right bits.
	void zeroleftfill (unsigned char *pass, int bits){
		int i;

		if (bits < 0 || bits > 128)
		{
			fprintf(stderr, "Error: invalid value for bits in zeroleftfill:  %d\n", bits);
			exit (-1);
		}

		for (i=15; i >= 0; i--, bits -= 8)
			if (bits <= 0)
				pass[i] = 0;
			else if (bits < 8)
				pass[i] &= (0xFF >> (8-bits));
	}	

	//Handles password (hash-reduce for 1 iteration, setting bitmap to 1.
	void handlePassword(unsigned char *pass, int i){
		aes_setkey_enc(&ctx, pass, 128);
		aes_crypt_ecb(&ctx, AES_ENCRYPT, plaintext, ciphertext);
		zeroleftfill(ciphertext, 16);
		bitmap[i] = 1; //Password is handled.
		*pass = ciphertext;

	}

	//Converts an integer ot a 16 byte array (128 bits)
	for (i= 0; i <= maxpasswordsize; i++){
		for (count = 0; count <= 100; count++){ // 100 iterations of hash-reduce
			if (bitmap[i] == 0){
				assign (pass, i);
				int passSize = sizeof(pass);
				
				handlePassword(pass, i);
				
				//Creating a buffer so that fwrite will write both the password and the hashed password to the rainbow file.
				/*
				int ciphertextSize = sizeof(ciphertext);
				int totalSize = (passSize + ciphertextSize);
				buffer = calloc(totalSize, sizeof(int));
				buffer[0] = pass;
				buffer[ciphertextSize] = ciphertext;
				*/
		
					
				}
			}
		//Writes hash-reduced password to 'rainbow' file. 
		fwrite(ciphertext,1,sizeof(ciphertext),fp);
	}
	
	fclose(fp);


	memory_allocation();
	return 0;
}
