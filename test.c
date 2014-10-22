#include <stdio.h>
#include "aes.h"

int main(void){

aes_context     ctx;

#define KEYSIZE 16

unsigned char key[KEYSIZE] = {};
unsigned char ciphertext[KEYSIZE] = {};
unsigned char plaintext[KEYSIZE] = {};


key[15] = 0xBC;
key[14] = 0xA;

aes_setkey_enc(&ctx, key, 128);

aes_crypt_ecb(&ctx, AES_ENCRYPT, plaintext, ciphertext);

int i;
for (i=0; i < 16; i++)
        printf("%02x", ciphertext[i]);

/*  Set the key and plaintext values  */
if (aes_setkey_enc (&ctx, key, 128))
    /*  error handling code  */
    printf("lololololhahah");
if (aes_crypt_ecb (&ctx, AES_ENCRYPT, plaintext, ciphertext))
    /*  error handling code  */
    printf("lolololol");

return 0;
}
