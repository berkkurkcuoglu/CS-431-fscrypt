#include "fscrypt.h"


void *fs_encrypt(void *plaintext, int bufsize, char *keystr, int *resultlen){
    
    cout << "ENCRYPTING..." << endl;
    
    *resultlen = bufsize;
    unsigned char iver[9] = "00000000";
    unsigned char *result = (unsigned char *)malloc(*resultlen+bufsize%BLOCKSIZE);
    
    BF_KEY key;
	BF_set_key(&key, bufsize, (const unsigned char*)keystr);
    
    BF_cbc_encrypt((unsigned char*)plaintext, result, bufsize, &key, iver, BF_ENCRYPT);



	return (void*)result;

}

void *fs_decrypt(void *ciphertext, int bufsize, char *keystr, int *resultlen){

    cout << "DECRYPTING..." << endl;
    
    *resultlen = bufsize;
    unsigned char iver[9] = "00000000";
    unsigned char *result = (unsigned char *)malloc(*resultlen+bufsize%BLOCKSIZE);
    
    BF_KEY key;
    BF_set_key(&key, bufsize, (const unsigned char*)keystr);
    
    BF_cbc_encrypt((unsigned char*)ciphertext, result, bufsize, &key, iver, BF_DECRYPT);
	return (void*)result;
}
