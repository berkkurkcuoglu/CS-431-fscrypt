#include "fscrypt.h"


void *fs_encrypt(void *plaintext, int bufsize, char *keystr, int *resultlen){
    
    cout << "ENCRYPTING..." << endl;

	unsigned char* plainText = (unsigned char *)plaintext;
	int padding = bufsize % BLOCKSIZE; //find padding size
    int blockCount = (padding > 0) ? (bufsize/BLOCKSIZE+1) : (bufsize/BLOCKSIZE); //find block count
	*resultlen = bufsize;
	
    BF_KEY key;
	BF_set_key(&key, bufsize, (const unsigned char*)keystr);

	vector<unsigned char *> *blocks = new vector<unsigned char *>();
	vector<unsigned char *> *encBlocks = new vector<unsigned char *>();
    unsigned char *temp;

  //divide into blocks
	for(int i=0; i < blockCount; i++){
        temp = (unsigned char*)calloc(BLOCKSIZE, sizeof(unsigned char));
		for(int j=0; j < BLOCKSIZE; j++){
			if( plainText[i * BLOCKSIZE + j] != '\0')
				temp[j] = plainText[i * BLOCKSIZE + j];
			else{
				for(int k=0;k <= padding; k++)
					temp[j + k] = 0;
				break;
			}
		}
		 blocks->push_back(temp);
    }
	
	unsigned char *exor, *cipher,*plain;
	
  //xor and encrypt blocks
	for(int i=0; i < blockCount; i++){
        temp = (unsigned char*)calloc(BLOCKSIZE, sizeof(unsigned char));
        exor = (unsigned char*)calloc(BLOCKSIZE, sizeof(unsigned char));
        cipher = (unsigned char*)calloc(BLOCKSIZE, sizeof(unsigned char));
        plain = (unsigned char*)calloc(BLOCKSIZE, sizeof(unsigned char));
        cipher = (i>0) ? (encBlocks->at(i-1)) : ((unsigned char*) "0000000");
		plain = blocks->at(i);
		for(int j=0; j < BLOCKSIZE; j++){
			exor[j] = cipher[j] ^ plain[j];
		}
		BF_ecb_encrypt(exor, temp, &key, BF_ENCRYPT);
        encBlocks->push_back(temp);

	}
    //put blocks together
	unsigned char *result = (unsigned char *)malloc(*resultlen+padding);
	for(int i = 0; i < blockCount ; i++){
        temp = (unsigned char*)calloc(BLOCKSIZE, sizeof(unsigned char));
		temp = encBlocks->at(i);
        cout << "cipher block " << i << endl;
        for(int j = 0; j < BLOCKSIZE; j++){
			result[i * BLOCKSIZE + j] = temp[j];
            printf("%02x", temp[j]);
        }
        cout << endl;
	}
    free(blocks);
    free(encBlocks);
    cout << "DONE ENCRYPTING!" << endl;

	return (void*)result;

}

void *fs_decrypt(void *ciphertext, int bufsize, char *keystr, int *resultlen){

    cout << "DECRYPTING..." << endl;
    
	unsigned char* cipherText = (unsigned char *)ciphertext;
	int blockCount = (bufsize % BLOCKSIZE > 0) ? (bufsize/BLOCKSIZE+1) : (bufsize/BLOCKSIZE);
    *resultlen = bufsize;
	BF_KEY key;
	BF_set_key(&key, bufsize, (const unsigned char*)keystr);

	vector<unsigned char *> *blocks = new vector<unsigned char *>();
	vector<unsigned char *> *decBlocks = new vector<unsigned char *>();
    unsigned char *temp;
    
    //divide into blocks
	for(int i=0; i < blockCount; i++){
        temp = (unsigned char*)calloc(BLOCKSIZE, sizeof(unsigned char));
        for(int j=0; j < BLOCKSIZE; j++)
				temp[j] = cipherText[i * BLOCKSIZE + j];
		blocks->push_back(temp);
	}
	
    unsigned char *exor, *cipher,*prev;
    //decrypt and exor blocks
	for(int i=0; i < blockCount; i++){
        exor = (unsigned char *)calloc(BLOCKSIZE, sizeof(unsigned char));
        temp = (unsigned char*)calloc(BLOCKSIZE, sizeof(unsigned char));
        cipher = (unsigned char*)calloc(BLOCKSIZE, sizeof(unsigned char));
        prev = (unsigned char*)calloc(BLOCKSIZE, sizeof(unsigned char));
        prev = (i>0) ? (blocks->at(i-1)) : ((unsigned char*) "0000000");
        cipher = blocks->at(i);
		BF_ecb_encrypt(cipher, temp, &key, BF_DECRYPT);
		for(int j=0; j < BLOCKSIZE; j++){
			exor[j] = prev[j] ^ temp[j];
		}
        //printf("exor: %02x%02x%02x%02x%02x%02x%02x%02x \n", exor[0],exor[1],exor[2],exor[3],exor[4],exor[5],exor[6],exor[7]);
		decBlocks->push_back(exor);
	}
    //put blocks together
	unsigned char *result = (unsigned char *)malloc(*resultlen + bufsize % BLOCKSIZE);
	for(int i = 0; i < blockCount ; i++){
        temp = (unsigned char*)calloc(BLOCKSIZE, sizeof(unsigned char));
		temp = decBlocks->at(i);
        cout << "plain block " << i << endl;
		for(int j = 0; j < BLOCKSIZE; j++){
			result[i * BLOCKSIZE + j] = temp[j];
			printf("%c", temp[j]);
		}
		cout << endl;
	}
    free(blocks);
    free(decBlocks);
    cout << "DONE DECRYPTING!" << endl;
    
	return (void*)result;
}
