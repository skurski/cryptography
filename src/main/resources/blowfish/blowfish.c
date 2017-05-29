#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/blowfish.h>

#define IVARG   1
#define KEYARG  2
#define SRCDATA 3
#define ARGS    4

#define TOKENS "\r \n"


char * readFile (char * filename);
char * encrypt (char * source);
void decrypt (char * source);

int main(int argc, char **argv) {
    char * source = readFile("test.txt");
    char * cipher = encrypt(source);
    decrypt(cipher);
}

char * encrypt (char * source) {
    BF_KEY key;
    char  inputz[strlen(source)];
//    char outputz[1024*1024];

    char * outputz = malloc(strlen(source));

    char ivec[8];
    char block[8];
    int i;
    int offset = 0;

    char * IV = "MY*IV000";
    char * mykey = "qazwsxedcrfvtgbyhnujmiklop";

    strncpy(ivec, IV, 8);

    for(i=0; i<strlen(source); i++) {
        inputz[i] = source[i];
    }

    BF_set_key(&key, strlen(mykey), mykey);
    while(1) {
        for(i=0; i<8; i++)
            block[i] = 0;

        strncpy(block, inputz+offset, 8);

        BF_cbc_encrypt(inputz+offset, outputz, 8, &key, ivec, BF_ENCRYPT);

        for(i=0; i<strlen(outputz); i++)
            printf("%02x ", (unsigned char) outputz[i]);

        if( strlen(inputz+offset)>8 ) {
            offset += 8;

        } else {
            break;
        }
    }

    printf("\n");

    decrypt(outputz);

    return outputz;
}

void decrypt (char * source) {
    char inputz[1024*1024];
    char outputz[1024*1024];
    char ivec[8];
    char byte;
    char *tok;
    int pos = 0;
    char block[8];
    int offset;


    BF_KEY key;

    char * IV = "MY*IV000";
    char * mykey = "qazwsxedcrfvtgbyhnujmiklop";

    strncpy(ivec, IV, 8);

//    tok = strtok(source, TOKENS);
//    while( tok ) {
//        if( sscanf(tok, "%c", &byte) ) {
//            inputz[pos] = byte;
//            inputz[++pos] = 0;
//        }
//
//        tok = strtok(NULL, TOKENS);
//    }
//
//    BF_set_key(&key, strlen(mykey), mykey);
//    BF_cbc_encrypt(inputz, outputz, pos, &key, ivec, BF_DECRYPT);

    int i;
    for(i=0; i<strlen(source); i++) {
        inputz[i] = source[i];
    }

    BF_set_key(&key, strlen(mykey), mykey);
    while(1) {
        for(i=0; i<8; i++)
            block[i] = 0;

        strncpy(block, inputz+offset, 8);

        BF_cbc_encrypt(inputz, outputz, pos, &key, ivec, BF_DECRYPT);

        if( strlen(inputz+offset)>8 ) {
            offset += 8;

        } else {
            break;
        }
    }





    printf("%s\n", outputz);
}

char * readFile (char * filename) {
	FILE *file;
	char *buffer;
	unsigned long fileLen;

	//Open file
	file = fopen(filename, "rb");
	if (!file)
	{
		fprintf(stderr, "Unable to open file %s", filename);
		exit(1);
	}

	//Get file length
	fseek(file, 0, SEEK_END);
	fileLen=ftell(file);
	fseek(file, 0, SEEK_SET);

	//Allocate memory
	buffer=(char *)malloc(fileLen+1);
	if (!buffer)
	{
		fprintf(stderr, "Memory error!");
        fclose(file);
		exit(1);
	}

	//Read file contents into buffer
	fread(buffer, fileLen, 1, file);
	fclose(file);

    return buffer;
}