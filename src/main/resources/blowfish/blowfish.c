#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <openssl/blowfish.h>

// block size for blowfish is 64 bits (8 bytes)
#define BLOCK_SIZE 8

#define ENCRYPT_ECB_MODE 1
#define ENCRYPT_CBC_MODE 2
#define DECRYPT_ECB_MODE 3
#define DECRYPT_CBC_MODE 4

#define ENCRYPT "encrypt"
#define DECRYPT "decrypt"
#define ECB "ecb"
#define CBC "cbc"

#define MY_KEY "1dqbfj4hgnr66534kjgrfs"
#define IV "initvect"

void encryptECB(const char * inFileName, const char * outFileName);
void decryptECB(const char * inFileName, const char * outFileName);
char * removePadding(char * block);
void encryptCBC(const char * inFileName, const char * outFileName);
void decryptCBC(const char * inFileName, const char * outFileName);
void printHex(int readBytes, char * buffer);

/*
 * Encryption / Decryption using Blowfish in ECB/CBC mode
 * Padding : PKCS7
 * Compilation: gcc blowfish.c -o blowfish -lcrypto
 * Execution format:
 * ./blowfish encrypt ecb input encrypted
 * ./blowfish encrypt cbc input encrypted
 * ./blowfish decrypt ecb encrypted decrypted
 * ./blowfish decrypt cbc encrypted decrypted
 */
int main(int argc, char * argv[]) {
    // program arguments validation
    if (argv[1] == NULL || argv[2] == NULL || argv[3] == NULL || argv[4] == NULL) {
        printf("Upss, something is wrong, check your parameters!\n");
        printf("Correct format: encrypt/decrypt ecb/cbc inFileName outFileName\n");
        return 1;
    }

    // choose correct mode for encryption/decryption
    int mode;
    if (strcmp(argv[1], ENCRYPT) == 0) {
        if (strcmp(argv[2], ECB) == 0) {
            mode = ENCRYPT_ECB_MODE;
        } else  if (strcmp(argv[2], CBC) == 0) {
            mode = ENCRYPT_CBC_MODE;
        }
    } else if (strcmp(argv[1], DECRYPT) == 0) {
        if (strcmp(argv[2], ECB) == 0) {
            mode = DECRYPT_ECB_MODE;
        } else if (strcmp(argv[2], CBC) == 0) {
            mode = DECRYPT_CBC_MODE;
        }
    }

    char * inFile = argv[3];
    char * outFile = argv[4];

    // fire encryption/decryption in choosen mode
    if (mode == ENCRYPT_ECB_MODE) {
        printf("Start encrypting in ECB mode...\n");
        encryptECB(inFile, outFile);
        return 0;
    }

    if (mode == ENCRYPT_CBC_MODE) {
        printf("Start encrypting in CBC mode...\n");
        encryptCBC(inFile, outFile);
        return 0;
    }

    if (mode == DECRYPT_ECB_MODE) {
        printf("Start decrypting in ECB mode...\n");
        decryptECB(inFile, outFile);
        return 0;
    }

    if (mode == DECRYPT_CBC_MODE) {
        printf("Start decrypting in CBC mode...\n");
        decryptCBC(inFile, outFile);
        return 0;
    }

    return 0;
}

void encryptECB(const char * inFileName, const char * outFileName) {
    BF_KEY key;
    FILE * inFile;
    FILE * outFile;
    unsigned char inBuffer[BLOCK_SIZE];
    unsigned char outBuffer[BLOCK_SIZE];
    int readBytes;

    if ((inFile = fopen(inFileName, "r")) == NULL) {
        printf("Open file error occurred");
        exit(1);
    }

    if ((outFile = fopen(outFileName, "w")) == NULL) {
        printf("Open file error occurred");
        exit(1);
    }

    // set key before encryption
    BF_set_key(&key, strlen(MY_KEY), MY_KEY);

    while (1) {
        // reset buffer
        memset(inBuffer, 0, BLOCK_SIZE);

        // read 8 bytes of data in each loop
        if ((readBytes = fread(inBuffer, 1, BLOCK_SIZE, inFile)) == -1) {
            printf("Read error occurred");
        }

        // end of file
        if (readBytes == 0) {
            break;
        }

        // apply padding if needed
        if (readBytes < BLOCK_SIZE) {
            printf("Number of bytes read (last block): %i", readBytes);
            unsigned char padding = BLOCK_SIZE - readBytes;
            printf(" -> padding aplied: %i\n", padding);
            int j = readBytes;
            for (j; j < BLOCK_SIZE; j++) {
                inBuffer[j] = padding;
            }
            readBytes = readBytes + padding;
        }

        // do encryption
        BF_ecb_encrypt(inBuffer, outBuffer, &key, BF_ENCRYPT);

        printHex(readBytes, outBuffer);

        // save encrypted part of file
        fwrite(outBuffer, 1, BLOCK_SIZE, outFile);
    }

    fclose(inFile);
    fclose(outFile);
}

void decryptECB(const char * inFileName, const char * outFileName) {
    BF_KEY key;
    FILE * inFile;
    FILE * outFile;
    unsigned char inBuffer[BLOCK_SIZE];
    unsigned char outBuffer[BLOCK_SIZE];
    int readBytes;
    int notFirstIteration = 0;

    if ((inFile = fopen(inFileName, "r")) == NULL) {
        printf("Open file error occurred");
        exit(1);
    }

    if ((outFile = fopen(outFileName, "w")) == NULL) {
        printf("Open file error occurred");
        exit(1);
    }

    // set key before encryption
    BF_set_key(&key, strlen(MY_KEY), MY_KEY);

    while (1) {
        // reset buffer
        memset(inBuffer, 0, BLOCK_SIZE);

        // read 8 bytes of data in each loop
        if ((readBytes = fread(inBuffer, 1, BLOCK_SIZE, inFile)) == -1) {
            printf("Read error occurred");
        }

        // end of file
        if (readBytes == 0) {
            // save decrypted block from previous iteration
            // if the previous iteration was last remove padding before saving
            char * originalBlock = removePadding(outBuffer);
            fwrite(originalBlock, 1, strlen(originalBlock), outFile);
            break;
        }

        if (notFirstIteration) {
            // save decrypted block from previous iteration         
            fwrite(outBuffer, 1, BLOCK_SIZE, outFile);
        }

        // do decryption
        BF_ecb_encrypt(inBuffer, outBuffer, &key, BF_DECRYPT);

        printHex(readBytes, outBuffer);

        notFirstIteration =1; // set the flag
    }

    fclose(inFile);
    fclose(outFile);
}

char * removePadding(char * buffer) {
    // check if last char represent padding
    if (!(buffer[BLOCK_SIZE-1] >= 1 && buffer[BLOCK_SIZE-1] <= 8)) {
        printf("No padding\n");
        return (char *) buffer;
    }
    
    printf("Padding value of last block: %02x\n" , buffer[BLOCK_SIZE-1]);
    char * block;
    int size = BLOCK_SIZE - buffer[BLOCK_SIZE-1];

    // last block = blocksize - padding value
    block = malloc(size * sizeof(char));
    printf("Size of block after padding removal: %i\n" , size);

    printf("Hex representation of last block: ");
    int i;
    for (i = 0; i < size; i++) {
        block[i] = buffer[i];
        printf("%02x ", (unsigned char) block[i]);
    }
    printf("\n");
    
    return block;
}

void encryptCBC(const char * inFileName, const char * outFileName) {
    BF_KEY key;
    FILE * inFile;
    FILE * outFile;
    unsigned char inBuffer[BLOCK_SIZE];
    unsigned char outBuffer[BLOCK_SIZE];
    int readBytes;
    char ivec[BLOCK_SIZE];
    
    if ((inFile = fopen(inFileName, "r")) == NULL) {
        printf("Open file error occurred");
        exit(1);
    }
    
    if ((outFile = fopen(outFileName, "w")) == NULL) {
        printf("Open file error occurred");
        exit(1);
    }
    
    // init initialization vector
    strncpy(ivec, IV, 8);
    
    // set key before encryption
    BF_set_key(&key, strlen(MY_KEY), MY_KEY);
    
    while (1) {
        // reset buffer
        memset(inBuffer, 0, BLOCK_SIZE);
        
        // read 8 bytes of data in each loop
        if ((readBytes = fread(inBuffer, 1, BLOCK_SIZE, inFile)) == -1) {
            printf("Read error occurred");
        }
        
        // end of file
        if (readBytes == 0) {
            break;
        }
        
        // apply padding if needed
        if (readBytes < BLOCK_SIZE) {
            printf("Number of bytes read (last block): %i", readBytes);
            unsigned char padding = BLOCK_SIZE - readBytes;
            printf(" -> padding aplied: %i\n", padding);
            int j = readBytes;
            for (j; j < BLOCK_SIZE; j++) {
                inBuffer[j] = padding;
            }
            readBytes = readBytes + padding;
        }

        // do encryption
        BF_cbc_encrypt(inBuffer, outBuffer, BLOCK_SIZE, &key, ivec, BF_ENCRYPT);
        
        printHex(readBytes, outBuffer);
        
        // save encrypted part of file
        fwrite(outBuffer, 1, BLOCK_SIZE, outFile);
    }
    
    fclose(inFile);
    fclose(outFile);
}

void decryptCBC(const char * inFileName, const char * outFileName) {
    BF_KEY key;
    FILE * inFile;
    FILE * outFile;
    unsigned char inBuffer[BLOCK_SIZE];
    unsigned char outBuffer[BLOCK_SIZE];
    int readBytes;
    int notFirstIteration = 0;
    char ivec[BLOCK_SIZE];
    
    if ((inFile = fopen(inFileName, "r")) == NULL) {
        printf("Open file error occurred");
        exit(1);
    }
    
    if ((outFile = fopen(outFileName, "w")) == NULL) {
        printf("Open file error occurred");
        exit(1);
    }
    
    // init initialization vector
    strncpy(ivec, IV, 8);
    
    // set key before encryption
    BF_set_key(&key, strlen(MY_KEY), MY_KEY);
    
    while (1) {
        // reset buffer
        memset(inBuffer, 0, BLOCK_SIZE);
        
        // read 8 bytes of data in each loop
        if ((readBytes = fread(inBuffer, 1, BLOCK_SIZE, inFile)) == -1) {
            printf("Read error occurred");
        }
        
        // end of file
        if (readBytes == 0) {
            // save decrypted block from previous iteration
            // if the previous iteration was last remove padding before saving
            char * originalBlock = removePadding(outBuffer);
            fwrite(originalBlock, 1, strlen(originalBlock), outFile);
            break;
        }
        
        if (notFirstIteration) {
            // save decrypted block from previous iteration
            fwrite(outBuffer, 1, BLOCK_SIZE, outFile);
        }
        
        // do decryption
        BF_cbc_encrypt(inBuffer, outBuffer, BLOCK_SIZE, &key, ivec, BF_DECRYPT);

        printHex(readBytes, outBuffer);

        notFirstIteration =1; // set the flag
    }
    
    fclose(inFile);
    fclose(outFile);
}

void printHex(int readBytes, char * buffer) {
    int print = 0; // print hex representation of read bytes
    if (print) {
        printf("Number of bytes read: %i\n", readBytes);
        printf("Hex representation: ");
        int x;
        for (x=0; x<readBytes; x++) {
            printf("%02x ", (unsigned char) buffer[x]);
        }
        printf("\n");
    }
}
