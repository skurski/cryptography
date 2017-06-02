#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

#define GENKEY "genkey"
#define GENKEY_MODE 1
#define ENCRYPT_MODE 2
#define DECRYPT_MODE 3

#define ENCRYPT "encrypt"
#define DECRYPT "decrypt"

int genkey(const char * privKey, const char * pubKey);
void encrypt(const char * inFileName, const char * outFileName);
void decrypt(const char * inFileName, const char * outFileName);

/* 
 * Encryption / Decryption using RSA algorithm
 * Compilation: gcc rsa.c -o rsa -lcrypto
 * Execution format:
 * ./rsa genkey privateKeyName publicKeyName
 * ./rsa encrypt/decrypt inFileName outFileName
 */
 
int main(int argc, char * argv[]) {
    // initializing testing values - to delete
    argv[0] = "main";
    // argv[1] = "encrypt";
    // argv[1] = "decrypt";
    argv[1] = "genkey";
    argv[2] = "private";
    // argv[2] = "outfile.txt";
    argv[3] = "public";
    // argv[3] = "decrypt.txt";
    int k;
    for (k=0; k<2; k++) {
        printf("%s\n", argv[k]);
    }

    // end of testing initialization - to delete
    // program arguments validation
    if (argv[1] == NULL || argv[2] == NULL || argv[3] == NULL) {
        printf("Upss, something is wrong, check your parameters!\n");
        printf("Correct format for key generation: genkey privateKeyName publicKeyName\n");
        printf("Correct format for encrytion: encrypt/decrypt inFileName outFileName\n");
        return 1;
    }

    // choose correct mode for key generation/encryption/decryption
    int mode;
    if (strcmp(argv[1], GENKEY) == 0) {
        mode = GENKEY_MODE;
    } else if (strcmp(argv[1], ENCRYPT) == 0) {
        mode = ENCRYPT_MODE;
    } else if (strcmp(argv[1], DECRYPT) == 0) {
        mode = DECRYPT_MODE;
    }

    char * inFile = argv[3];
    char * outFile = argv[4];

    if (mode == GENKEY_MODE) {
        printf("Start generating private and public key pair ...\n");
        genkey(inFile, outFile);
        return 0;
    }
    if (mode == ENCRYPT_MODE) {
        printf("Start encrypting ...\n");
        encrypt(inFile, outFile);
        return 0;
    }
    if (mode == DECRYPT_MODE) {
        printf("Start decrypting ...\n");
        decrypt(inFile, outFile);
        return 0;
    }

    return 0;
}

int getKeyFromInput() {
 char * keySizeInput;
 printf("Enter key size: ");
 scanf("%s", keySizeInput);
 
 int keylen = 0;
 sscanf(keySizeInput, "%d", &keylen);
 return keylen;
}

RSA * createRSA(unsigned char * key,int public)
{
    RSA *rsa= NULL;
    BIO *keybio ;
    keybio = BIO_new_mem_buf(key, -1);
    if (keybio==NULL)
    {
        printf( "Failed to create key BIO");
        return 0;
    }
    if(public)
    {
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL);
    }
    else
    {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,NULL, NULL);
    }

    return rsa;
}

void encrypt(const char * inFileName, const char * outFileName) {

}

void decrypt(const char * inFileName, const char * outFileName) {

}

int genkey(const char * privKey, const char * pubKey) {
    int keyLength = getKeyFromInput();
    printf ("Choosen key length is: %i\n", keyLength);
    int result = 0;
    unsigned char buffer[1024];
    RSA * rsa = NULL;
    BIO * bio = NULL;
    BIGNUM * bigNum = NULL;
    FILE * privKeyFile;
    FILE * pubKeyFile;
 
    if ((privKeyFile = fopen(privKey, "wb")) == NULL) {
        printf("Open file error occurred");
        exit(1);
    }
    if ((pubKeyFile = fopen(pubKey, "wb")) == NULL) {
        printf("Open file error occurred");
        exit(1);
    }
 
    printf("Starting generating RSA key pair...");
    
    // RSA structure
    rsa = RSA_new();
    if (rsa == NULL) {
        printf("Error during generation of RSA structure!");
        exit(1);
    }
 
    // BIGNUM structure
    bigNum = BN_new();
    BN_set_word(bigNum, 17);
 
    // generate key pair
    if (RSA_generate_key_ex(rsa, keyLength, bigNum, NULL) == 0) {
        printf("Error during generation of RSA key pair!");
        RSA_free(rsa);
        exit(1);
    }
 
    printf("Key pair generated successfully!\n");
 
    // BIO for storing the key printed from RSA
    bio = BIO_new(BIO_s_mem());
    RSA_print(bio, rsa, 4);
 
    // Print keys to terminal
    memset(buffer, 0, 1024);
    while (BIO_read(bio, buffer, 1024) > 0) {
        printf("%s", buffer);
        memset(buffer, 0, 1024);
    }
    
    // Write keys to files
    printf("Writing keys to files...");
    result = PEM_write_RSA_PUBKEY(pubKeyFile, rsa);
    if (result == 0) {
        printf("Error occured when trying to store public key!");
    }
   // Be careful - writing private key without securing it with password!
   result = PEM_write_RSAPrivateKey(privKeyFile, rsa, EVP_aes_128_cbc(), NULL, NULL, NULL, NULL);
   if (result == 0) {
       printf("Error occured when trying to store private key!");
   }
   // free resources
   // BIO_free_all(pubKeyFile);
   // BIO_free_all(privKeyFile);
   RSA_free(rsa);
   // BN_free(bigNum);
   return ret;
}
