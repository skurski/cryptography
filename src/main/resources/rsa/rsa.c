#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/bio.h>

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

int genkey(const char * privKey, const char * pubKey) {
    int bits = getKeyFromInput();
    printf ("Choosen key length is: %i\n", bits);
    int ret = 0;
    RSA * r = NULL;
    BIGNUM * bne = NULL;
    BIO * bp_public = NULL;
    BIO * bp_private = NULL;
    unsigned long e = RSA_F4;

    // 1. generate rsa key
    bne = BN_new();
    ret = BN_set_word(bne,e);
    ret = 1;

    r = RSA_new();
    ret = RSA_generate_key_ex(r, bits, bne, NULL);

    // 2. save public key
    bp_public = BIO_new_file("public.pem", "w+");
    ret = PEM_write_bio_RSAPublicKey(bp_public, r);

    // 3. save private key
    bp_private = BIO_new_file("private.pem", "w+");
    ret = PEM_write_bio_RSAPrivateKey(bp_private, r, NULL, NULL, 0, NULL, NULL);

    // 4. free 
    BIO_free_all(bp_public);
    BIO_free_all(bp_private);
    RSA_free(r);
    BN_free(bne);

    return ret;
}

void encrypt(const char * inFileName, const char * outFileName) {

}

void decrypt(const char * inFileName, const char * outFileName) {

}
