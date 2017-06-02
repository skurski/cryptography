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

int genkey(int keyLength, const char * privKey, const char * pubKey);
void encrypt(const char * keyFile, const char * inFileName, const char * outFileName);
void decrypt(const char * keyFile, const char * inFileName, const char * outFileName);
RSA * createRSA(unsigned char * key, int public);

/* 
 * Encryption / Decryption using RSA algorithm
 * Compilation: gcc rsa.c -o rsa -lcrypto
 * Execution format:
 * ./rsa genkey 2048 privateKeyName publicKeyName
 * ./rsa encrypt/decrypt keyFile inFileName outFileName
 */
 
int main(int argc, char * argv[]) {
    // program arguments validation
    if (argv[1] == NULL || argv[2] == NULL || argv[3] == NULL || argv[4] == NULL) {
        printf("Upss, something is wrong, check your parameters!\n");
        printf("Correct format for key generation: genkey privateKeyName publicKeyName\n");
        printf("Correct format for encrytion: encrypt/decrypt inFileName outFileName\n");
        return 1;
    }

    // choose correct mode for [key generation/encryption/decryption]
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
		int keyLength = 0;
		sscanf(argv[2], "%d", &keyLength);
        genkey(keyLength, inFile, outFile);
        return 0;
    }
	
	char * keyFile = argv[2];
    if (mode == ENCRYPT_MODE) {
        printf("Start encrypting ...\n");
        encrypt(keyFile, inFile, outFile);
        return 0;
    }
    if (mode == DECRYPT_MODE) {
        printf("Start decrypting ...\n");
        decrypt(keyFile, inFile, outFile);
        return 0;
    }

    return 1;
}

RSA * createRSA(char * keyFile,int public) {
	if ((fp = fopen(keyFile, "rb")) == NULL) {
        printf("Open key file error occurred!");
        exit(1);
    }

    RSA * rsa = RSA_new();

    if (public) {
		printf("Reading public key...");
        rsa = PEM_read_RSA_PUBKEY(fp, &rsa, NULL, NULL);
	} else {
		printf("Reading private key...");
        rsa = PEM_read_RSAPrivateKey(fp, &rsa, 0, NULL);
	}
	
    if (rsa == NULL) {
        printf("Error while reading key!");
		exit(1);
    }

    return rsa;
}

void encrypt(const char * keyFile, const char * inFileName, const char * outFileName) {
	RSA * rsa = createRSA(keyFile, 1);
    FILE * inFile;
    FILE * outFile;
	unsigned char * inBuffer = NULL;
    unsigned char * outBuffer = NULL;
	int padding = RSA_PKCS1_PADDING;
	int writesize = RSA_size(rsa);

	
    if ((inFile = fopen(inFileName, "r")) == NULL) {
        printf("Open file error occurred");
        exit(1);
    }
    if ((outFile = fopen(outFileName, "w")) == NULL) {
        printf("Open file error occurred");
        exit(1);
    }
}

void decrypt(const char * keyFile, const char * inFileName, const char * outFileName) {
	RSA * rsa = createRSA(keyFile, 1);
}

int genkey(int keyLength, const char * privKey, const char * pubKey) {
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
   result = PEM_write_RSAPrivateKey(privKeyFile, rsa, EVP_aes_128_cbc(), NULL, 0, 0, NULL);
   if (result == 0) {
       printf("Error occured when trying to store private key!");
   }
   // free resources
   // BIO_free_all(pubKeyFile);
   // BIO_free_all(privKeyFile);
   RSA_free(rsa);
   // BN_free(bigNum);
   
   close(privKeyFile);
   close(pubKeyFile);
   
   return ret;
}

