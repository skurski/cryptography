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
#define ENCRYPT "encrypt"
#define DECRYPT "decrypt"

#define GENKEY_MODE 1
#define ENCRYPT_MODE 2
#define DECRYPT_MODE 3

int genkey(int keyLength, const char * privKey, const char * pubKey);
void encrypt(const char * keyFile, const char * inFileName, const char * outFileName);
void decrypt(const char * keyFile, const char * inFileName, const char * outFileName);
RSA * createRSA(const char * keyFile,int public);

/*
 * Key pair generation / Encryption / Decryption using RSA algorithm
 * Compilation: gcc rsa.c -o rsa -lcrypto
 * Execution format:
 * ./rsa genkey 2048 private.pem public.pem
 * ./rsa encrypt public.pem input encrypted
 * ./rsa decrypt private.pem encrypted decrypted
 *
 * Random file generation: dd if=/dev/zero of=file128M  bs=128M  count=1
 */

int main(int argc, char * argv[]) {
    // program arguments validation
    if (argv[1] == NULL || argv[2] == NULL || argv[3] == NULL || argv[4] == NULL) {
        printf("Upss, something is wrong, check your parameters!\n");
        printf("Correct format for key generation: genkey 2048 private.pem public.pem\n");
        printf("Correct format for encryption: encrypt public.pem input encrypted\n");
        printf("Correct format for decryption: decrypt private.pem encrypted decrypted\n");
        return 1;
    }

    // Added for automatic password callback in PEM_read_RSAPrivateKey
    OpenSSL_add_all_algorithms();

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

RSA * createRSA(const char * keyFile,int public) {
    FILE * fp;
    if ((fp = fopen(keyFile, "rb")) == NULL) {
        printf("Open key file error occurred!\n");
        exit(1);
    }

    RSA * rsa = RSA_new();

    if (public) {
        printf("Reading public key...\n");
        rsa = PEM_read_RSA_PUBKEY(fp, &rsa, NULL, NULL);
    } else {
        printf("Reading private key...\n");
        rsa = PEM_read_RSAPrivateKey(fp, &rsa, 0, NULL);
    }

    if (rsa == NULL) {
        printf("Error while reading key!\n");
        exit(1);
    }

    return rsa;
}

void encrypt(const char * keyFile, const char * inFileName, const char * outFileName) {
    RSA * rsa = createRSA(keyFile, 1);
    clock_t begin = clock();

    FILE * inFile;
    FILE * outFile;
    unsigned char * inBuffer = NULL;
    unsigned char * outBuffer = NULL;
    int padding = RSA_PKCS1_PADDING;
    int writeSize = RSA_size(rsa);
    // block read size must be less than RSA_size(rsa) - 11 for the PKCS #1 v1.5 padding
    int readSize = writeSize - 11;
    int readBytes = 0;
    int encSize = 0;

    inBuffer  = malloc(readSize * sizeof(char));
    outBuffer = malloc(writeSize * sizeof(char));

    if ((inFile = fopen(inFileName, "r")) == NULL) {
        printf("Open file error occurred\n");
        exit(1);
    }
    if ((outFile = fopen(outFileName, "w")) == NULL) {
        printf("Open file error occurred\n");
        exit(1);
    }

    while (1) {
        memset(inBuffer, 0, readSize);
        if ((readBytes = fread(inBuffer, 1, readSize, inFile)) == -1) {
            printf("Read error occurred\n");
            break;
        }

        memset(outBuffer, 0, writeSize);
        encSize = RSA_public_encrypt(readBytes, inBuffer, outBuffer, rsa, padding);
        if (encSize < 0) {
            printf("Error while encrypting data block\n");
            break;
        }

        if (fwrite(outBuffer, 1, encSize, outFile) == -1) {
            printf("Error while writing encrypted data block\n");
            break;
        }

        if (readBytes < readSize)
            break; // exit
    }

    printf("DONE\n");

    free(inBuffer);
    free(outBuffer);

    clock_t end = clock();
    printf("Elapsed: %f seconds\n", (double)(end - begin) / CLOCKS_PER_SEC);
}

void decrypt(const char * keyFile, const char * inFileName, const char * outFileName) {
    RSA * rsa = createRSA(keyFile, 0);
    clock_t begin = clock();

    FILE * inFile;
    FILE * outFile;
    unsigned char * inBuffer = NULL;
    unsigned char * outBuffer = NULL;
    int padding = RSA_PKCS1_PADDING;
    int blockSize = RSA_size(rsa);
    int readBytes = 0;
    int decSize = 0;

    inBuffer  = malloc(blockSize * sizeof(char));
    outBuffer = malloc(blockSize * sizeof(char));

    if ((inFile = fopen(inFileName, "r")) == NULL) {
        printf("Open file error occurred\n");
        exit(1);
    }
    if ((outFile = fopen(outFileName, "w")) == NULL) {
        printf("Open file error occurred\n");
        exit(1);
    }

    while (1) {
        memset(inBuffer, 0, blockSize);
        if ((readBytes = fread(inBuffer, 1, blockSize, inFile)) == -1) {
            printf("Read error occurred\n");
            break;
        }

        if (!readBytes)
            break;

        memset(outBuffer, 0, blockSize);
        decSize = RSA_private_decrypt(blockSize, inBuffer, outBuffer, rsa, padding);
        if (decSize < 0) {
            printf("Error while decrypting data block\n");
            break;
        }

        if (fwrite(outBuffer, 1, decSize, outFile) == -1) {
            printf("Error while writing decrypted data block\n");
            break;
        }
    }

    printf("DONE\n");

    free(inBuffer);
    free(outBuffer);

    clock_t end = clock();
    printf("Elapsed: %f seconds\n", (double)(end - begin) / CLOCKS_PER_SEC);
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
        printf("Open file error occurred\n");
        exit(1);
    }
    if ((pubKeyFile = fopen(pubKey, "wb")) == NULL) {
        printf("Open file error occurred\n");
        exit(1);
    }

    printf("Starting generating RSA key pair...\n");

    // RSA structure
    rsa = RSA_new();
    if (rsa == NULL) {
        printf("Error during generation of RSA structure!\n");
        exit(1);
    }

    // BIGNUM structure
    bigNum = BN_new();
    BN_set_word(bigNum, 17);

    // generate key pair
    if (RSA_generate_key_ex(rsa, keyLength, bigNum, NULL) == 0) {
        printf("Error during generation of RSA key pair!\n");
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
    printf("Writing keys to files...\n");
    result = PEM_write_RSA_PUBKEY(pubKeyFile, rsa);
    if (result == 0) {
        printf("Error occured when trying to store public key!\n");
    }
    // Writing private key - prompt for password
    result = PEM_write_RSAPrivateKey(privKeyFile, rsa, EVP_aes_128_cbc(), NULL, 0, 0, NULL);
    if (result == 0) {
       printf("Error occured when trying to store private key!\n");
    }

    // free resources
    // BIO_free_all(pubKeyFile);
    // BIO_free_all(privKeyFile);
    RSA_free(rsa);
    BN_free(bigNum);

    fclose(privKeyFile);
    fclose(pubKeyFile);

    return result;
}

