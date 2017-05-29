#include <stdio.h>
#include <stdlib.h>

#define BLOCK_SIZE 8 /* read 8 bytes at a time */

char * readFile (char *filename);
void readChunk (void);
void writeFile (char * string);
void readAsBinary (char * filename);

int main(void) {
    printf("hello world!\n");

    char * string = readFile("test.txt");

    readAsBinary("test.txt");

//    writeFile(string);

//    if (string) {
//        puts(string);
//        free(string);
//    }
//
//    readChunk();
}

char * readFile (char * filename) {
   char * buffer = NULL;
   int string_size, read_size;
   FILE * handler = fopen(filename, "r");

   if (handler) {
       fseek(handler, 0, SEEK_END);
       string_size = ftell(handler);
       rewind(handler);

       buffer = (char *) malloc(sizeof(char) * (string_size + 1) );
       read_size = fread(buffer, sizeof(char), string_size, handler);
       buffer[string_size] = '\0';

       if (string_size != read_size) {
           free(buffer);
           buffer = NULL;
       }
       fclose(handler);
    }
    return buffer;
}

void readChunk (void) {
    char buf[BLOCK_SIZE];
    FILE * inputFile;
    size_t nread;

    inputFile = fopen("test.txt", "r");
    if (inputFile) {
        while ((nread = fread(buf, 1, sizeof buf, inputFile)) > 0) {
            printf("\nNumber of bytes: ");
            printf("%lu", nread);
            printf("\n");
            fwrite(buf, 1, nread, stdout);
        }

        if (ferror(inputFile)) {
            /* deal with error */
        }

        fclose(inputFile);
    }
}

void writeFile (char * string) {
    printf("Write string to file...\n");
    printf("%s\n", string);

    FILE * fp = fopen("test-copy.txt", "w");
    if (fp == NULL) {
        printf("Error opening file!\n");
        exit(1);
    }

    fprintf(fp, "%s\n", string);
    fclose(fp);
}

void readAsBinary (char * filename) {
	FILE *file;
	char *buffer;
	unsigned long fileLen;

	//Open file
	file = fopen(filename, "rb");
	if (!file)
	{
		fprintf(stderr, "Unable to open file %s", filename);
		return;
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
		return;
	}

	//Read file contents into buffer
	fread(buffer, fileLen, 1, file);
	fclose(file);

    printf("Binary file: \n");
	printf("%s\n", buffer);

	free(buffer);
}