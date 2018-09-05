#include "md5_file.h"
#include "md5.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LINE_SIZE 1000
void hashFileLines(char* fileNameIn, char* fileNameOut) {
	FILE *fp = fopen(fileNameIn, "r");

	char buffer[MAX_LINE_SIZE];
	struct MD5Context ctx;
	char digest[32];

	while(fgets(buffer, MAX_LINE_SIZE, fp) != NULL) {
		char* newLinePos;
		if((newLinePos = strchr(buffer, '\n')) != NULL) {
			*newLinePos = '\0';
		}

		MD5Init(&ctx);
		MD5Update(&ctx, (unsigned char*)buffer, strlen(buffer));
		MD5Hexdigest(digest, &ctx);

		printf("%.32s\n", digest);
	}
}

int main() {
	hashFileLines("input.txt", NULL);
	return EXIT_SUCCESS;
}
