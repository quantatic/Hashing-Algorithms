#include "cartesian.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

char** generateCartesian(const char* chars, unsigned int count) {
	size_t charsLen = strlen(chars);

	size_t resultSize = 1;
	for(long unsigned int i = 0; i < count; i++) {
		resultSize *= charsLen;
	}

	char **result = malloc(sizeof(char *) * (resultSize + 1));
	result[count] = NULL; //add null to symbolize end of strings
	
	for(int i = 0; i < resultSize; i++) {
		result[i] = malloc(sizeof(char) * (count + 1));
		result[i][count] = '\0'; //add null byte
	}

	//uses equation (outIdx / idxModifier) % charsLen where idxModifier starts as out as output_length and is /= charsLen every iteration
	size_t idxModifier = resultSize;
	for(long unsigned int countIdx = 0; countIdx < count; countIdx++) {
		idxModifier /= charsLen;
		for(size_t resultIdx = 0; resultIdx < resultSize; resultIdx++) {
			char thisChar = chars[(resultIdx / idxModifier) % charsLen];
			result[resultIdx][countIdx] = thisChar;
		}
	}

	return result;
}

void freeCartesian(char** cartesian) {
	for(size_t i = 0; cartesian[i] != NULL; i++) {
		free(cartesian[i]);
	}

	free(cartesian);
}

void printCartesian(char** cartesian) {
	if(cartesian[0] == NULL) {
		return;
	}

	for(size_t i = 0; cartesian[i] != NULL; i++) {
		printf("%s\n", cartesian[i]);
	}

}

int main() {
	char** cartesian = generateCartesian("0123456789", 6);
	printCartesian(cartesian);
	freeCartesian(cartesian);
}
