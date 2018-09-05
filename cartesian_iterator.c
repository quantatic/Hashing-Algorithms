#include "cartesian_iterator.h"
#include "md5.h"
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

void initCartesianIterator(struct CartesianIterator *itr, const char *space, size_t numFromSpace) {
	size_t spaceSize = strlen(space);

	itr->space = malloc((spaceSize + 1) * sizeof(char));
	strcpy(itr->space, space);

	itr->numFromSpace = numFromSpace;

	size_t totalToGet = 1;
	for(size_t i = 0; i < numFromSpace; i++) {
		totalToGet *= spaceSize;
	}
	itr->totalToGet = totalToGet;

	itr->totalGotten = 0;
	itr->last = calloc(numFromSpace + 1, sizeof(char)); //haven't gotten anything yet
}

void freeCartesianIterator(struct CartesianIterator* itr) {
	free(itr->space);
	free(itr->last);
}

char* cartesianIteratorNext(struct CartesianIterator *itr) {
	if(itr->totalGotten == itr->totalToGet) {
		return NULL;
	}

	size_t idxModifier = itr->totalToGet;
	size_t spaceSize = strlen(itr->space);
	for(size_t countIdx = 0; countIdx < itr->numFromSpace; countIdx++) {
		idxModifier /= spaceSize;
		(itr->last)[countIdx] = (itr->space)[(itr->totalGotten / idxModifier) % spaceSize];
	}
	(itr->totalGotten)++;
	return itr->last;
}

int main(int argc, char** argv) {
	struct CartesianIterator itr;
	initCartesianIterator(&itr, "0123456789", 6);
	struct MD5Context ctx;
	char digest[32];
	while(cartesianIteratorNext(&itr) != NULL) {
		MD5Init(&ctx);
		MD5Update(&ctx, itr.last, strlen(itr.last));
		MD5Hexdigest(digest, &ctx);
		//printf("%.32s\n", digest);
		printf("%s\n", itr.last);
	}	
}
