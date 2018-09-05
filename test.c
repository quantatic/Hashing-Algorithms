#include "cartesian.h"
#include "md5.h"

#include <string.h>
#include <stdio.h>

#define TO_CRACK "5d41402abc4b2a76b9719d911017c592"
#define SEARCH_SPACE "abcdefghijklmnopqrstuvwxyz"
#define ORIGINAL_LENGTH 6

int main(int argc, char** argv) {
	char** cartesian = generateCartesian(SEARCH_SPACE, ORIGINAL_LENGTH);
	struct MD5Context ctx;
	unsigned char hexdigest[32];

	for(size_t i = 0; cartesian[i] != NULL; i++) {
		MD5Init(&ctx);
		MD5Update(&ctx, (unsigned char*)cartesian[i], strlen(cartesian[i]));
		MD5Hexdigest(hexdigest, &ctx);
		if(!(strncmp(TO_CRACK, hexdigest, 32))) {
			printf("Found it! Un-hashed string: %s\n", cartesian[i]);
		}
	}
}
