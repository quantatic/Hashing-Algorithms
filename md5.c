#include "md5.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define F(B,C,D) (((B) & (C)) | (~(B) & (D)))
#define G(B,C,D) (((B) & (D)) | ((C) & ~(D)))
#define H(B,C,D) ((B) ^ (C) ^ (D))
#define I(B,C,D) ((C) ^ ((B) | ~(D)))
#define LEFT_ROTATE(X,C) (((X) << (C)) | ((X) >> (32 - (C))))

#define A0_INIT 0x67452301
#define B0_INIT 0xefcdab89
#define C0_INIT 0x98badcfe
#define D0_INIT 0x10325476

uint32_t s[64] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
	          5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
	          4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
	          6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

uint32_t K[64] = {0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 
	          0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	          0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
	          0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	          0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
	          0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	          0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
	          0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	          0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
	          0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	          0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
	          0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	          0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
	          0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	          0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
	          0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};

uint32_t charsToUint32(const unsigned char addr[4]) {
	uint32_t result = 0;
	result |= (uint32_t)addr[0];
	result |= (uint32_t)(addr[1] << 8);
	result |= (uint32_t)(addr[2] << 16);
	result |= (uint32_t)(addr[3] << 24);

	return result;
}

void uint32ToChars(unsigned char addr[4], uint32_t in) {
	addr[0] = (unsigned char)(in);
	addr[1] = (unsigned char)(in >> 8);
	addr[2] = (unsigned char)(in >> 16);
	addr[3] = (unsigned char)(in >> 24);
}

void MD5Init(struct MD5Context *ctx) {
	ctx->a0 = A0_INIT;
	ctx->b0 = B0_INIT;
	ctx->c0 = C0_INIT;
	ctx->d0 = D0_INIT;
	ctx->bits = 0;
}

void MD5Transform(struct MD5Context *ctx, const unsigned char in[64]) {
	uint32_t M[16];
	for(size_t i = 0; i < 16; i++) { //setup M array with input block data
		size_t startIdx = i * 4;	
		M[i] = charsToUint32(in + startIdx);
	}

	uint32_t A = ctx->a0;
	uint32_t B = ctx->b0;
	uint32_t C = ctx->c0;
	uint32_t D = ctx->d0;
	for(uint32_t i = 0; i < 64; i++) {
		uint32_t F, g;
		if(0 <= i && i <= 15) {
			F = F(B, C, D);
			g = i;
		} else if(16 <= i && i <= 31) {
			F = G(B, C, D);
			g = ((5 * i) + 1) % 16;
		} else if(32 <= i && i <= 47) {
			F = H(B, C, D);
			g = ((3 * i) + 5) % 16;
		} else if(48 <= i && i <= 63) {
			F = I(B, C, D);
			g = (i * 7) % 16;
		}

		F = F + A + K[i] + M[g];
		A = D;
		D = C;
		C = B;
		B = B + LEFT_ROTATE(F, s[i]);
	}

	ctx->a0 += A; //update state variables
	ctx->b0 += B;
	ctx->c0 += C;
	ctx->d0 += D;
}


void MD5Update(struct MD5Context *ctx, const unsigned char *buf, size_t length) {
	ctx->bits += (length * 8);	
	unsigned char block[64];

	while(length >= 64) {
		memcpy(block, buf, 64);
		MD5Transform(ctx, block);

		length -= 64;
		buf += 64;
	}

	memcpy(block, buf, length); //copy remaining data

	unsigned char *p = block + length;
	*p++ = 0x80; //guaranteed to have at least one free byte
	
	size_t paddingBytes = 64 - length - 1; //calculate bytes of padding required

	if(paddingBytes < 8) { //if we're over 448 bits, add some zeroes, update digest, then ready padded zeroes for final update
		memset(p, 0, paddingBytes);
		MD5Transform(ctx, block);

		memset(block, 0, 56);
	} else {
		memset(p, 0, paddingBytes - 8); //fill with zeroes for the amount of padding required, leaving room for last 8 bytes
	}

	uint32ToChars(block + 56, (uint32_t)(ctx->bits));
	uint32ToChars(block + 60, (uint32_t)((ctx->bits) >> 32));

	MD5Transform(ctx, block);
}

void MD5Digest(unsigned char digest[16], struct MD5Context *ctx) {
	uint32ToChars(digest, ctx->a0);
	uint32ToChars(digest + 4, ctx->b0);
	uint32ToChars(digest + 8, ctx->c0);
	uint32ToChars(digest + 12, ctx->d0);
}

void MD5Hexdigest(char hexdigest[32], struct MD5Context *ctx) {
	unsigned char digest[16];
	MD5Digest(digest, ctx);

	char currHex[3]; //2 chars plus null byte
	for(size_t i = 0; i < 16; i++) {
		snprintf(currHex, 3, "%02x", digest[i]); //read into temporary array
		hexdigest[i * 2] = currHex[0]; //copy 2 chars from temporary variable into the result
		hexdigest[(i * 2) + 1] = currHex[1];
	}
}

/**int main() {
	char* (a[4]) = {"asdf", "zxcv", "pouu", "qwer"};
	struct MD5Context ctx;
	char digest[32];
	for(int i = 0; i < 4; i++) {
		MD5Init(&ctx);
		MD5Update(&ctx, (unsigned char*)a[i], 4);
		MD5Hexdigest(digest, &ctx);
		printf("%.32s\n", digest);
	}
}*/
