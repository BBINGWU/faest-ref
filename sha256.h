/* sha256.h */
#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint32_t state[8];
    uint64_t bitcount;
    uint8_t buffer[64];
} SHA256_CTX;

void SHA256_Init(SHA256_CTX *ctx);
void SHA256_Update(SHA256_CTX *ctx, const void *data, size_t len);
void SHA256_Final(uint8_t digest[32], SHA256_CTX *ctx);

#endif /* SHA256_H */