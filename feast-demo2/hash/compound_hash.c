// 以下是我的compound_hash.c的代码内容
#include "compound_hash.h"
#include "sha256.h"
#include "ripemd160.h"

void compound_hash(const uint8_t *input, size_t input_len, uint8_t output[COMPOUND_HASH_DIGEST_LENGTH]) {
    uint8_t sha256_digest[32];
    SHA256_CTX ctx;

    SHA256_Init(&ctx);
    SHA256_Update(&ctx, input, input_len);
    SHA256_Final(sha256_digest, &ctx);

    ripemd160(sha256_digest, 32, output);
}
