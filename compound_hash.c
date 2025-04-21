// compound_hash.c
#include "compound_hash.h"
#include "sha256.h"
#include "ripemd160.h"
#include <string.h>
#include <stdlib.h>

void compound_prf(
  const uint8_t *key, size_t key_len,
  const uint8_t iv[16],
  uint8_t out16[16]
) {
    // 1) SHA256(key || iv)
    SHA256_CTX s256;
    SHA256_Init(&s256);
    SHA256_Update(&s256, key, key_len);
    SHA256_Update(&s256, iv, 16);
    uint8_t sha_out[32];
    SHA256_Final(sha_out, &s256);

    // 2) RIPEMD160(sha_out)
    RIPEMD160_CTX r160;
    RIPEMD160_Init(&r160);
    RIPEMD160_Update(&r160, sha_out, 32);
    uint8_t ripemd_out[20];
    RIPEMD160_Final(ripemd_out, &r160);

    // 3) 截前 16 字节
    memcpy(out16, ripemd_out, 16);
}
