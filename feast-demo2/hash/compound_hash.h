// 以下是我的compound_hash.h的代码内容
#ifndef COMPOUND_HASH_H
#define COMPOUND_HASH_H

#include <stddef.h>
#include <stdint.h>

#define COMPOUND_HASH_DIGEST_LENGTH 20  // Output: RIPEMD160(SHA256(x))

#ifdef __cplusplus
extern "C" {
#endif

void compound_hash(const uint8_t *input, size_t input_len, uint8_t output[COMPOUND_HASH_DIGEST_LENGTH]);

#ifdef __cplusplus
}
#endif

#endif