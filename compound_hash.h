// compound_hash.h
#ifndef COMPOUND_HASH_H
#define COMPOUND_HASH_H
#include <stddef.h>
#include <stdint.h>
/// 复合 PRF：输出 16 字节
void compound_prf(
  const uint8_t *key, size_t key_len,
  const uint8_t iv[16],
  uint8_t out16[16]
);
#endif
