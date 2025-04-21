#ifndef RIPEMD160_H
#define RIPEMD160_H

#include <stdint.h>
#include <stddef.h>

#define RIPEMD160_DIGEST_LENGTH 20  // 160-bit digest size in bytes

/**
 * Compute RIPEMD-160 hash of the input message.
 * @param message Pointer to input data.
 * @param length  Length of input data in bytes.
 * @param digest  Output buffer (20 bytes) to receive the 160-bit hash.
 */
void ripemd160(const uint8_t *message, size_t length, uint8_t digest[RIPEMD160_DIGEST_LENGTH]);

#endif /* RIPEMD160_H */
