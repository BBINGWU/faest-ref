
#include "../hash/sha256.h"
#include "../hash/ripemd160.h"
#include <string.h>
#include <assert.h>
#include <stdbool.h>  // 为 C 语言提供 bool 类型

#define get_bit(value, index) (((value) >> (index)) & 1)
#define set_bit(value, index) ((value) << (index))

typedef uint8_t bf8_t;

// 假设这些函数已经定义好
bf8_t bf8_square(bf8_t x) {
    // 这个函数计算 x^2 （模某个有限域）
    return (x << 1) ^ (x >> 7);  // 这是GF(2^8)域下的平方操作，可能需要根据具体的域来修改
}

bf8_t bf8_mul(bf8_t x, bf8_t y) {
    // 这个函数计算 x * y （模某个有限域）
    bf8_t result = 0;
    for (int i = 7; i >= 0; --i) {
        result <<= 1;
        if (result & 0x100) result ^= 0x1b;  // 模乘法的结果需要和模多项式相乘
        if (y & (1 << i)) result ^= x;
    }
    return result;
}

bf8_t bf_exp_238(bf8_t x) {
    // 238 == 0b11101110
    bf8_t y = bf8_square(x); // x^2
    x = bf8_square(y); // x^4
    y = bf8_mul(x, y);  // x^6
    x = bf8_square(x); // x^8
    y = bf8_mul(x, y);  // x^14
    x = bf8_square(x); // x^16
    x = bf8_square(x); // x^32
    y = bf8_mul(x, y);  // x^46
    x = bf8_square(x); // x^64
    y = bf8_mul(x, y);  // x^110
    x = bf8_square(x); // x^128
    return bf8_mul(x, y);  // x^238 = x^128 * x^64 * x^32 * x^16 * x^8 * x^4 * x^2
}


void bf8_store(uint8_t* dst, uint8_t src) {
    *dst = src;
}

// SHA-256 invnorm 操作
uint8_t invnorm_sha256(uint8_t in) {
    // 假设我们使用类似于 AES 中的方式，但这里针对 SHA-256 进行了调整
    // 这里的 bf_exp_238 可以根据 SHA-256 的 S 盒操作进行相应的定义
    in = bf_exp_238(in);  // 使用适用于SHA-256的操作
    return set_bit(get_bit(in, 0), 0) ^ set_bit(get_bit(in, 5), 1) ^ set_bit(get_bit(in, 6), 2) ^ set_bit(get_bit(in, 7), 3);
}


// 保存SHA-256的witness，仿照AES witness的奇数轮
static uint8_t* store_sha256_state(uint8_t* dst, uint8_t* state, unsigned int block_words) {
    for (unsigned int i = 0; i != block_words; ++i, ++dst) {
        bf8_store(dst, state[i]);  // 使用bf8_store存储每个状态值
    }
    return dst;
}

// 保存SHA-256的witness，仿照AES witness的偶数轮
static uint8_t* store_invnorm_sha256_state(uint8_t* dst, uint8_t* state, unsigned int block_words) {
    for (unsigned int i = 0; i != block_words; ++i, ++dst) {
        uint8_t normstate = invnorm_sha256(state[i]);
        bf8_store(dst, normstate);  // 使用bf8_store存储规范化后的状态值
    }
    return dst;
}

// RIPEMD-160 invnorm 操作
uint8_t invnorm_ripemd160(uint8_t in) {
    // 假设我们使用类似于 AES 中的方式，但这里针对 RIPEMD-160 进行了调整
    in = bf_exp_238(in);  // 使用适用于RIPEMD-160的操作
    return set_bit(get_bit(in, 1), 0) ^ set_bit(get_bit(in, 4), 1) ^ set_bit(get_bit(in, 5), 2) ^ set_bit(get_bit(in, 6), 3);
}


// 保存RIPEMD-160的witness，仿照AES witness的奇数轮
static uint8_t* store_ripemd160_state(uint8_t* dst, uint8_t* state) {
    for (int i = 0; i < RIPEMD160_DIGEST_LENGTH; ++i, ++dst) {
        bf8_store(dst, state[i]);  // 使用bf8_store存储每个字节
    }
    return dst;
}

// 保存RIPEMD-160的witness，仿照AES witness的偶数轮
static uint8_t* store_invnorm_ripemd160_state(uint8_t* dst, uint8_t* state) {
    for (int i = 0; i < RIPEMD160_DIGEST_LENGTH; ++i, ++dst) {
        uint8_t normstate = invnorm_ripemd160(state[i]);
        bf8_store(dst, normstate);  // 使用bf8_store存储规范化后的状态值
    }
    return dst;
}

void H_witness_extend(uint8_t* w, const uint8_t* key, const uint8_t* params) {
    const unsigned int lambda      = params[0];  // 数组中的第一个元素表示lambda
    const unsigned int num_rounds  = params[1];  // 数组中的第二个元素表示num_rounds
    const unsigned int blocksize   = 32 * params[2];  // 数组中的第三个元素表示Nst
    const unsigned int beta        = (lambda + blocksize - 1) / blocksize;
    const unsigned int block_words = blocksize / 32;
    const bool is_em               = (params[3] != 0);  // 假设数组中的第四个元素表示是否为EM变体

#if !defined(NDEBUG)
    uint8_t* const w_out = w;
#endif

    // Step 1: SHA-256 Hashing of key and storing the result as the first part of witness
    uint8_t sha256_output[32];
    SHA256_CTX sha256_ctx;
    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, key, lambda / 8);
    SHA256_Final(sha256_output, &sha256_ctx);
    
    // Store SHA-256 output in the witness
    memcpy(w, sha256_output, 32);
    w += 32;

    // Step 2: Generate and store SHA-256 witness
    for (unsigned int round = 0; round < num_rounds; ++round) {
        // Compute SHA-256 hash for the current round and update the witness
        uint8_t sha256_state[32];
        SHA256_Init(&sha256_ctx);
        SHA256_Update(&sha256_ctx, sha256_output, 32);  // Use the previous round's output as input
        SHA256_Final(sha256_state, &sha256_ctx);
        
        // Odd round: Store the normal state
        if (round % 2 == 0) {
            w = store_sha256_state(w, sha256_state, block_words);
        }
        // Even round: Store the inverted normalized state
        else {
            w = store_invnorm_sha256_state(w, sha256_state, block_words);
        }

        // Update sha256_output for the next round
        memcpy(sha256_output, sha256_state, 32);
    }

    // Step 3: Generate and store RIPEMD-160 witness
    uint8_t ripemd160_output[RIPEMD160_DIGEST_LENGTH];
    ripemd160(sha256_output, 32, ripemd160_output);  // Use the final SHA-256 output as input for RIPEMD-160

    // Store the RIPEMD-160 output in the witness
    memcpy(w, ripemd160_output, RIPEMD160_DIGEST_LENGTH);
    w += RIPEMD160_DIGEST_LENGTH;

    // Step 4: Process RIPEMD-160 for each round
    for (unsigned int round = 0; round < num_rounds; ++round) {
        // Compute RIPEMD-160 hash for the current round and update the witness
        uint8_t ripemd160_state[RIPEMD160_DIGEST_LENGTH];
        ripemd160(ripemd160_output, RIPEMD160_DIGEST_LENGTH, ripemd160_state);

        // Odd round: Store the normal state
        if (round % 2 == 0) {
            w = store_ripemd160_state(w, ripemd160_state);
        }
        // Even round: Store the inverted normalized state
        else {
            w = store_invnorm_ripemd160_state(w, ripemd160_state);
        }

        // Update ripemd160_output for the next round
        memcpy(ripemd160_output, ripemd160_state, RIPEMD160_DIGEST_LENGTH);
    }

    // assert(w - w_out == params[4] / 8);  // Ensure witness length is correct (params[4] represents the length)
}
