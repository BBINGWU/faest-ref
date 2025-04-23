#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <time.h>
#include "compound_hash.h"  // 引入你自己的复合哈希函数实现

#define NUM_TESTS 100000  // 测试次数，增加到 10 万次以确保统计的时间足够
#define REPEAT_TESTS 100  // 重复测试的次数（例如 100 次）
#define KEY_SIZE 16      // 128 位密钥 (16 字节)

void test_aes(const uint8_t *key, const uint8_t *input, uint8_t *output) {
    AES_KEY aes_key;
    AES_set_encrypt_key(key, 128, &aes_key);
    AES_encrypt(input, output, &aes_key);
}

void test_compound_hash(const uint8_t *input, uint8_t *output) {
    compound_hash(input, 16, output);  // 输入长度为16字节（128位）
}

long long measure_time(void (*func)(const uint8_t *, uint8_t *), const uint8_t *input, uint8_t *output) {
    clock_t start_time, end_time;
    start_time = clock();
    for (int i = 0; i < NUM_TESTS; ++i) {
        func(input, output);
    }
    end_time = clock();
    return ((long long)(end_time - start_time)) * 1000000 / CLOCKS_PER_SEC;  // 返回微秒数
}

int main() {
    uint8_t aes_key[KEY_SIZE] = {0};  // AES密钥为128位（全0）
    uint8_t aes_input[KEY_SIZE] = {0};  // AES输入为全0
    uint8_t aes_output[KEY_SIZE];

    uint8_t compound_hash_output[COMPOUND_HASH_DIGEST_LENGTH];

    long long aes_time, hash_time;

    // 测试 AES
    long long total_aes_time = 0;
    for (int i = 0; i < REPEAT_TESTS; ++i) {
        aes_time = measure_time(test_aes, aes_input, aes_output);
        total_aes_time += aes_time;
    }
    printf("Average AES encryption time over %d runs: %lld microseconds\n", REPEAT_TESTS, total_aes_time / REPEAT_TESTS);

    // 测试复合哈希
    long long total_hash_time = 0;
    for (int i = 0; i < REPEAT_TESTS; ++i) {
        hash_time = measure_time(test_compound_hash, aes_input, compound_hash_output);
        total_hash_time += hash_time;
    }
    printf("Average Compound Hash computation time over %d runs: %lld microseconds\n", REPEAT_TESTS, total_hash_time / REPEAT_TESTS);

    return 0;
}
