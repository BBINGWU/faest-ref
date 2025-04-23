#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

// 你需要根据实际情况提供以下参数的定义
#define KEY_LENGTH 32  // 假设密钥长度为32字节
#define PARAMS_LENGTH 5  // 假设参数数组长度为5，实际根据你的参数结构调整
#define WITNESS_LENGTH 1024  // 假设witness的长度为1024字节

void H_witness_extend(uint8_t* w, const uint8_t* key, const uint8_t* params);  // 手动声明函数

// 测试用的函数
void test_efficiency() {
    uint8_t key[KEY_LENGTH] = {0};  // 假设用零填充的密钥

    // 假设params的值，根据实际情况调整 params[4] 为WITNESS_LENGTH * 8，即 1024 * 8 = 8192
    uint8_t params[PARAMS_LENGTH] = {128, 69, 4, 1, WITNESS_LENGTH * 8};  // 这里的 params[4] 需要与 WITNESS_LENGTH 匹配

    uint8_t witness[WITNESS_LENGTH];  // 结果存储在witness中

    // 记录总时间
    clock_t start_time, end_time;
    double total_time = 0.0;

    // 测量10次调用的时间
    for (int i = 0; i < 10; ++i) {
        start_time = clock();  // 记录开始时间

        // 调用H_witness_extend函数
        H_witness_extend(witness, key, params);

        end_time = clock();  // 记录结束时间

        // 计算每次调用的耗时，并打印
        double elapsed_time = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;
        printf("Iteration %d time: %f seconds\n", i + 1, elapsed_time);

        total_time += elapsed_time;  // 累加总时间
    }

    // 打印平均时间
    printf("\nAverage time per call: %f seconds\n", total_time / 10.0);
}

int main() {
    test_efficiency();  // 调用测试函数
    return 0;
}
