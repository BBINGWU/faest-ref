#include <stdio.h>
#include <string.h>
#include "../hash/ripemd160.h"
#include "../hash/sha256.h"  // 引入 sha256 的头文件（相对路径）

// 打印哈希值的辅助函数
void print_digest(const unsigned char *digest, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");
}

int main() {
    const char *message = "abc";  // 输入消息
    unsigned char ripemd160_digest[RIPEMD160_DIGEST_LENGTH];
    unsigned char sha256_digest[SHA256_DIGEST_LENGTH];  // 为 SHA-256 创建输出数组

    // 测试 RIPEMD-160
    ripemd160((const unsigned char *)message, strlen(message), ripemd160_digest);
    printf("Message: \"%s\"\n", message);
    printf("RIPEMD-160 Digest: ");
    print_digest(ripemd160_digest, RIPEMD160_DIGEST_LENGTH);
    printf("Expected:          8eb208f7e05d987a9b044a8e98c6b087f15a0bfc\n");

    // 测试 SHA-256
    SHA256_CTX sha256_ctx;  // 定义 SHA256_CTX 结构体
    SHA256_Init(&sha256_ctx);  // 初始化 SHA256_CTX
    SHA256_Update(&sha256_ctx, (const unsigned char *)message, strlen(message));  // 更新 SHA256_CTX
    SHA256_Final(sha256_digest, &sha256_ctx);  // 获取最终的 SHA256 哈希值

    printf("SHA-256 Digest: ");
    print_digest(sha256_digest, SHA256_DIGEST_LENGTH);
    printf("Expected:          ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\n");

    return 0;
}
