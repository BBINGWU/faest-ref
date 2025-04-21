#include <stdio.h>
#include <string.h>
#include "ripemd160.h"

void print_digest(const unsigned char *digest, size_t len) {
    for (size_t i = 0; i < len; i++)
        printf("%02x", digest[i]);
    printf("\n");
}

int main() {
    const char *message = "abc";  // UTF-8 input
    unsigned char digest[RIPEMD160_DIGEST_LENGTH];

    ripemd160((const unsigned char *)message, strlen(message), digest);

    printf("Message: \"%s\"\n", message);
    printf("RIPEMD-160 Digest: ");
    print_digest(digest, RIPEMD160_DIGEST_LENGTH);

    printf("Expected:          8eb208f7e05d987a9b044a8e98c6b087f15a0bfc\n");

    return 0;
}
