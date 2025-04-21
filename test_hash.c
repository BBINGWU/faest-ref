// test_hash.c
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "sha256.h"
#include "ripemd160.h"
#include "compound_hash.h"

static void print_hex(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) printf("%02x", buf[i]);
    printf("\n");
}

static int test_sha256(void) {
    const char *msg = "abc";
    uint8_t digest[32];
    SHA256_CTX sctx;
    SHA256_Init(&sctx);
    SHA256_Update(&sctx, msg, strlen(msg));
    SHA256_Final(digest, &sctx);

    const char *expect = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    char outhex[65] = {0};
    for (int i = 0; i < 32; i++) sprintf(outhex + 2*i, "%02x", digest[i]);

    printf("SHA256(\"%s\") = %s\n", msg, outhex);
    printf("Expected          = %s\n\n", expect);
    return strcmp(outhex, expect) == 0;
}

static int test_ripemd160(void) {
    // RFC 2286 五个测试向量
    struct { const char *msg, *exp; } tvs[] = {
        { "",    "9c1185a5c5e9fc54612808977ee8f548b2258d31" },
        { "a",   "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe" },
        { "abc", "8eb208f7e05d987a9b04e0345414467e5b1c5b0e" },
        { "message digest",          "5d0689ef49d2fae572b881b123a85ffa21595f36" },
        { "abcdefghijklmnopqrstuvwxyz", "f71c27109c692c1b56bbdceb5b9d2865b3708dbc" }
    };
    int ok = 1;
    printf("=== RIPEMD‑160 multi‑vector test ===\n");
    for (int i = 0; i < 5; i++) {
        const char *m = tvs[i].msg;
        const char *e = tvs[i].exp;
        uint8_t digest[20];
        RIPEMD160_CTX ctx;
        RIPEMD160_Init(&ctx);
        RIPEMD160_Update(&ctx, m, strlen(m));
        RIPEMD160_Final(digest, &ctx);

        char outhex[41] = {0};
        for (int j = 0; j < 20; j++) sprintf(outhex + 2*j, "%02x", digest[j]);

        printf("Test #%d \"%s\"\n", i+1, m);
        printf("  You: %s\n", outhex);
        printf("  RFC: %s\n", e);
        if (strcmp(outhex, e) != 0) {
            printf("  >>> FAIL\n\n");
            ok = 0;
        } else {
            printf("  PASS\n\n");
        }
    }
    return ok;
}

static int test_compound(void) {
    const uint8_t key[] = "key";
    const uint8_t iv[16] = {0};
    uint8_t out1[16], out2[16];
    compound_prf(key, sizeof(key)-1, iv, out1);
    compound_prf(key, sizeof(key)-1, iv, out2);
    printf("=== Compound PRF consistency ===\n");
    print_hex(out1,16);
    print_hex(out2,16);
    return memcmp(out1, out2, 16) == 0;
}

int main(void) {
    int ok = 1;
    printf("=== SHA‑256 test ===\n");
    if (!test_sha256()) ok = 0;
    if (!test_ripemd160()) ok = 0;
    if (!test_compound()) {
        printf("FAIL compound consistency\n");
        ok = 0;
    }
    return ok ? 0 : 1;
}
