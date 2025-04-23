// 以下是我的ripemd160.c的代码内容
#include <string.h>
#include "ripemd160.h"

// 32-bit left rotation
#define ROL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

// RIPEMD-160 non-linear functions
#define F(x,y,z) ((x) ^ (y) ^ (z))
#define G(x,y,z) (((x) & (y)) | (~(x) & (z)))
#define H(x,y,z) (((x) | ~(y)) ^ (z))
#define I(x,y,z) (((x) & (z)) | ((y) & ~(z)))
#define J(x,y,z) ((x) ^ ((y) | ~(z)))

// RIPEMD-160 round constants and operations for left line
#define FF(a,b,c,d,e,x,s) { (a) += F(b,c,d) + (x);                 (a) = ROL32((a),(s)) + (e); (c) = ROL32((c), 10); }
#define GG(a,b,c,d,e,x,s) { (a) += G(b,c,d) + (x) + 0x5a827999UL; (a) = ROL32((a),(s)) + (e); (c) = ROL32((c), 10); }
#define HH(a,b,c,d,e,x,s) { (a) += H(b,c,d) + (x) + 0x6ed9eba1UL; (a) = ROL32((a),(s)) + (e); (c) = ROL32((c), 10); }
#define II(a,b,c,d,e,x,s) { (a) += I(b,c,d) + (x) + 0x8f1bbcdcUL; (a) = ROL32((a),(s)) + (e); (c) = ROL32((c), 10); }
#define JJ(a,b,c,d,e,x,s) { (a) += J(b,c,d) + (x) + 0xa953fd4eUL; (a) = ROL32((a),(s)) + (e); (c) = ROL32((c), 10); }

// RIPEMD-160 round constants and operations for parallel (right line)
#define FFF(a,b,c,d,e,x,s) { (a) += F(b,c,d) + (x);                 (a) = ROL32((a),(s)) + (e); (c) = ROL32((c), 10); }
#define GGG(a,b,c,d,e,x,s) { (a) += G(b,c,d) + (x) + 0x7a6d76e9UL; (a) = ROL32((a),(s)) + (e); (c) = ROL32((c), 10); }
#define HHH(a,b,c,d,e,x,s) { (a) += H(b,c,d) + (x) + 0x6d703ef3UL; (a) = ROL32((a),(s)) + (e); (c) = ROL32((c), 10); }
#define III(a,b,c,d,e,x,s) { (a) += I(b,c,d) + (x) + 0x5c4dd124UL; (a) = ROL32((a),(s)) + (e); (c) = ROL32((c), 10); }
#define JJJ(a,b,c,d,e,x,s) { (a) += J(b,c,d) + (x) + 0x50a28be6UL; (a) = ROL32((a),(s)) + (e); (c) = ROL32((c), 10); }

// Compress a 512-bit block and update state
static void ripemd160_compress(uint32_t state[5], const uint8_t block[64]) {
    uint32_t X[16];
    // Load block into 16 little-endian 32-bit words
    for (int i = 0; i < 16; ++i) {
        X[i] = (uint32_t)block[4*i] 
             | ((uint32_t)block[4*i + 1] << 8)
             | ((uint32_t)block[4*i + 2] << 16)
             | ((uint32_t)block[4*i + 3] << 24);
    }
    // Initialize working variables
    uint32_t aa = state[0], bb = state[1], cc = state[2], dd = state[3], ee = state[4];
    uint32_t aaa = state[0], bbb = state[1], ccc = state[2], ddd = state[3], eee = state[4];

    // Round 1 (F)
    FF(aa, bb, cc, dd, ee, X[0], 11);  FF(ee, aa, bb, cc, dd, X[1], 14);
    FF(dd, ee, aa, bb, cc, X[2], 15);  FF(cc, dd, ee, aa, bb, X[3], 12);
    FF(bb, cc, dd, ee, aa, X[4], 5);   FF(aa, bb, cc, dd, ee, X[5], 8);
    FF(ee, aa, bb, cc, dd, X[6], 7);   FF(dd, ee, aa, bb, cc, X[7], 9);
    FF(cc, dd, ee, aa, bb, X[8], 11);  FF(bb, cc, dd, ee, aa, X[9], 13);
    FF(aa, bb, cc, dd, ee, X[10], 14); FF(ee, aa, bb, cc, dd, X[11], 15);
    FF(dd, ee, aa, bb, cc, X[12], 6);  FF(cc, dd, ee, aa, bb, X[13], 7);
    FF(bb, cc, dd, ee, aa, X[14], 9);  FF(aa, bb, cc, dd, ee, X[15], 8);

    // Round 2 (G)
    GG(ee, aa, bb, cc, dd, X[7], 7);   GG(dd, ee, aa, bb, cc, X[4], 6);
    GG(cc, dd, ee, aa, bb, X[13], 8);  GG(bb, cc, dd, ee, aa, X[1], 13);
    GG(aa, bb, cc, dd, ee, X[10], 11); GG(ee, aa, bb, cc, dd, X[6], 9);
    GG(dd, ee, aa, bb, cc, X[15], 7);  GG(cc, dd, ee, aa, bb, X[3], 15);
    GG(bb, cc, dd, ee, aa, X[12], 7);  GG(aa, bb, cc, dd, ee, X[0], 12);
    GG(ee, aa, bb, cc, dd, X[9], 15);  GG(dd, ee, aa, bb, cc, X[5], 9);
    GG(cc, dd, ee, aa, bb, X[2], 11);  GG(bb, cc, dd, ee, aa, X[14], 7);
    GG(aa, bb, cc, dd, ee, X[11], 13); GG(ee, aa, bb, cc, dd, X[8], 12);

    // Round 3 (H)
    HH(dd, ee, aa, bb, cc, X[3], 11);  HH(cc, dd, ee, aa, bb, X[10], 13);
    HH(bb, cc, dd, ee, aa, X[14], 6);  HH(aa, bb, cc, dd, ee, X[4], 7);
    HH(ee, aa, bb, cc, dd, X[9], 14);  HH(dd, ee, aa, bb, cc, X[15], 9);
    HH(cc, dd, ee, aa, bb, X[8], 13);  HH(bb, cc, dd, ee, aa, X[1], 15);
    HH(aa, bb, cc, dd, ee, X[2], 14);  HH(ee, aa, bb, cc, dd, X[7], 8);
    HH(dd, ee, aa, bb, cc, X[0], 13);  HH(cc, dd, ee, aa, bb, X[6], 6);
    HH(bb, cc, dd, ee, aa, X[13], 5);  HH(aa, bb, cc, dd, ee, X[11], 12);
    HH(ee, aa, bb, cc, dd, X[5], 7);   HH(dd, ee, aa, bb, cc, X[12], 5);

    // Round 4 (I)
    II(cc, dd, ee, aa, bb, X[1], 11);  II(bb, cc, dd, ee, aa, X[9], 12);
    II(aa, bb, cc, dd, ee, X[11], 14); II(ee, aa, bb, cc, dd, X[10], 15);
    II(dd, ee, aa, bb, cc, X[0], 14);  II(cc, dd, ee, aa, bb, X[8], 15);
    II(bb, cc, dd, ee, aa, X[12], 9);  II(aa, bb, cc, dd, ee, X[4], 8);
    II(ee, aa, bb, cc, dd, X[13], 9);  II(dd, ee, aa, bb, cc, X[3], 14);
    II(cc, dd, ee, aa, bb, X[7], 5);   II(bb, cc, dd, ee, aa, X[15], 6);
    II(aa, bb, cc, dd, ee, X[14], 8);  II(ee, aa, bb, cc, dd, X[5], 6);
    II(dd, ee, aa, bb, cc, X[6], 5);   II(cc, dd, ee, aa, bb, X[2], 12);

    // Round 5 (J)
    JJ(bb, cc, dd, ee, aa, X[4], 9);   JJ(aa, bb, cc, dd, ee, X[0], 15);
    JJ(ee, aa, bb, cc, dd, X[5], 5);   JJ(dd, ee, aa, bb, cc, X[9], 11);
    JJ(cc, dd, ee, aa, bb, X[7], 6);   JJ(bb, cc, dd, ee, aa, X[12], 8);
    JJ(aa, bb, cc, dd, ee, X[2], 13);  JJ(ee, aa, bb, cc, dd, X[10], 12);
    JJ(dd, ee, aa, bb, cc, X[14], 5);  JJ(cc, dd, ee, aa, bb, X[1], 12);
    JJ(bb, cc, dd, ee, aa, X[3], 13);  JJ(aa, bb, cc, dd, ee, X[8], 14);
    JJ(ee, aa, bb, cc, dd, X[11], 11); JJ(dd, ee, aa, bb, cc, X[6], 8);
    JJ(cc, dd, ee, aa, bb, X[15], 5);  JJ(bb, cc, dd, ee, aa, X[13], 6);

    // Parallel round 1 (J)
    JJJ(aaa, bbb, ccc, ddd, eee, X[5], 8);   JJJ(eee, aaa, bbb, ccc, ddd, X[14], 9);
    JJJ(ddd, eee, aaa, bbb, ccc, X[7], 9);   JJJ(ccc, ddd, eee, aaa, bbb, X[0], 11);
    JJJ(bbb, ccc, ddd, eee, aaa, X[9], 13);  JJJ(aaa, bbb, ccc, ddd, eee, X[2], 15);
    JJJ(eee, aaa, bbb, ccc, ddd, X[11], 15); JJJ(ddd, eee, aaa, bbb, ccc, X[4], 5);
    JJJ(ccc, ddd, eee, aaa, bbb, X[13], 7);  JJJ(bbb, ccc, ddd, eee, aaa, X[6], 7);
    JJJ(aaa, bbb, ccc, ddd, eee, X[15], 8);  JJJ(eee, aaa, bbb, ccc, ddd, X[8], 11);
    JJJ(ddd, eee, aaa, bbb, ccc, X[1], 14);  JJJ(ccc, ddd, eee, aaa, bbb, X[10], 14);
    JJJ(bbb, ccc, ddd, eee, aaa, X[3], 12);  JJJ(aaa, bbb, ccc, ddd, eee, X[12], 6);

    // Parallel round 2 (I)
    III(eee, aaa, bbb, ccc, ddd, X[6], 9);   III(ddd, eee, aaa, bbb, ccc, X[11], 13);
    III(ccc, ddd, eee, aaa, bbb, X[3], 15);  III(bbb, ccc, ddd, eee, aaa, X[7], 7);
    III(aaa, bbb, ccc, ddd, eee, X[0], 12);  III(eee, aaa, bbb, ccc, ddd, X[13], 8);
    III(ddd, eee, aaa, bbb, ccc, X[5], 9);   III(ccc, ddd, eee, aaa, bbb, X[10], 11);
    III(bbb, ccc, ddd, eee, aaa, X[14], 7);  III(aaa, bbb, ccc, ddd, eee, X[15], 7);
    III(eee, aaa, bbb, ccc, ddd, X[8], 12);  III(ddd, eee, aaa, bbb, ccc, X[12], 7);
    III(ccc, ddd, eee, aaa, bbb, X[4], 6);   III(bbb, ccc, ddd, eee, aaa, X[9], 15);
    III(aaa, bbb, ccc, ddd, eee, X[1], 13);  III(eee, aaa, bbb, ccc, ddd, X[2], 11);

    // Parallel round 3 (H)
    HHH(ddd, eee, aaa, bbb, ccc, X[15], 9);  HHH(ccc, ddd, eee, aaa, bbb, X[5], 7);
    HHH(bbb, ccc, ddd, eee, aaa, X[1], 15);  HHH(aaa, bbb, ccc, ddd, eee, X[3], 11);
    HHH(eee, aaa, bbb, ccc, ddd, X[7], 8);   HHH(ddd, eee, aaa, bbb, ccc, X[14], 6);
    HHH(ccc, ddd, eee, aaa, bbb, X[6], 6);   HHH(bbb, ccc, ddd, eee, aaa, X[9], 14);
    HHH(aaa, bbb, ccc, ddd, eee, X[11], 12); HHH(eee, aaa, bbb, ccc, ddd, X[8], 13);
    HHH(ddd, eee, aaa, bbb, ccc, X[12], 5);  HHH(ccc, ddd, eee, aaa, bbb, X[2], 14);
    HHH(bbb, ccc, ddd, eee, aaa, X[10], 13); HHH(aaa, bbb, ccc, ddd, eee, X[0], 13);
    HHH(eee, aaa, bbb, ccc, ddd, X[4], 7);   HHH(ddd, eee, aaa, bbb, ccc, X[13], 5);

    // Parallel round 4 (G)
    GGG(ccc, ddd, eee, aaa, bbb, X[8], 15);  GGG(bbb, ccc, ddd, eee, aaa, X[6], 5);
    GGG(aaa, bbb, ccc, ddd, eee, X[4], 8);   GGG(eee, aaa, bbb, ccc, ddd, X[1], 11);
    GGG(ddd, eee, aaa, bbb, ccc, X[3], 14);  GGG(ccc, ddd, eee, aaa, bbb, X[11], 14);
    GGG(bbb, ccc, ddd, eee, aaa, X[15], 6);  GGG(aaa, bbb, ccc, ddd, eee, X[0], 14);
    GGG(eee, aaa, bbb, ccc, ddd, X[5], 6);   GGG(ddd, eee, aaa, bbb, ccc, X[12], 9);
    GGG(ccc, ddd, eee, aaa, bbb, X[2], 12);  GGG(bbb, ccc, ddd, eee, aaa, X[13], 9);
    GGG(aaa, bbb, ccc, ddd, eee, X[9], 12);  GGG(eee, aaa, bbb, ccc, ddd, X[7], 5);
    GGG(ddd, eee, aaa, bbb, ccc, X[10], 15); GGG(ccc, ddd, eee, aaa, bbb, X[14], 8);

    // Parallel round 5 (F)
    FFF(bbb, ccc, ddd, eee, aaa, X[12], 8);  FFF(aaa, bbb, ccc, ddd, eee, X[15], 5);
    FFF(eee, aaa, bbb, ccc, ddd, X[10], 12); FFF(ddd, eee, aaa, bbb, ccc, X[4], 9);
    FFF(ccc, ddd, eee, aaa, bbb, X[1], 12);  FFF(bbb, ccc, ddd, eee, aaa, X[5], 5);
    FFF(aaa, bbb, ccc, ddd, eee, X[8], 14);  FFF(eee, aaa, bbb, ccc, ddd, X[7], 6);
    FFF(ddd, eee, aaa, bbb, ccc, X[6], 8);   FFF(ccc, ddd, eee, aaa, bbb, X[2], 13);
    FFF(bbb, ccc, ddd, eee, aaa, X[13], 6);  FFF(aaa, bbb, ccc, ddd, eee, X[14], 5);
    FFF(eee, aaa, bbb, ccc, ddd, X[0], 15);  FFF(ddd, eee, aaa, bbb, ccc, X[3], 13);
    FFF(ccc, ddd, eee, aaa, bbb, X[9], 11);  FFF(bbb, ccc, ddd, eee, aaa, X[11], 11);

    // Combine results
    ddd += cc + state[1];
    state[1] = state[2] + dd + eee;
    state[2] = state[3] + ee + aaa;
    state[3] = state[4] + aa + bbb;
    state[4] = state[0] + bb + ccc;
    state[0] = ddd;
}

// Compute RIPEMD-160 hash of message
void ripemd160(const uint8_t *message, size_t length, uint8_t digest[RIPEMD160_DIGEST_LENGTH]) {
    // Initialize state (A, B, C, D, E)
    uint32_t state[5] = {
        0x67452301UL, 0xEFCDAB89UL, 0x98BADCFEUL, 0x10325476UL, 0xC3D2E1F0UL
    };

    // Process message in 512-bit (64-byte) blocks
    size_t blocks = length / 64;
    for (size_t i = 0; i < blocks; ++i) {
        ripemd160_compress(state, message + 64*i);
    }

    // Prepare final block with padding
    uint8_t block[64];
    size_t rem = length % 64;
    if (rem) memcpy(block, message + 64*blocks, rem);
    block[rem] = 0x80;  // append "1" bit (0x80 means binary 10000000)
    if (rem < 63) memset(block + rem + 1, 0, 63 - rem);
    if (rem > 55) {
        // Not enough space for 64-bit length -> compress this block with padding
        ripemd160_compress(state, block);
        memset(block, 0, 56);  // prepare a new block of zeros
    } else {
        // If there is space for length, zero pad the rest (if any) before length
        if (rem < 56) memset(block + rem + 1, 0, 56 - (rem + 1));
    }
    // Append original message length in bits (64-bit little-endian)
    uint64_t bit_length = (uint64_t)length * 8ULL;
    for (int i = 0; i < 8; ++i) {
        block[56 + i] = (uint8_t)(bit_length >> (8 * i));
    }
    ripemd160_compress(state, block);

    // Output digest in little-endian order
    for (int i = 0; i < 5; ++i) {
        digest[4*i + 0] = (uint8_t)(state[i] & 0xFF);
        digest[4*i + 1] = (uint8_t)((state[i] >> 8) & 0xFF);
        digest[4*i + 2] = (uint8_t)((state[i] >> 16) & 0xFF);
        digest[4*i + 3] = (uint8_t)((state[i] >> 24) & 0xFF);
    }
}
