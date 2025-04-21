/* sha256.c */
#include "sha256.h"
#include <string.h>

/* SHA-256 constants */
static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROTR(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define CH(x,y,z) (((x)&(y))^((~(x))&(z)))
#define MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define SIG0(x) (ROTR(x,2)^ROTR(x,13)^ROTR(x,22))
#define SIG1(x) (ROTR(x,6)^ROTR(x,11)^ROTR(x,25))
#define sig0(x) (ROTR(x,7)^ROTR(x,18)^((x)>>3))
#define sig1(x) (ROTR(x,17)^ROTR(x,19)^((x)>>10))

static void sha256_transform(SHA256_CTX *ctx, const uint8_t data[64]) {
    uint32_t W[64], a,b,c,d,e,f,g,h,T1,T2;
    for(int i=0;i<16;i++) {
        W[i] = (data[4*i]<<24) | (data[4*i+1]<<16) | (data[4*i+2]<<8) | (data[4*i+3]);
    }
    for(int i=16;i<64;i++) {
        W[i] = sig1(W[i-2]) + W[i-7] + sig0(W[i-15]) + W[i-16];
    }
    a=ctx->state[0]; b=ctx->state[1]; c=ctx->state[2]; d=ctx->state[3];
    e=ctx->state[4]; f=ctx->state[5]; g=ctx->state[6]; h=ctx->state[7];
    for(int i=0;i<64;i++) {
        T1 = h + SIG1(e) + CH(e,f,g) + K[i] + W[i];
        T2 = SIG0(a) + MAJ(a,b,c);
        h=g; g=f; f=e; e=d+T1;
        d=c; c=b; b=a; a=T1+T2;
    }
    ctx->state[0]+=a; ctx->state[1]+=b; ctx->state[2]+=c; ctx->state[3]+=d;
    ctx->state[4]+=e; ctx->state[5]+=f; ctx->state[6]+=g; ctx->state[7]+=h;
}

void SHA256_Init(SHA256_CTX *ctx) {
    ctx->state[0]=0x6a09e667; ctx->state[1]=0xbb67ae85;
    ctx->state[2]=0x3c6ef372; ctx->state[3]=0xa54ff53a;
    ctx->state[4]=0x510e527f; ctx->state[5]=0x9b05688c;
    ctx->state[6]=0x1f83d9ab; ctx->state[7]=0x5be0cd19;
    ctx->bitcount=0; memset(ctx->buffer,0,64);
}

void SHA256_Update(SHA256_CTX *ctx, const void *data, size_t len) {
    size_t i,j;
    j = (ctx->bitcount>>3) % 64;
    ctx->bitcount += (uint64_t)len<<3;
    for(i=0;i<len;i++) {
        ctx->buffer[j++] = ((const uint8_t*)data)[i];
        if(j==64) { sha256_transform(ctx, ctx->buffer); j=0; }
    }
}

void SHA256_Final(uint8_t digest[32], SHA256_CTX *ctx) {
    uint8_t bits[8];
    for(int i=0;i<8;i++) bits[7-i] = ctx->bitcount >> (i*8);
    size_t idx = (ctx->bitcount>>3) % 64;
    ctx->buffer[idx++] = 0x80;
    if(idx>56) { while(idx<64) ctx->buffer[idx++]=0; sha256_transform(ctx,ctx->buffer); idx=0; }
    while(idx<56) ctx->buffer[idx++]=0;
    memcpy(ctx->buffer+56,bits,8);
    sha256_transform(ctx,ctx->buffer);
    for(int i=0;i<8;i++) {
        digest[4*i]   = (ctx->state[i]>>24)&0xff;
        digest[4*i+1] = (ctx->state[i]>>16)&0xff;
        digest[4*i+2] = (ctx->state[i]>>8)&0xff;
        digest[4*i+3] = ctx->state[i]&0xff;
    }
}
