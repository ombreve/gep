#include <string.h>
#include "rfc8439.h"

#define U8V(v)  ((uint8_t)(v)  & UINT8_C(0xFF))
#define U32V(v) ((uint32_t)(v) & UINT32_C(0xFFFFFFFF))

#define U8TO32_LITTLE(p) \
  (((uint32_t)((p)[0])      ) | \
   ((uint32_t)((p)[1]) <<  8) | \
   ((uint32_t)((p)[2]) << 16) | \
   ((uint32_t)((p)[3]) << 24))

#define U32TO8_LITTLE(p, v) \
  do { \
    (p)[0] = U8V((v)      ); \
    (p)[1] = U8V((v) >>  8); \
    (p)[2] = U8V((v) >> 16); \
    (p)[3] = U8V((v) >> 24); \
  } while (0)

#define ROTATE(v,c) (U32V((v) << (c)) | ((v) >> (32 - (c))))
#define XOR(v,w) ((v) ^ (w))
#define PLUS(v,w) (U32V((v) + (w)))
#define PLUSONE(v) (PLUS((v),1))

#define QUARTERROUND(a,b,c,d) \
  x[a] = PLUS(x[a],x[b]); x[d] = ROTATE(XOR(x[d],x[a]),16); \
  x[c] = PLUS(x[c],x[d]); x[b] = ROTATE(XOR(x[b],x[c]),12); \
  x[a] = PLUS(x[a],x[b]); x[d] = ROTATE(XOR(x[d],x[a]), 8); \
  x[c] = PLUS(x[c],x[d]); x[b] = ROTATE(XOR(x[b],x[c]), 7);

/* Chacha20 block function. */
static void
chacha20_block(uint8_t output[64], const uint32_t input[16])
{
    uint32_t x[16];
    size_t i;

    for (i = 0; i < 16; i++)
        x[i] = input[i];

    for (i = 0; i < 10; i++) {
        QUARTERROUND(0,  4,  8, 12)
        QUARTERROUND(1,  5,  9, 13)
        QUARTERROUND(2,  6, 10, 14)
        QUARTERROUND(3,  7, 11, 15)
        QUARTERROUND(0,  5, 10, 15)
        QUARTERROUND(1,  6, 11, 12)
        QUARTERROUND(2,  7,  8, 13)
        QUARTERROUND(3,  4,  9, 14)
    }
    for (i = 0; i < 16; i++)
        x[i] = PLUS(x[i], input[i]);

    for (i = 0; i < 16; i++)
        U32TO8_LITTLE(output + 4 * i, x[i]);
}

/* The chacha20 state is initialized as follows:
   - The first four words (0-3) are constants: 0x61707865, 0x3320646e,
     0x79622d32, 0x6b206574.
   - The next eight words (4-11) are taken from the 256-bit key by
     reading the bytes in little-endian order, in 4-byte chunks.
   - Word 12 is a block counter.  Since each block is 64-byte, a 32-bit
     word is enough for 256 gigabytes of data.
   - Words 13-15 are a nonce, which MUST not be repeated for the same
     key.  The 13th word is the first 32 bits of the input nonce taken
     as a little-endian integer, while the 15th word is the last 32
     bits.

     cccccccc  cccccccc  cccccccc  cccccccc
     kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
     kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
     bbbbbbbb  nnnnnnnn  nnnnnnnn  nnnnnnnn
*/
void
chacha20_init(CHACHA20_CTX *x, const uint8_t key[32], const uint8_t nonce[12])
{
    static const char sigma[16] = "expand 32-byte k";

    x->state[0]  = U8TO32_LITTLE(sigma + 0);
    x->state[1]  = U8TO32_LITTLE(sigma + 4);
    x->state[2]  = U8TO32_LITTLE(sigma + 8);
    x->state[3]  = U8TO32_LITTLE(sigma + 12);

    x->state[4]  = U8TO32_LITTLE(key + 0);
    x->state[5]  = U8TO32_LITTLE(key + 4);
    x->state[6]  = U8TO32_LITTLE(key + 8);
    x->state[7]  = U8TO32_LITTLE(key + 12);
    x->state[8]  = U8TO32_LITTLE(key + 16);
    x->state[9]  = U8TO32_LITTLE(key + 20);
    x->state[10] = U8TO32_LITTLE(key + 24);
    x->state[11] = U8TO32_LITTLE(key + 28);

    x->state[12] = 1;

    x->state[13] = U8TO32_LITTLE(nonce + 0);
    x->state[14] = U8TO32_LITTLE(nonce + 4);
    x->state[15] = U8TO32_LITTLE(nonce + 8);
}

void
chacha20_encrypt(CHACHA20_CTX *x, const uint8_t *m, uint8_t *c, size_t n)
{
    uint8_t output[64];
    size_t i;

    if (!n)
        return;
    for (;;) {
        chacha20_block(output, x->state);
        x->state[12] = PLUSONE(x->state[12]);
        if (n <= 64) { /* last block */
            for (i = 0; i < n; i++)
                c[i] = m[i] ^ output[i];
            return;
        }
        for (i = 0; i < 64; i++)
            c[i] = m[i] ^ output[i];
        c += 64;
        m += 64;
        n -= 64;
    }
}

void
poly1305_init(POLY1305_CTX *x, const uint8_t key[32])
{
    /* The first 16 bytes of the key are treated as a 16-byte little-endian
     * number r. The x->r table gets 30 bits by slot of the number:
     * r & 0xffffffc0ffffffc0ffffffc0fffffff */
    x->r[0] = (U8TO32_LITTLE(key +  0)     ) & 0x3ffffff;
    x->r[1] = (U8TO32_LITTLE(key +  3) >> 2) & 0x3ffff03;
    x->r[2] = (U8TO32_LITTLE(key +  6) >> 4) & 0x3ffc0ff;
    x->r[3] = (U8TO32_LITTLE(key +  9) >> 6) & 0x3f03fff;
    x->r[4] = (U8TO32_LITTLE(key + 12) >> 8) & 0x00fffff;

    /* h = 0 */
    x->h[0] = 0;
    x->h[1] = 0;
    x->h[2] = 0;
    x->h[3] = 0;
    x->h[4] = 0;

    /* The last part of the key is saved for later */
    x->pad[0] = U8TO32_LITTLE(&key[16]);
    x->pad[1] = U8TO32_LITTLE(&key[20]);
    x->pad[2] = U8TO32_LITTLE(&key[24]);
    x->pad[3] = U8TO32_LITTLE(&key[28]);

    x->leftover = 0;
    x->final = 0;
}

static void
poly1305_blocks(POLY1305_CTX *x, const unsigned char *m, size_t bytes)
{
    const uint32_t hibit = (x->final) ? 0 : (1UL << 24);
    uint32_t r0, r1, r2, r3, r4;
    uint32_t s1, s2, s3, s4;
    uint32_t h0, h1, h2, h3, h4;
    uint64_t d0, d1, d2, d3, d4;
    uint32_t c;

    r0 = x->r[0];
    r1 = x->r[1];
    r2 = x->r[2];
    r3 = x->r[3];
    r4 = x->r[4];

    s1 = r1 * 5;
    s2 = r2 * 5;
    s3 = r3 * 5;
    s4 = r4 * 5;

    h0 = x->h[0];
    h1 = x->h[1];
    h2 = x->h[2];
    h3 = x->h[3];
    h4 = x->h[4];

    while (bytes >= 16) {
        /* h += m[i] */
        h0 += (U8TO32_LITTLE(m + 0)     ) & 0x3ffffff;
        h1 += (U8TO32_LITTLE(m + 3) >> 2) & 0x3ffffff;
        h2 += (U8TO32_LITTLE(m + 6) >> 4) & 0x3ffffff;
        h3 += (U8TO32_LITTLE(m + 9) >> 6) & 0x3ffffff;
        h4 += (U8TO32_LITTLE(m +12) >> 8) | hibit;

        /* h *= r */
        d0 = ((uint64_t)h0 * r0) + ((uint64_t)h1 * s4) + ((uint64_t)h2 * s3)
            + ((uint64_t)h3 * s2) + ((uint64_t)h4 * s1);
        d1 = ((uint64_t)h0 * r1) + ((uint64_t)h1 * r0) + ((uint64_t)h2 * s4)
            + ((uint64_t)h3 * s3) + ((uint64_t)h4 * s2);
        d2 = ((uint64_t)h0 * r2) + ((uint64_t)h1 * r1) + ((uint64_t)h2 * r0)
            + ((uint64_t)h3 * s4) + ((uint64_t)h4 * s3);
        d3 = ((uint64_t)h0 * r3) + ((uint64_t)h1 * r2) + ((uint64_t)h2 * r1)
            + ((uint64_t)h3 * r0) + ((uint64_t)h4 * s4);
        d4 = ((uint64_t)h0 * r4) + ((uint64_t)h1 * r3) + ((uint64_t)h2 * r2)
            + ((uint64_t)h3 * r1) + ((uint64_t)h4 * r0);

        /* (partial) h %= p */
        c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3ffffff; d1 += c;
        c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3ffffff; d2 += c;
        c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3ffffff; d3 += c;
        c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3ffffff; d4 += c;
        c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3ffffff; h0 += c * 5;
        c = (h0 >> 26); h0 = h0 & 0x3ffffff; h1 += c;

        m += 16;
        bytes -= 16;
    }

    x->h[0] = h0;
    x->h[1] = h1;
    x->h[2] = h2;
    x->h[3] = h3;
    x->h[4] = h4;
}

void
poly1305_update(POLY1305_CTX *x, const uint8_t *m, size_t bytes)
{
    uint32_t i = 0;

    /* Handle leftover */
    if (x->leftover) {
        uint32_t want = (16 - x->leftover);

        if (want > bytes)
            want = bytes;
        for (i = 0; i < want; i++)
            x->buffer[x->leftover + i] = m[i];
        bytes -= want;
        m += want;
        x->leftover += want;
        if (x->leftover < 16)
            return;
        poly1305_blocks(x, x->buffer, 16);
        x->leftover = 0;
    }

    /* Process full blocks */
    if (bytes >= 16) {
        uint32_t want = (bytes & ~15);

        poly1305_blocks(x, m, want);
        m += want;
        bytes -= want;
    }

    /* Store leftover */
    if (bytes) {
        for (i = 0; i < bytes; i++)
            x->buffer[x->leftover + i] = m[i];
        x->leftover += bytes;
    }
}

void
poly1305_final(POLY1305_CTX *x, uint8_t tag[16])
{
    uint32_t h0, h1, h2, h3, h4, c;
    uint32_t g0, g1, g2, g3, g4;
    uint64_t f;
    uint32_t mask;

    /* process the remaining block */
    if (x->leftover) {
        uint32_t i = x->leftover;

        x->buffer[i++] = 1;
        for (; i < 16; i++)
            x->buffer[i] = 0;
        x->final = 1;
        poly1305_blocks(x, x->buffer, 16);
    }

    /* fully carry h */
    h0 = x->h[0];
    h1 = x->h[1];
    h2 = x->h[2];
    h3 = x->h[3];
    h4 = x->h[4];

    c = h1 >> 26; h1 = h1 & 0x3ffffff; h2 += c;
    c = h2 >> 26; h2 = h2 & 0x3ffffff; h3 += c;
    c = h3 >> 26; h3 = h3 & 0x3ffffff; h4 += c;
    c = h4 >> 26; h4 = h4 & 0x3ffffff; h0 += c * 5;
    c = h0 >> 26; h0 = h0 & 0x3ffffff; h1 += c;

    /* compute h + -p */
    g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    g4 = h4 + c - (1UL << 26);

    /* select h if h < p, or h + -p if h >= p */
    mask = (g4 >> ((sizeof(uint32_t) * 8) - 1)) - 1;
    g0 &= mask;
    g1 &= mask;
    g2 &= mask;
    g3 &= mask;
    g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;

    /* h = h % (2^128) */
    h0 = ((h0      ) | (h1 << 26)) & 0xffffffff;
    h1 = ((h1 >>  6) | (h2 << 20)) & 0xffffffff;
    h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff;
    h3 = ((h3 >> 18) | (h4 <<  8)) & 0xffffffff;

    /* mac = (h + pad) % (2^128) */
    f = (uint64_t)h0 + x->pad[0]            ; h0 = (uint32_t)f;
    f = (uint64_t)h1 + x->pad[1] + (f >> 32); h1 = (uint32_t)f;
    f = (uint64_t)h2 + x->pad[2] + (f >> 32); h2 = (uint32_t)f;
    f = (uint64_t)h3 + x->pad[3] + (f >> 32); h3 = (uint32_t)f;

    U32TO8_LITTLE(tag +  0, h0);
    U32TO8_LITTLE(tag +  4, h1);
    U32TO8_LITTLE(tag +  8, h2);
    U32TO8_LITTLE(tag + 12, h3);
}

int
poly1305_verify(const uint8_t tag1[16], const uint8_t tag2[16])
{
    size_t i = 0;
    uint16_t dif = 0;

    for (i = 0; i < 16; i++)
        dif |= (tag1[i] ^ tag2[i]);
    dif = (dif - 1) >> ((sizeof(uint16_t) * 8) - 1);
    return (dif & 1);
}

void
rfc8439_init(RFC8439_CTX *x, const uint8_t key[32], const uint8_t nonce[12],
             const uint8_t *aad, size_t n)
{
    uint8_t m[64] = {0}, c[64];

    chacha20_init(x->c, key, nonce);
    x->c->state[12] = 0;
    chacha20_encrypt(x->c, m, c, 64);
    poly1305_init(x->p, c);

    poly1305_update(x->p, aad, n);
    x->aad_sz = n;
    n = n % 16;
    if (n)
        poly1305_update(x->p, m, 16 - n); /* padding */

    x->c_sz = 0;
}

void
rfc8439_encrypt(RFC8439_CTX *x, const uint8_t *m, uint8_t *c, size_t n)
{
    chacha20_encrypt(x->c, m, c, n);
    poly1305_update(x->p, c, n);
    x->c_sz += n;
}

void
rfc8439_decrypt(RFC8439_CTX *x, const uint8_t *c, uint8_t *m, size_t n)
{
    chacha20_encrypt(x->c, c, m, n);
    poly1305_update(x->p, c, n);
    x->c_sz += n;
}

void rfc8439_mac(RFC8439_CTX *x, uint8_t mac[16])
{
    uint8_t padding[16] = {0};
    size_t pad;

    pad = x->c_sz % 16;
    if (pad)
        poly1305_update(x->p, padding, 16 - pad);

    U32TO8_LITTLE(padding, x->aad_sz);
    poly1305_update(x->p, padding, 8);
    U32TO8_LITTLE(padding, x->c_sz);
    poly1305_update(x->p, padding, 8);

    poly1305_final(x->p, mac);
}

int rfc8439_verify(RFC8439_CTX *x, uint8_t mac[16])
{
    uint8_t padding[16] = {0};
    size_t pad;

    pad = x->c_sz % 16;
    if (pad)
        poly1305_update(x->p, padding, 16 - pad);

    U32TO8_LITTLE(padding, x->aad_sz);
    poly1305_update(x->p, padding, 8);
    U32TO8_LITTLE(padding, x->c_sz);
    poly1305_update(x->p, padding, 8);

    poly1305_final(x->p, padding);
    return poly1305_verify(mac, padding);
}

void
xchacha20_key(const uint8_t key[32], const uint8_t nonce[24],
              uint8_t subkey[32], uint8_t subnonce[12])
{
    CHACHA20_CTX ctx[1];
    uint32_t *x = ctx->state;
    size_t i;

    /* Init with key and the first 16 bytes of the nonce (no counter) */
    chacha20_init(ctx, key, nonce + 4);
    x[12] = U8TO32_LITTLE(nonce);

    /* One block function without the final addition */
    for (i = 0; i < 10; i++) {
        QUARTERROUND(0,  4,  8, 12)
        QUARTERROUND(1,  5,  9, 13)
        QUARTERROUND(2,  6, 10, 14)
        QUARTERROUND(3,  7, 11, 15)
        QUARTERROUND(0,  5, 10, 15)
        QUARTERROUND(1,  6, 11, 12)
        QUARTERROUND(2,  7,  8, 13)
        QUARTERROUND(3,  4,  9, 14)
    }

    /* First and last rows of state make the subkey */
    for (i = 0; i < 4; i++)
        U32TO8_LITTLE(subkey + 4 * i, x[i]);
    for (i = 12; i < 16; i++)
        U32TO8_LITTLE(subkey + 4 * i - 32, x[i]);

    /* Last 8 bytes of nonce prefixed by 4 null bytes make the subnonce */
    memset(subnonce, 0, 4);
    memcpy(subnonce + 4, nonce + 16, 8);
}

#ifdef RFC8439_TEST

#include <stdio.h>
#include <stdlib.h>

static void
print_state(const uint32_t state[16])
{
    int i, j;

    for (i = 0; i < 4; i++) {
        printf("    ");
        for (j = 0; j < 4; j++)
            printf("  %08x", state[i * 4 + j]);
        putchar('\n');
    }
}

static void
print_block(const uint8_t *block, size_t len)
{
    int i, j;

    for (i = 0; i < len/16; i++) {
        printf("     ");
        for (j = 0; j < 16; j++)
            printf(" %02x", block[i * 16 + j]);
        putchar('\n');
    }
    if (len%16) {
        printf("     ");
        for (j = 0; j < len%16; j++)
            printf(" %02x", block[i * 16 + j]);
        putchar('\n');
    }
}

static void
test_block_function()
{
    static const uint8_t key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    static const uint8_t nonce[12] = {
        0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a,
        0x00, 0x00, 0x00, 0x00
    };
    static const uint32_t expected_state[16] = {
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
        0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
        0x00000001, 0x09000000, 0x4a000000, 0x00000000
    };
    static const uint8_t expected_output[64] = {
        0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15,
        0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
        0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03,
        0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
        0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09,
        0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
        0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9,
        0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e
    };

    CHACHA20_CTX x[1];
    uint8_t output[64];

    printf("2.3.2. Test Vector for the ChaCha20 Block Function\n\n");
    chacha20_init(x, key, nonce);
    printf("   Expected ChaCha state with the key setup:\n");
    print_state(expected_state);
    printf("   Result:\n");
    print_state(x->state);
    printf("   %s\n\n",
        memcmp(expected_state, x->state, sizeof(expected_state)) ?
        "ERROR" : "OK");

    chacha20_block(output, x->state);
    printf("   Expected ChaCha serialized state after calling "
           "block function:\n");
    print_block(expected_output, 64);
    printf("   Result:\n");
    print_block(output, 64);
    printf("   %s\n\n",
        memcmp(expected_output, output, sizeof(expected_output)) ?
        "ERROR" : "OK");
}

static void
test_chacha20_cipher(void)
{
    static const uint8_t key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    static const uint8_t nonce[12] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a,
        0x00, 0x00, 0x00, 0x00
    };
    static const char *message =
        "Ladies and Gentlemen of the class of '99: "
        "If I could offer you only one tip for the future, "
        "sunscreen would be it.";
    static const uint8_t expected[] = {
        0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80,
        0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81,
        0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2,
        0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b,
        0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab,
        0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57,
        0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab,
        0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8,
        0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61,
        0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e,
        0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06,
        0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36,
        0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6,
        0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
        0x87, 0x4d
    };

    CHACHA20_CTX x[1];
    uint8_t output[64*2];

    if (sizeof(expected) != strlen(message)) {
        fprintf(stderr, "Bad data for testing\n");
        exit(1);
    }
    printf("2.4.2.  Example and Test Vector for the ChaCha20 Cipher\n\n");
    chacha20_init(x, key, nonce);
    chacha20_encrypt(x, (uint8_t *)message, output, sizeof(expected));
    printf("   Expected ciphertext Sunscreen:\n");
    print_block(expected, sizeof(expected));
    printf("   Result:\n");
    print_block(output, sizeof(expected));
    printf("   %s\n\n",
        memcmp(expected, output, sizeof(expected)) ?
        "ERROR" : "OK");
}

static void
test_poly1305(void)
{
    static const uint8_t key[32] = {
        0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
        0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
        0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
        0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b
    };
    static const char message[] =
        "Cryptographic Forum Research Group";
    static const uint8_t expected[16] = {
        0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6,
        0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9
    };

    POLY1305_CTX x[1];
    uint8_t output[16];

    printf("2.5.2.  Poly1305 Example and Test Vector\n\n");
    poly1305_init(x, key);
    poly1305_update(x, (uint8_t *)message, strlen(message));
    poly1305_final(x, output);
    printf("   Expected tag:\n");
    print_block(expected, sizeof(expected));
    printf("   Result:\n");
    print_block(output, sizeof(expected));
    printf("   %s\n\n",
        memcmp(expected, output, sizeof(expected)) ?
        "ERROR" : "OK");
}

static void
test_rfc8439(void)
{
    static const uint8_t key[32] = {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
    };
    static const uint8_t nonce[12] = {
        0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43,
        0x44, 0x45, 0x46, 0x47
    };
    static const uint8_t aad[] = {
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3,
        0xc4, 0xc5, 0xc6, 0xc7
    };
    static const char message[] =
        "Ladies and Gentlemen of the class of '99: "
        "If I could offer you only one tip for the future, "
        "sunscreen would be it.";
    static const uint8_t expected[] = {
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb,
        0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
        0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe,
        0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
        0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12,
        0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
        0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
        0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
        0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c,
        0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
        0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94,
        0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
        0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d,
        0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
        0x61, 0x16, 0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09,
        0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60,
        0x06, 0x91
    };

    RFC8439_CTX x[1];
    uint8_t output[64*2 + 16];
    uint8_t plain[64*2];
    size_t len = strlen(message);

    printf("2.8.2.  Example and Test Vector for AEAD_CHACHA20_POLY1305\n\n");
    rfc8439_init(x, key, nonce, aad, sizeof(aad));
    rfc8439_encrypt(x, (uint8_t *)message, output, len);
    rfc8439_mac(x, output + len);
    printf("   Expected cipher text plus MAC:\n");
    print_block(expected, sizeof(expected));
    printf("   Result:\n");
    print_block(output, sizeof(expected));
    printf("   %s\n\n",
        memcmp(expected, output, sizeof(expected)) ?
        "ERROR" : "OK");

    rfc8439_init(x, key, nonce, aad, sizeof(aad));
    rfc8439_decrypt(x, output, plain, len);
    plain[len] = 0;
    printf("   Expected plain text:\n      %s\n", message);
    printf("   Result:\n      %s\n", plain);
    printf("   %s\n",
        memcmp(message, plain, len) ?
        "ERROR" : "OK");
    printf("   Authentification:\n   %s\n\n",
           rfc8439_verify(x, output + len) ?  "OK" : "ERROR");
}

static void
test_xchacha20()
{
    static const uint8_t key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    static const uint8_t nonce[24] = {
        0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a,
        0x00, 0x00, 0x00, 0x00, 0x31, 0x41, 0x59, 0x27,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
    };
    static const uint8_t expected_key[32] = {
        0x82, 0x41, 0x3b, 0x42, 0x27, 0xb2, 0x7b, 0xfe,
        0xd3, 0x0e, 0x42, 0x50, 0x8a, 0x87, 0x7d, 0x73,
        0xa0, 0xf9, 0xe4, 0xd5, 0x8a, 0x74, 0xa8, 0x53,
        0xc1, 0x2e, 0xc4, 0x13, 0x26, 0xd3, 0xec, 0xdc
    };
    static const uint8_t expected_nonce[12] = {
        0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x07, 0x08
    };

    uint8_t subkey[32], subnonce[12];

    printf("Test of XChaCha20\n\n");
    xchacha20_key(key, nonce, subkey, subnonce);
    printf("   Expected key:\n");
    print_block(expected_key, 32);
    printf("   Result:\n");
    print_block(subkey, 32);
    printf("   %s\n\n",
        memcmp(expected_key, subkey, 32) ?  "ERROR" : "OK");
    printf("   Expected nonce:\n");
    print_block(expected_nonce, 12);
    printf("   Result:\n");
    print_block(subnonce, 12);
    printf("   %s\n",
        memcmp(expected_nonce, subnonce, 12) ?  "ERROR" : "OK");
}

main()
{
    test_block_function();
    test_chacha20_cipher();
    test_poly1305();
    test_rfc8439();
    test_xchacha20();
}

#endif /* RFC8439_TEST */
