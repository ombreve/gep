#ifndef RFC8439_H
#define RFC8439_H

#include <stdint.h>
#include <stddef.h>

/**
 ** Chacha20 with 256-bit key, 96-bit nonce and 32-bit block count.
 **/

typedef struct {
    uint32_t state[16];
    uint8_t output[64];
    size_t idx;
} CHACHA20_CTX;

/* Initialize a chacha20 context with a KEY and a NONCE. */
void chacha20_init(CHACHA20_CTX *ctx,
                   const uint8_t key[32], const uint8_t nonce[12]);

/* Encrypt N bytes from message M to C.
 * This function can be called mutiple times to encrypt messages by chunks.
 * Decryption is done by exchanging M and C. */
void chacha20_encrypt(CHACHA20_CTX *ctx,
                      const uint8_t *m, uint8_t *c, size_t n);


/**
 ** Poly1305 128-bit tag from a 256-bit key and a message.
 **/

typedef struct {
    uint32_t r[5];
    uint32_t h[5];
    uint32_t pad[4];
    uint32_t leftover;
    uint8_t buffer[16];
    uint8_t final;
} POLY1305_CTX;

/* Initialize a poly1305 context with a KEY. */
void poly1305_init(POLY1305_CTX *ctx, const uint8_t key[32]);

/* Update a poly1305 context with message M of length N. */
void poly1305_update(POLY1305_CTX *, const uint8_t *m, size_t n);

/* Compute the final poly1305 TAG. */
void poly1305_final(POLY1305_CTX *ctx, uint8_t tag[16]);

/* Return a non null value if TAG1 and TAG2 matches bit to bit.
 * This function runs in constant time. */
int poly1305_verify(const uint8_t tag1[16], const uint8_t tag2[16]);


/**
 ** AEAD-Chacha20-Poly1305 authenticated encryption with additional data.
 **/

typedef struct {
    CHACHA20_CTX   c[1];
    POLY1305_CTX p[1];
    size_t aad_sz;
    size_t c_sz;
} RFC8439_CTX;

#define RFC8439_MAC_SIZE 16

/* Initialize a rfc8439 context with a KEY, a NONCE and N bytes of additional
 * authenticated data. */
void rfc8439_init(RFC8439_CTX *ctx,
                  const uint8_t key[32], const uint8_t nonce[12],
                  const uint8_t *aad, size_t n);

/* Encrypt N bytes from message M to C.
 * This function can be called mutiple times to encrypt messages by chunks. */
void rfc8439_encrypt(RFC8439_CTX *ctx,
                     const uint8_t *m, uint8_t *c, size_t n);

/* Encode a message authentification code in MAC.
 * MAC should point to the end of the previously encrypted message. */
void rfc8439_mac(RFC8439_CTX *ctx, uint8_t mac[16]);

/* Decrypt N bytes from message C to M.
 * This function can be called mutiple times to decrypt messages by chunks. */
void rfc8439_decrypt(RFC8439_CTX *x,
                     const uint8_t *c, uint8_t *m, size_t n);

/* Return a non null value if the message authentification code MAC is correct.
 * MAC should point to the end of the previously decrypted message. */
int rfc8439_verify(RFC8439_CTX *ctx, uint8_t mac[16]);

#endif /* RFC8439_H */
