#if !defined(MBEDTLS_CONFIG_FILE)

#include "mbedtls/config.h"

#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_X25519_C)

#include <string.h>
#include <stdlib.h>

#if defined(MBEDTLS_SHA512_C)

#include <mbedtls/sha512.h>

#endif

#include "mbedtls/x25519.h"
#include "mbedtls/x25519_external.h"


/*
 * Low level API
 */
static int mbedtls_x25519_ext_montgomery_pubkey(unsigned char* public_key, const unsigned char* private_key);

static int mbedtls_x25519_ext_montgomery_az(unsigned char* az, const unsigned char* private_key);

static int mbedtls_x25519_ext_edwards_az(unsigned char* az, const unsigned char* secret_key);

static int mbedtls_x25519_ext_edwards_key(unsigned char* private_key, const unsigned char* secret_key);

/*
 * This method is taken from MbedTlS library.
 */
void mbedtls_x25519_zeroize(void* v, size_t n) {
    volatile unsigned char* p = v;
    while (n--) { *p++ = 0; }
}

void mbedtls_x25519_public_key_init(mbedtls_x25519_public_key_t* public_key) {
    public_key->len = sizeof(public_key->p);
    memset(public_key->p, 0x00, public_key->len);
}

void mbedtls_x25519_private_key_init(mbedtls_x25519_private_key_t* private_key) {
    private_key->len = sizeof(private_key->p);
    memset(private_key->p, 0x00, private_key->len);
}

void mbedtls_x25519_signature_init(mbedtls_x25519_signature_t* signature) {
    signature->len = sizeof(signature->p);
    signature->s_len = sizeof(signature->s);
    signature->r_len = sizeof(signature->r);
    memset(signature->p, 0x00, signature->len);
}

void mbedtls_x25519_secret_key_init(mbedtls_x25519_secret_key_t* secret_key) {
    secret_key->len = sizeof(secret_key->p);
    memset(secret_key->p, 0x00, secret_key->len);
}

void mbedtls_x25519_shared_key_init(mbedtls_x25519_shared_key_t* shared_key) {
    shared_key->len = sizeof(shared_key->p);
    memset(shared_key->p, 0x00, shared_key->len);
}

void mbedtls_x25519_public_key_free(mbedtls_x25519_public_key_t* public_key) {
    (void) public_key;
}

void mbedtls_x25519_private_key_free(mbedtls_x25519_private_key_t* private_key) {
    mbedtls_x25519_zeroize(private_key->p, private_key->len);
}

void mbedtls_x25519_signature_free(mbedtls_x25519_signature_t* signature) {
    (void) signature;
}

void mbedtls_x25519_secret_key_free(mbedtls_x25519_secret_key_t* secret_key) {
    mbedtls_x25519_zeroize(secret_key->p, secret_key->len);
}

void mbedtls_x25519_shared_key_free(mbedtls_x25519_shared_key_t* shared_key) {
    mbedtls_x25519_zeroize(shared_key->p, shared_key->len);
}

struct mbedtls_x25519_sha512_context_t {
    mbedtls_sha512_context sha512_ctx;
};

mbedtls_x25519_sha512_context_t* mbedtls_x25519_sha512_alloc(void) {
    mbedtls_x25519_sha512_context_t* ctx = calloc(1, sizeof(mbedtls_x25519_sha512_context_t));
    if (ctx) {
        mbedtls_sha512_init(&ctx->sha512_ctx);
    }
    return ctx;
}

void mbedtls_x25519_sha512_init(mbedtls_x25519_sha512_context_t* ctx) {
    mbedtls_sha512_starts(&ctx->sha512_ctx, 0);
}

void mbedtls_x25519_sha512_free(mbedtls_x25519_sha512_context_t* ctx) {
    mbedtls_sha512_free(&ctx->sha512_ctx);
    free(ctx);
}

void mbedtls_x25519_sha512_update(mbedtls_x25519_sha512_context_t* ctx, const unsigned char* msg, size_t msg_len) {
    mbedtls_sha512_update(&ctx->sha512_ctx, msg, msg_len);
}

void mbedtls_x25519_sha512_finish(mbedtls_x25519_sha512_context_t* ctx, unsigned char digest[64]) {
    mbedtls_sha512_finish(&ctx->sha512_ctx, digest);
}

void mbedtls_x25519_sha512(unsigned char* hash, const unsigned char* msg, size_t msg_len) {
    mbedtls_sha512(msg, msg_len, hash, 0);
}

int mbedtls_x25519_montgomery_getpub(
        mbedtls_x25519_public_key_t* public_key, const mbedtls_x25519_private_key_t* private_key) {
    return mbedtls_x25519_ext_montgomery_pubkey(public_key->p, private_key->p);
}

int mbedtls_x25519_montgomery_sign(
        mbedtls_x25519_signature_t* signature,
        const mbedtls_x25519_private_key_t* private_key,
        const unsigned char* msg, const unsigned long msg_len) {

    unsigned char ed_public_key[32];
    unsigned char az[64];
    unsigned char sign_bit = 0;

    mbedtls_x25519_ext_montgomery_az(az, private_key->p);
    mbedtls_x25519_ext_edwards_pubkey(ed_public_key, az);

    sign_bit = ed_public_key[31] & (unsigned char) 0x80;

    mbedtls_x25519_ext_edwards_sign(signature->s, signature->r, msg, msg_len, ed_public_key, az);

    signature->s[31] &= 0x7F;  // bit should be zero already, but just in case
    signature->s[31] |= sign_bit;

    mbedtls_x25519_zeroize(az, sizeof(az));
    return 0;
}

int mbedtls_x25519_montgomery_verify(
        const mbedtls_x25519_signature_t* signature,
        const mbedtls_x25519_public_key_t* public_key,
        const unsigned char* msg, const unsigned long msg_len) {
    unsigned char ed_public_key[32];

    unsigned char fixed_s[32];

    mbedtls_x25519_ext_montgomery_to_edwards_pubkey(ed_public_key, public_key->p);
    ed_public_key[31] |= (signature->s[31] & 0x80);

    memmove(fixed_s, signature->s, signature->s_len);

    fixed_s[31] &= 0x7F;

    return mbedtls_x25519_ext_edwards_verify(fixed_s, signature->r, msg, msg_len, ed_public_key);
}

int mbedtls_x25519_montgomery_key_exchange(
        mbedtls_x25519_shared_key_t* shared_key,
        const mbedtls_x25519_public_key_t* public_key,
        const mbedtls_x25519_private_key_t* private_key) {

    return mbedtls_x25519_ext_montgomery_key_exchange(shared_key->p, public_key->p, private_key->p);
}

int
mbedtls_x25519_edwards_getpub(mbedtls_x25519_public_key_t* public_key, const mbedtls_x25519_secret_key_t* secret_key) {

    unsigned char private_key[32];

    (void) mbedtls_x25519_ext_edwards_key(private_key, secret_key->p);
    (void) mbedtls_x25519_ext_edwards_pubkey(public_key->p, private_key);

    mbedtls_x25519_zeroize(private_key, sizeof(private_key));
    return 0;
}


int mbedtls_x25519_edwards_key_exchange(
        mbedtls_x25519_shared_key_t* shared_key,
        const mbedtls_x25519_public_key_t* public_key,
        const mbedtls_x25519_secret_key_t* secret_key) {

    unsigned char curve_public_key[32];
    unsigned char curve_private_key[32];

    (void) mbedtls_x25519_ext_edwards_key(curve_private_key, secret_key->p);
    (void) mbedtls_x25519_ext_edwards_to_montgomery_pubkey(curve_public_key, public_key->p);
    (void) mbedtls_x25519_ext_montgomery_key_exchange(shared_key->p, curve_public_key, curve_private_key);

    mbedtls_x25519_zeroize(curve_private_key, sizeof(curve_private_key));
    return 0;
}

int mbedtls_x25519_edwards_sign(
        mbedtls_x25519_signature_t* signature,
        const mbedtls_x25519_secret_key_t* secret_key,
        const unsigned char* msg, const unsigned long msg_len) {

    unsigned char public_key[32];
    unsigned char az[64];


    (void) mbedtls_x25519_ext_edwards_az(az, secret_key->p);
    (void) mbedtls_x25519_ext_edwards_pubkey(public_key, az);
    (void) mbedtls_x25519_ext_edwards_sign(signature->s, signature->r, msg, msg_len, public_key, az);

    mbedtls_x25519_zeroize(az, sizeof(az));
    return 0;
}


int mbedtls_x25519_edwards_verify(
        const mbedtls_x25519_signature_t* signature,
        const mbedtls_x25519_public_key_t* public_key,
        const unsigned char* msg, const unsigned long msg_len) {

    return mbedtls_x25519_ext_edwards_verify(signature->s, signature->r, msg, msg_len, public_key->p);
}

/*
 * Low Level API implementation
 */

int mbedtls_x25519_ext_montgomery_pubkey(unsigned char* public_key, const unsigned char* private_key) {
    (void) mbedtls_x25519_ext_edwards_pubkey(public_key, private_key);
    (void) mbedtls_x25519_ext_edwards_to_montgomery_pubkey(public_key, public_key);
    return 0;
}

int mbedtls_x25519_ext_montgomery_az(unsigned char* az, const unsigned char* private_key) {
    mbedtls_x25519_sha512(az, private_key, 32); // H(k) = (h0, h1, . . . , h2b−1)
    memmove(az, private_key, 32); // Restore k, and leave (hb, ..., hb-1) as is
    return 0;
}

int mbedtls_x25519_ext_edwards_az(unsigned char* az, const unsigned char* secret_key) {
    mbedtls_x25519_sha512(az, secret_key, 32);
    az[0] &= 248;
    az[31] &= 63;
    az[31] |= 64;
    return 0;
}

int mbedtls_x25519_ext_edwards_key(unsigned char* private_key, const unsigned char* secret_key) {
    unsigned char az[64];
    (void) mbedtls_x25519_ext_edwards_az(az, secret_key);
    memmove(private_key, az, 32);
    mbedtls_x25519_zeroize(az, sizeof(az));
    return 0;
}

#endif /* MBEDTLS_X25519_C */
