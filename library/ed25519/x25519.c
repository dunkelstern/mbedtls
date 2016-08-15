#include "config.h"

#if defined(ED25519_ENABLED)
#include <string.h>

#include "fe.h"
#include "ge.h"
#include "sha512.h"
#include "ed25519.h"
#include "x25519.h"

/*
 * Implementation that should never be optimized out by the compiler.
 * This method is taken from MbedTlS library.
 */
static void zeroize(void *v, size_t n) {
    volatile unsigned char *p = v; while(n--) *p++ = 0;
}

void x25519_public_key_init(x25519_public_key_t* public_key) {
    public_key->len = sizeof(public_key->p);
    memset(public_key->p, 0x00, public_key->len);
}

void x25519_private_key_init(x25519_private_key_t* private_key) {
    private_key->len = sizeof(private_key->p);
    memset(private_key->p, 0x00, private_key->len);
}

void x25519_signature_init(x25519_signature_t* signature) {
    signature->len = sizeof(signature->p);
    signature->s_len = sizeof(signature->s);
    signature->r_len = sizeof(signature->r);
    memset(signature->p, 0x00, signature->len);
}

void x25519_secret_key_init(x25519_secret_key_t* secret_key) {
    secret_key->len = sizeof(secret_key->p);
    memset(secret_key->p, 0x00, secret_key->len);
}

void x25519_shared_key_init(x25519_shared_key_t* shared_key) {
    shared_key->len = sizeof(shared_key->p);
    memset(shared_key->p, 0x00, shared_key->len);
}

void x25519_public_key_free(x25519_public_key_t* public_key) {
    (void)public_key;
}

void x25519_private_key_free(x25519_private_key_t* private_key) {
    zeroize(private_key->p, private_key->len);
}

void x25519_signature_free(x25519_signature_t* signature) {
    (void)signature;
}

void x25519_secret_key_free(x25519_secret_key_t* secret_key) {
    zeroize(secret_key->p, secret_key->len);
}

void x25519_shared_key_free(x25519_shared_key_t* shared_key) {
    zeroize(shared_key->p, shared_key->len);
}

int x25519_montgomery_getpub(x25519_public_key_t* public_key, const x25519_private_key_t* private_key)
{
    ge_p3 A;
    fe x1, tmp0, tmp1;
    ge_scalarmult_base(&A, private_key->p);
    ge_p3_tobytes(public_key->p, &A);

    /* convert edwards to montgomery */
    /* due to CodesInChaos: montgomeryX = (edwardsY + 1)*inverse(1 - edwardsY) mod p */
    fe_frombytes(x1, public_key->p);
    fe_1(tmp1);
    fe_add(tmp0, x1, tmp1);
    fe_sub(tmp1, tmp1, x1);
    fe_invert(tmp1, tmp1);
    fe_mul(x1, tmp0, tmp1);

    fe_tobytes(public_key->p, x1);
    return 0;
}

int x25519_montgomery_sign(
        x25519_signature_t* signature,
        const x25519_private_key_t* private_key,
        const unsigned char* msg, const unsigned long msg_len)
{
    ge_p3 ed_public_key_point;
    unsigned char ed_public_key[32];
    unsigned char ed_private_key[64];
    unsigned char sign_bit = 0;

    /*
     * Step 1. Get Ed25519 private key from the Curve25519 private key
     */
    sha512(private_key->p, 32, ed_private_key); // H(k) = (h0, h1, . . . , h2b−1)
    memmove(ed_private_key, private_key, 32); // Restore k, and leave (hb, ..., hb-1) as is

    /*
     * Step 2. Get Ed25519 public key from the Curve25519 private key
     */
    ge_scalarmult_base(&ed_public_key_point, private_key->p);
    ge_p3_tobytes(ed_public_key, &ed_public_key_point);
    sign_bit = ed_public_key[31] & 0x80;

    /*
     * Step 3. Use EdDSA to derive signature
     */
    ed25519_sign(signature->p, msg, msg_len, ed_public_key, ed_private_key);

    /*
     * Step 4. Encode the sign bit into signature (in unused high bit of S)
     */
     signature->p[63] &= 0x7F;  // bit should be zero already, but just in case
     signature->p[63] |= sign_bit;

    zeroize(ed_private_key, 64);
    return 0;
}

int x25519_montgomery_verify(
        const x25519_signature_t* signature,
        const x25519_public_key_t* public_key,
        const unsigned char* msg, const unsigned long msg_len)
{
    fe mont_x, mont_x_minus_one, mont_x_plus_one, inv_mont_x_plus_one;
    fe one;
    fe ed_y;
    unsigned char ed_public_key_point[32];
    unsigned char verify_buf[64]; // working buffer

    /*
     * Step 1. Convert the Curve25519 public key into an Ed25519 public key
     */
    fe_frombytes(mont_x, public_key->p);
    fe_1(one);
    fe_sub(mont_x_minus_one, mont_x, one);
    fe_add(mont_x_plus_one, mont_x, one);
    fe_invert(inv_mont_x_plus_one, mont_x_plus_one);
    fe_mul(ed_y, mont_x_minus_one, inv_mont_x_plus_one);
    fe_tobytes(ed_public_key_point, ed_y);

    /*
     * Step 2. Copy the sign bit, and remove it from signature
     */
    ed_public_key_point[31] |= (signature->p[63] & 0x80);
    memmove(verify_buf, signature, 64);
    verify_buf[63] &= 0x7F;

    /*
     * Step 3. Use EdDSA to verify signature
     */
    return ed25519_verify(verify_buf, msg, msg_len, ed_public_key_point);
}

int x25519_montgomery_key_exchange(
        x25519_shared_key_t* shared_key,
        const x25519_public_key_t* public_key,
        const x25519_private_key_t* private_key)
{
    fe mont_x, mont_x_minus_one, mont_x_plus_one, inv_mont_x_plus_one;
    fe one;
    fe ed_y;
    unsigned char ed_public_key[32];

    /*
     * Step 1. Convert the Curve25519 public key into an Ed25519 public key
     */
    fe_frombytes(mont_x, public_key->p);
    fe_1(one);
    fe_sub(mont_x_minus_one, mont_x, one);
    fe_add(mont_x_plus_one, mont_x, one);
    fe_invert(inv_mont_x_plus_one, mont_x_plus_one);
    fe_mul(ed_y, mont_x_minus_one, inv_mont_x_plus_one);
    fe_tobytes(ed_public_key, ed_y);

    /*
     * Step 2. Compute shared secret
     */
    ed25519_key_exchange(shared_key->p, ed_public_key, private_key->p);
    return 0;
}

int x25519_edwards_getpub(x25519_public_key_t* public_key, const x25519_secret_key_t* secret_key) {
    unsigned char private_key[64];
    ed25519_create_keypair(public_key->p, private_key, secret_key->p);
    zeroize(private_key, sizeof(private_key));
    return 0;
}


int x25519_edwards_key_exchange(
        x25519_shared_key_t* shared_key,
        const x25519_public_key_t* public_key,
        const x25519_secret_key_t* secret_key) {

    unsigned char az[64];
    sha512(secret_key->p, 32, az);
    az[0] &= 248;
    az[31] &= 63;
    az[31] |= 64;

    ed25519_key_exchange(shared_key->p, public_key->p, az);
    zeroize(az, sizeof(az));
    return 0;
}

int x25519_edwards_sign(
        x25519_signature_t* signature,
        const x25519_secret_key_t* secret_key,
        const unsigned char* msg, const unsigned long msg_len) {

    unsigned char public_key[32];
    unsigned char private_key[64];

    ed25519_create_keypair(public_key, private_key, secret_key->p);
    libsodium_ed25519_sign(signature->p, msg, msg_len, private_key);
    return 0;
}


int x25519_edwards_verify(
        const x25519_signature_t* signature,
        const x25519_public_key_t* public_key,
        const unsigned char* msg, const unsigned long msg_len) {
    return ed25519_verify(signature->p, msg, msg_len, public_key->p);
}

#endif /* ED25519_ENABLED */
