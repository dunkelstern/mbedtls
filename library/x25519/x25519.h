
#ifndef CURVE_25519_H
#define CURVE_25519_H

#include <stddef.h>

#define X25519_LEN 32

/**
 * @brief Type for Curve25519 or Ed25519 public key.
 */
typedef struct {
    unsigned char p[X25519_LEN];
    size_t len;
} x25519_public_key_t;

/**
 * @brief Type for Curve25519 private key.
 */
typedef struct {
    unsigned char p[X25519_LEN];
    size_t len;
} x25519_private_key_t;

/**
 * @brief Type for Ed25519 secret key.
 */
typedef struct {
    unsigned char p[X25519_LEN];
    size_t len;
} x25519_secret_key_t;

/**
 * @brief Type for shared key - result of ECDH algorithm.
 */
typedef struct {
    unsigned char p[X25519_LEN];
    size_t len;
} x25519_shared_key_t;

/**
 * @brief Type for signature - result of ECDSA algorithm.
 */
typedef struct {
    union {
        struct {
            unsigned char p[X25519_LEN << 1];
        };
        struct {
            unsigned char s[X25519_LEN];
            unsigned char r[X25519_LEN];
        };
    };
    size_t len;
    size_t s_len;
    size_t r_len;
} x25519_signature_t;

#undef X25519_LEN

/**
 * @brief Initialize structure internal state.
 * @note Correspond *_free function SHOULD be used.
 */
void x25519_public_key_init(x25519_public_key_t* public_key);

/**
 * @brief Initialize structure internal state.
 * @note Correspond *_free function SHOULD be used.
 */
void x25519_private_key_init(x25519_private_key_t* private_key);

/**
 * @brief Initialize structure internal state.
 * @note Correspond *_free function SHOULD be used.
 */
void x25519_signature_init(x25519_signature_t* signature);

/**
 * @brief Initialize structure internal state.
 * @note Correspond *_free function SHOULD be used.
 */
void x25519_secret_key_init(x25519_secret_key_t* secret_key);

/**
 * @brief Initialize structure internal state.
 * @note Correspond *_free function SHOULD be used.
 */
void x25519_shared_key_init(x25519_shared_key_t* shared_key);

/**
 * @brief Clear structure internal state.
 */
void x25519_public_key_free(x25519_public_key_t* public_key);

/**
 * @brief Clear structure internal state.
 */
void x25519_private_key_free(x25519_private_key_t* private_key);

/**
 * @brief Clear structure internal state.
 */
void x25519_signature_free(x25519_signature_t* signature);

/**
 * @brief Clear structure internal state.
 */
void x25519_secret_key_free(x25519_secret_key_t* secret_key);

/**
 * @brief Clear structure internal state.
 */
void x25519_shared_key_free(x25519_shared_key_t* shared_key);

/*
 * @breif Clear memory in a secure manner.
 * @note Implementation that should never be optimized out by the compiler.
 */
void x25519_zeroize(void *v, size_t n);

/**
 * @brief Derive public key from the private key.
 *
 * Use ESDSA to derive signature
 *
 * @param public_key - Curve25519 public key (unsigned binary data, low endian, 32 byte)
 * @param private_key - Curve25519 private key (unsigned binary data, low endian, 32 byte)
 * @return 0 on success
 */
int x25519_montgomery_getpub(x25519_public_key_t* public_key, const x25519_private_key_t* private_key);

/**
 * @brief Create signature based on the Curve25519 montgomery curve
 *
 * Use ESDSA to derive signature
 *
 * @param signature - derived signature (unsigned binary data, low endian, 64 byte)
 * @param private_key - Curve25519 private key (unsigned binary data, low endian, 32 byte)
 * @param msg - message to be signed
 * @param msg_len - message length
 * @return 0 on success
 */
int x25519_montgomery_sign(
        x25519_signature_t* signature,
        const x25519_private_key_t* private_key,
        const unsigned char* msg, const unsigned long msg_len);

/**
 * @brief Verify signature based on the Curve25519 montgomery curve
 *
 * Use ESDSA to verify signature
 *
 * @param signature - derived signature (unsigned binary data, low endian, 64 byte)
 * @param public_key - Curve25519 public key (unsigned binary data, low endian, 32 byte)
 * @param msg - message to be verified
 * @param msg_len - message length
 * @return 1 on success
 */
int x25519_montgomery_verify(
        const x25519_signature_t* signature,
        const x25519_public_key_t* public_key,
        const unsigned char* msg, const unsigned long msg_len);

/**
 * @brief Compute shared secret based on the Curve25519 montgomery curve
 *
 * @param shared_key - computed shared secret (unsigned binary data, low endian, 32 byte)
 * @param public_key - Curve25519 public key from other party (unsigned binary data, low endian, 32 byte)
 * @param private_key - Curve25519 private key (unsigned binary data, low endian, 32 byte)
 * @return 0 on success
 */
int x25519_montgomery_key_exchange(
        x25519_shared_key_t* shared_key,
        const x25519_public_key_t* public_key,
        const x25519_private_key_t* private_key);

/**
 * @brief Derive public key from the private key.
 *
 * Use ESDSA to derive signature
 *
 * @param public_key - Ed25519 public key (unsigned binary data, low endian, 32 byte)
 * @param secret_key - Ed25519 secret key (unsigned binary data, low endian, 32 byte)
 * @return 0 on success
 */
int x25519_edwards_getpub(x25519_public_key_t* public_key, const x25519_secret_key_t* secret_key);

/**
 * @brief Compute shared secret based on the Ed25519 edwards curve
 *
 * @param shared_key - computed shared secret (unsigned binary data, low endian, 32 byte)
 * @param public_key - Ed25519 public key from other party (unsigned binary data, low endian, 32 byte)
 * @param secret_key - Ed25519 secret key (unsigned binary data, low endian, 32 byte)
 * @return 0 on success
 */
int x25519_edwards_key_exchange(
        x25519_shared_key_t* shared_key,
        const x25519_public_key_t* public_key,
        const x25519_secret_key_t* secret_key);

/**
 * @brief Create signature based on the Ed25519 edwards curve
 *
 * Use ESDSA to derive signature
 *
 * @param signature - derived signature (unsigned binary data, low endian, 64 byte)
 * @param secret_key - Ed25519 secret key (unsigned binary data, low endian, 32 byte)
 * @param msg - message to be signed
 * @param msg_len - message length
 * @return 0 on success
 */
int x25519_edwards_sign(
        x25519_signature_t* signature,
        const x25519_secret_key_t* secret_key,
        const unsigned char* msg, const unsigned long msg_len);


/**
 * @brief Verify signature based on the Ed25519 edwards curve
 *
 * Use ESDSA to verify signature
 *
 * @param signature - derived signature (unsigned binary data, low endian, 64 byte)
 * @param public_key - Ed25519 public key (unsigned binary data, low endian, 32 byte)
 * @param msg - message to be verified
 * @param msg_len - message length
 * @return 1 on success
 */
int x25519_edwards_verify(
        const x25519_signature_t* signature,
        const x25519_public_key_t* public_key,
        const unsigned char* msg, const unsigned long msg_len);

#endif /* CURVE_25519_H */
