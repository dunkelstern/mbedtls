/**
 * Copyright (C) 2015-2016 Virgil Security Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * This file is part of extension to mbed TLS (https://tls.mbed.org)
 */

#ifndef VIRGIL_SECURITY_X25519_H
#define VIRGIL_SECURITY_X25519_H

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

/**
 * @brief Clear memory in a secure manner.
 * @note Implementation that should never be optimized out by the compiler.
 */
void x25519_zeroize(void *v, size_t n);

/**
 * \brief Hash context
 */
typedef struct x25519_sha512_context_t x25519_sha512_context_t;

/**
 * @brief Allocate hash context
 * @note Should be initilized and deallocated after usage.
 * @see x25519_sha512_init()
 * @see x25519_sha512_free()
 * @return Unainitialzed hash context.
 */
x25519_sha512_context_t* x25519_sha512_alloc(void);

/**
 * @brief Initialize hash context to be used for new message hashing.
 * @param ctx Hash context to be initialized.
 */
void x25519_sha512_init(x25519_sha512_context_t* ctx);

/**
 * @brief Deallocate hash context.
 * @param ctx Hash context to be deallocated.
 */
void x25519_sha512_free(x25519_sha512_context_t* ctx);

/**
 * @brief Process next message.
 * @param ctx Hash context.
 * @param msg Message to be added to the hash.
 * @param msg_len Message length.
 */
void x25519_sha512_update(x25519_sha512_context_t* ctx, const unsigned char* msg, size_t msg_len);

/**
 * @brief Finalize message processing.
 * @param ctx Hash context.
 * @param digest Hash result.
 */
void x25519_sha512_finish(x25519_sha512_context_t* ctx, unsigned char digest[64]);

/**
 * @brief Provide system hash function.
 * @param hash Destination buffer.
 * @param msg Message to be hashed.
 * @param msg_len Message length.
 */
void x25519_sha512(unsigned char* hash, const unsigned char* msg, size_t msg_len);

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

#endif /* VIRGIL_SECURITY_X25519_H */
