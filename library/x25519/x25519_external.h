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

/**
 * @file x25519_external.h
 * @brief Interface to the specific Ed25519 and Curve25510 ECP implemetation.
 *
 * Provides interface that MUST be implemented within specific Ed25519 and
 * Curve25510 ECP implemetation.
 */

#ifndef VIRGIL_SECURITY_EXTERNAL_X25519_H
#define VIRGIL_SECURITY_EXTERNAL_X25519_H

#include <stddef.h>

/**
 * @brief Perform sign with Ed25519 keys.
 * @param[out] s Signature.
 * @param[out] r Pseudo random number multiplied to the base point.
 * @param[in] msg Message to be signed.
 * @param[in] msg_len Message length.
 * @param[in] public_key Ed25519 public key.
 * @param[in] az Ed25519 private key + sign material(32 + 32)
 * @return 0 if success, non zero - otherwise.
 * @note signature = (r,s)
 */
int x25519_ext_edwards_sign(
        unsigned char s[32], unsigned char r[32],
        const unsigned char* msg, size_t msg_len,
        const unsigned char public_key[32], const unsigned char az[64]);

/**
 * @brief Perform sign verification with Ed25519 keys.
 * @param[out] s Signature.
 * @param[out] r Pseudo random number multiplied to the base point.
 * @param[in] msg Message to be signed.
 * @param[in] msg_len Message length.
 * @param[in] public_key Ed25519 public key.
 * @return 0 if success, non zero - otherwise.
 * @note signature = (r,s)
 */
int x25519_ext_edwards_verify(
        const unsigned char s[32], const unsigned char r[32],
        const unsigned char* msg, size_t msg_len,
        const unsigned char public_key[32]);

/**
 * @brief Derive public key from the private key.
 * @param[out] public_key Ed25519 public key.
 * @param[in] private_key Ed25519 private key.
 * @return 0 if success, non zero - otherwise.
 */
int x25519_ext_edwards_pubkey(unsigned char public_key[32], const unsigned char private_key[32]);

/**
 * @brief Convert Ed25519 public key to the birationally equivalent Curve25519 public key.
 * @param[out] curve_public_key Curve25519 public key.
 * @param[in] ed_public_key Ed25519 public key.
 * @return 0 if success, non zero - otherwise.
 */
int x25519_ext_edwards_to_montgomery_pubkey(unsigned char curve_public_key[32], const unsigned char ed_public_key[32]);

/**
 * @brief Convert Curve25519 public key to the birationally equivalent Ed25519 public key.
 * @param[out] ed_public_key Ed25519 public key.
 * @param[in] curve_public_key Curve25519 public key.
 * @return 0 if success, non zero - otherwise.
 */
int x25519_ext_montgomery_to_edwards_pubkey(unsigned char ed_public_key[32], const unsigned char curve_public_key[32]);

/**
 * @brief Perform ECDH algorithm with Curve25519 keys.
 * @param[out] shared_secret Derived shared key.
 * @param[in] public_key Curve25519 public key.
 * @param[in] private_key Curve25519 private key.
 * @return 0 if success, non zero - otherwise.
 */
int x25519_ext_montgomery_key_exchange(
        unsigned char shared_secret[32], const unsigned char public_key[32], const unsigned char private_key[32]);

#endif //VIRGIL_SECURITY_EXTERNAL_X25519_H
