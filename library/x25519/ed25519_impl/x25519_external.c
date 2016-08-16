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
 *
 * Low level implementation was taken from Orson Peters library,
 *     see https://github.com/orlp/ed25519 and license.txt file
 */

#include <string.h>

#include "../x25519.h"
#include "../x25519_external.h"

#include "fe.h"
#include "ge.h"
#include "sc.h"


int x25519_ext_edwards_pubkey(unsigned char public_key[32], const unsigned char private_key[32]) {
    ge_p3 A;
    ge_scalarmult_base(&A, private_key);
    ge_p3_tobytes(public_key, &A);
    return 0;
}

/*
 * due to CodesInChaos: montgomeryX = (edwardsY + 1)*inverse(1 - edwardsY) mod p
 */
int x25519_ext_edwards_to_montgomery_pubkey(unsigned char curve_public_key[32], const unsigned char ed_public_key[32]) {
    fe x1, tmp0, tmp1;

    fe_frombytes(x1, ed_public_key);
    fe_1(tmp1);
    fe_add(tmp0, x1, tmp1);
    fe_sub(tmp1, tmp1, x1);
    fe_invert(tmp1, tmp1);
    fe_mul(x1, tmp0, tmp1);

    fe_tobytes(curve_public_key, x1);

    return 0;
}

/*
 * edwardsY = (montgomeryX - 1)*inverse(montgomeryX + 1) mod p
 */
int x25519_ext_montgomery_to_edwards_pubkey(unsigned char ed_public_key[32], const unsigned char curve_public_key[32]) {
    fe mont_x, mont_x_minus_one, mont_x_plus_one, inv_mont_x_plus_one, one, ed_y;

    fe_frombytes(mont_x, curve_public_key);
    fe_1(one);
    fe_sub(mont_x_minus_one, mont_x, one);
    fe_add(mont_x_plus_one, mont_x, one);
    fe_invert(inv_mont_x_plus_one, mont_x_plus_one);
    fe_mul(ed_y, mont_x_minus_one, inv_mont_x_plus_one);
    fe_tobytes(ed_public_key, ed_y);

    return 0;
}

int x25519_ext_edwards_sign(
        unsigned char s[32], unsigned char r[32],
        const unsigned char* msg, size_t msg_len,
        const unsigned char public_key[32], const unsigned char az[64]) {

    x25519_sha512_context_t* hash;
    unsigned char hram[64];
    unsigned char nonce[64];
    unsigned char signature[64];
    ge_p3 R;

    hash = x25519_sha512_alloc();
    if (hash == NULL) {
        return 1;
    }

    x25519_sha512_init(hash);
    x25519_sha512_update(hash, az + 32, 32);
    x25519_sha512_update(hash, msg, msg_len);
    x25519_sha512_finish(hash, nonce);

    sc_reduce(nonce);
    ge_scalarmult_base(&R, nonce);
    ge_p3_tobytes(signature, &R);

    memmove(signature + 32, public_key, 32);

    x25519_sha512_init(hash);
    x25519_sha512_update(hash, signature, sizeof(signature));
    x25519_sha512_update(hash, msg, msg_len);
    x25519_sha512_finish(hash, hram);

    sc_reduce(hram);
    sc_muladd(signature + 32, hram, az, nonce); // (R, S)

    memmove(r, signature, 32);
    memmove(s, signature + 32, 32);

    x25519_zeroize(nonce, sizeof(nonce));
    x25519_sha512_free(hash);

    return 0;
}

static int consttime_equal(const unsigned char* x, const unsigned char* y) {
    unsigned char r = 0;

    r = x[0] ^ y[0];
#define F(i) r |= x[i] ^ y[i]
    F(1);
    F(2);
    F(3);
    F(4);
    F(5);
    F(6);
    F(7);
    F(8);
    F(9);
    F(10);
    F(11);
    F(12);
    F(13);
    F(14);
    F(15);
    F(16);
    F(17);
    F(18);
    F(19);
    F(20);
    F(21);
    F(22);
    F(23);
    F(24);
    F(25);
    F(26);
    F(27);
    F(28);
    F(29);
    F(30);
    F(31);
#undef F

    return !r;
}

int x25519_ext_edwards_verify(
        const unsigned char s[32], const unsigned char r[32],
        const unsigned char* msg, size_t msg_len,
        const unsigned char public_key[32]) {

    x25519_sha512_context_t* hash;
    unsigned char h[64];
    unsigned char checker[32];
    unsigned char signature[64];
    ge_p3 A;
    ge_p2 R;


    memmove(signature, r, 32);
    memmove(signature + 32, s, 32);

    if (signature[63] & 224) {
        return 1;
    }

    if (ge_frombytes_negate_vartime(&A, public_key) != 0) {
        return 1;
    }

    hash = x25519_sha512_alloc();
    if (hash == NULL) {
        return -1;
    }

    x25519_sha512_init(hash);
    x25519_sha512_update(hash, signature, 32);
    x25519_sha512_update(hash, public_key, 32);
    x25519_sha512_update(hash, msg, msg_len);
    x25519_sha512_finish(hash, h);

    sc_reduce(h);
    ge_double_scalarmult_vartime(&R, h, &A, signature + 32);
    ge_tobytes(checker, &R);

    if (!consttime_equal(checker, signature)) {
        return 2;
    }

    return 0;
}

int x25519_ext_montgomery_key_exchange(
        unsigned char shared_secret[32], const unsigned char public_key[32], const unsigned char private_key[32]) {

    fe x1;
    fe x2;
    fe z2;
    fe x3;
    fe z3;
    fe tmp0;
    fe tmp1;

    int pos;
    unsigned int swap;
    unsigned int b;

    fe_frombytes(x1, public_key);

    fe_1(x2);
    fe_0(z2);
    fe_copy(x3, x1);
    fe_1(z3);

    swap = 0;
    for (pos = 254; pos >= 0; --pos) {
        b = private_key[pos / 8] >> (pos & 7);
        b &= 1;
        swap ^= b;
        fe_cswap(x2, x3, swap);
        fe_cswap(z2, z3, swap);
        swap = b;

        /* from montgomery.h */
        fe_sub(tmp0, x3, z3);
        fe_sub(tmp1, x2, z2);
        fe_add(x2, x2, z2);
        fe_add(z2, x3, z3);
        fe_mul(z3, tmp0, x2);
        fe_mul(z2, z2, tmp1);
        fe_sq(tmp0, tmp1);
        fe_sq(tmp1, x2);
        fe_add(x3, z3, z2);
        fe_sub(z2, z3, z2);
        fe_mul(x2, tmp1, tmp0);
        fe_sub(tmp1, tmp1, tmp0);
        fe_sq(z2, z2);
        fe_mul121666(z3, tmp1);
        fe_sq(x3, x3);
        fe_add(tmp0, tmp0, z3);
        fe_mul(z3, x1, z2);
        fe_mul(z2, tmp1, tmp0);
    }

    fe_cswap(x2, x3, swap);
    fe_cswap(z2, z3, swap);

    fe_invert(z2, z2);
    fe_mul(x2, x2, z2);
    fe_tobytes(shared_secret, x2);

    return 0;
}
