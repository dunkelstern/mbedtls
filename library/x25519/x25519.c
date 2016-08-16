#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_X25519_C)

#include <string.h>

#include "x25519.h"

/*
 * This method is taken from MbedTlS library.
 */
void x25519_zeroize(void *v, size_t n) {
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
    x25519_zeroize(private_key->p, private_key->len);
}

void x25519_signature_free(x25519_signature_t* signature) {
    (void)signature;
}

void x25519_secret_key_free(x25519_secret_key_t* secret_key) {
    x25519_zeroize(secret_key->p, secret_key->len);
}

void x25519_shared_key_free(x25519_shared_key_t* shared_key) {
    x25519_zeroize(shared_key->p, shared_key->len);
}

#endif /* MBEDTLS_X25519_C */
