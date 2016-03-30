
#ifndef CURVE_25519_H
#define CURVE_25519_H

/**
 * @brief Create signature based on the Curve25519 montgomery curve
 *
 * Use ESDSA to derive signature
 *
 * @param signature[64] - derived signature (unsigned binary data, low endian)
 * @param private_key[32] - Curve25519 private key (unsigned binary data, low endian)
 * @param msg [description]
 * @param msg_len [description]
 * @return 0 on success
 */
int curve25519_sign(unsigned char* signature,
                    const unsigned char* private_key,
                    const unsigned char* msg, const unsigned long msg_len);

/**
 * @brief Verify signature based on the Curve25519 montgomery curve
 *
 * Use ESDSA to verify signature
 *
 * @param signature[64] [description]
 * @param public_key[32] [description]
 * @param msg [description]
 * @param msg_len [description]
 * @return 0 on success
 */
int curve25519_verify(const unsigned char* signature,
                      const unsigned char* public_key,
                      const unsigned char* msg, const unsigned long msg_len);


#endif /* CURVE_25519_H */
