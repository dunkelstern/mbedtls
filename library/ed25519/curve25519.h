
#ifndef CURVE_25519_H
#define CURVE_25519_H

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
int curve25519_sign(unsigned char* signature,
                    const unsigned char* private_key,
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
 * @return 0 on success
 */
int curve25519_verify(const unsigned char* signature,
                      const unsigned char* public_key,
                      const unsigned char* msg, const unsigned long msg_len);


#endif /* CURVE_25519_H */
