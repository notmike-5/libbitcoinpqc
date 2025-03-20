/**
 * @file mldsa.h
 * @brief ML-DSA-44 (CRYSTALS-Dilithium) specific functions
 */

#ifndef BITCOIN_PQC_MLDSA_H
#define BITCOIN_PQC_MLDSA_H

#include <stddef.h>
#include <stdint.h>

/* ML-DSA-44 constants */
#define MLDSA44_PUBLIC_KEY_SIZE 1312
#define MLDSA44_SECRET_KEY_SIZE 2528
#define MLDSA44_SIGNATURE_SIZE 2420

/**
 * @brief Generate an ML-DSA-44 key pair
 *
 * @param pk Output public key (must have space for MLDSA44_PUBLIC_KEY_SIZE bytes)
 * @param sk Output secret key (must have space for MLDSA44_SECRET_KEY_SIZE bytes)
 * @param random_data User-provided random data (entropy)
 * @param random_data_size Size of random data, must be >= 128 bytes
 * @return 0 on success, non-zero on failure
 */
int mldsa44_keygen(
    uint8_t *pk,
    uint8_t *sk,
    const uint8_t *random_data,
    size_t random_data_size
);

/**
 * @brief Sign a message using ML-DSA-44
 *
 * @param sig Output signature (must have space for MLDSA44_SIGNATURE_SIZE bytes)
 * @param siglen Output signature length
 * @param m Message to sign
 * @param mlen Message length
 * @param sk Secret key
 * @param random_data Optional user-provided random data (entropy), can be NULL for deterministic signing
 * @param random_data_size Size of random data, must be >= 64 bytes if provided
 * @return 0 on success, non-zero on failure
 */
int mldsa44_sign(
    uint8_t *sig,
    size_t *siglen,
    const uint8_t *m,
    size_t mlen,
    const uint8_t *sk,
    const uint8_t *random_data,
    size_t random_data_size
);

/**
 * @brief Verify an ML-DSA-44 signature
 *
 * @param sig Signature
 * @param siglen Signature length
 * @param m Message
 * @param mlen Message length
 * @param pk Public key
 * @return 0 if signature is valid, non-zero otherwise
 */
int mldsa44_verify(
    const uint8_t *sig,
    size_t siglen,
    const uint8_t *m,
    size_t mlen,
    const uint8_t *pk
);

#endif /* BITCOIN_PQC_MLDSA_H */
