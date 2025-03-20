/**
 * @file fn_dsa.h
 * @brief FN-DSA-512 (FALCON) specific functions
 */

#ifndef BITCOIN_PQC_FN_DSA_H
#define BITCOIN_PQC_FN_DSA_H

#include <stddef.h>
#include <stdint.h>

/* FN-DSA-512 constants */
#define FN_DSA_512_PUBLIC_KEY_SIZE 897
#define FN_DSA_512_SECRET_KEY_SIZE 1281
#define FN_DSA_512_SIGNATURE_SIZE 666  /* Average size, actual size may vary */
#define FN_DSA_512_SIG_MAX_SIZE 809    /* Maximum signature size */

/* Key Generation Functions */

/**
 * @brief Generate a FN-DSA-512 key pair
 *
 * @param pk Output public key (must have space for FN_DSA_512_PUBLIC_KEY_SIZE bytes)
 * @param sk Output secret key (must have space for FN_DSA_512_SECRET_KEY_SIZE bytes)
 * @param random_data User-provided random data (entropy)
 * @param random_data_size Size of random data, must be >= 128 bytes
 * @return 0 on success, non-zero on failure
 */
int fn_dsa_512_keygen(
    uint8_t *pk,
    uint8_t *sk,
    const uint8_t *random_data,
    size_t random_data_size
);

/* Signing Functions */

/**
 * @brief Sign a message using FN-DSA-512
 *
 * @param sig Output signature (must have space for FN_DSA_512_SIG_MAX_SIZE bytes)
 * @param siglen Output signature length
 * @param m Message to sign
 * @param mlen Message length
 * @param sk Secret key
 * @param random_data Optional user-provided random data (entropy), can be NULL
 * @param random_data_size Size of random data, must be >= 64 bytes if provided
 * @return 0 on success, non-zero on failure
 */
int fn_dsa_512_sign(
    uint8_t *sig,
    size_t *siglen,
    const uint8_t *m,
    size_t mlen,
    const uint8_t *sk,
    const uint8_t *random_data,
    size_t random_data_size
);

/* Verification Functions */

/**
 * @brief Verify a FN-DSA-512 signature
 *
 * @param sig Signature
 * @param siglen Signature length
 * @param m Message
 * @param mlen Message length
 * @param pk Public key
 * @return 0 if signature is valid, non-zero otherwise
 */
int fn_dsa_512_verify(
    const uint8_t *sig,
    size_t siglen,
    const uint8_t *m,
    size_t mlen,
    const uint8_t *pk
);

#endif /* BITCOIN_PQC_FN_DSA_H */
