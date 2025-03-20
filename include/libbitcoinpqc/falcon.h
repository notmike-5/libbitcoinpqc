/**
 * @file fndsa.h
 * @brief FN-DSA-512 (FALCON) specific functions
 */

#ifndef BITCOIN_PQC_FNDSA_H
#define BITCOIN_PQC_FNDSA_H

#include <stddef.h>
#include <stdint.h>

/* FN-DSA-512 constants */
#define FNDSA512_PUBLIC_KEY_SIZE 897
#define FNDSA512_SECRET_KEY_SIZE 1281
#define FNDSA512_SIGNATURE_SIZE 666  /* Average size, actual size may vary */
#define FNDSA512_SIG_MAX_SIZE 809    /* Maximum signature size */

/**
 * @brief Generate a FN-DSA-512 key pair
 *
 * @param pk Output public key (must have space for FNDSA512_PUBLIC_KEY_SIZE bytes)
 * @param sk Output secret key (must have space for FNDSA512_SECRET_KEY_SIZE bytes)
 * @param random_data User-provided random data (entropy)
 * @param random_data_size Size of random data, must be >= 128 bytes
 * @return 0 on success, non-zero on failure
 */
int fndsa512_keygen(
    uint8_t *pk,
    uint8_t *sk,
    const uint8_t *random_data,
    size_t random_data_size
);

/**
 * @brief Sign a message using FN-DSA-512
 *
 * @param sig Output signature (must have space for FNDSA512_SIG_MAX_SIZE bytes)
 * @param siglen Output signature length
 * @param m Message to sign
 * @param mlen Message length
 * @param sk Secret key
 * @param random_data Optional user-provided random data (entropy), can be NULL
 * @param random_data_size Size of random data, must be >= 64 bytes if provided
 * @return 0 on success, non-zero on failure
 */
int fndsa512_sign(
    uint8_t *sig,
    size_t *siglen,
    const uint8_t *m,
    size_t mlen,
    const uint8_t *sk,
    const uint8_t *random_data,
    size_t random_data_size
);

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
int fndsa512_verify(
    const uint8_t *sig,
    size_t siglen,
    const uint8_t *m,
    size_t mlen,
    const uint8_t *pk
);

#endif /* BITCOIN_PQC_FNDSA_H */
