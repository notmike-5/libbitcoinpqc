#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "libbitcoinpqc/fn_dsa.h"

/*
 * This file implements the signing function for FN-DSA-512 (FALCON)
 */

/* Include necessary headers from FALCON reference implementation */
#include "../../falcon/falcon.h"

// Debug mode flag - set to 0 to disable debug output
#define FN_DSA_DEBUG 0

// Conditional debug print macro
#define DEBUG_PRINT(fmt, ...) \
    do { if (FN_DSA_DEBUG) printf(fmt, ##__VA_ARGS__); } while (0)

/* External declaration for utility functions */
extern void fn_dsa_shake256_with_entropy(void *out, size_t out_len,
                                      const void *in1, size_t in1_len,
                                      const void *in2, size_t in2_len,
                                      const uint8_t *entropy, size_t entropy_len);

int fn_dsa_512_sign(
    uint8_t *sig,
    size_t *siglen,
    const uint8_t *m,
    size_t mlen,
    const uint8_t *sk
) {
    if (!sig || !siglen || !m || !sk) {
        DEBUG_PRINT("FN-DSA sign: Invalid arguments\n");
        return -1;
    }

    // Create a deterministic RNG for signing based on the message and secret key
    shake256_context rng;
    shake256_init(&rng);

    // Mix message and secret key to create deterministic randomness
    shake256_inject(&rng, sk, FN_DSA_512_SECRET_KEY_SIZE);
    shake256_inject(&rng, m, mlen);
    shake256_flip(&rng);

    /*
     * Temporary buffer size needed for Falcon-512 signature
     * FALCON_TMPSIZE_SIGNDYN(9) is the buffer size for degree 2^9 = 512
     */
    size_t tmp_size = FALCON_TMPSIZE_SIGNDYN(9);
    uint8_t *tmp = malloc(tmp_size);
    if (!tmp) {
        DEBUG_PRINT("FN-DSA sign: Memory allocation failed\n");
        return -1;
    }

    DEBUG_PRINT("FN-DSA sign: Calling falcon_sign_dyn\n");

    // Sign the message using the FALCON implementation
    int result = falcon_sign_dyn(
        &rng,          // RNG context (deterministic)
        sig,           // output signature
        siglen,        // output signature length
        FALCON_SIG_COMPRESSED, // signature format
        sk,            // secret key
        FN_DSA_512_SECRET_KEY_SIZE, // secret key size
        m,             // message to sign
        mlen,          // message length
        tmp,           // temporary buffer
        tmp_size       // temporary buffer size
    );

    DEBUG_PRINT("FN-DSA sign: Created signature of length %zu, result %d\n",
               *siglen, result);

    // Clean up
    memset(tmp, 0, tmp_size);
    free(tmp);

    return result;
}
