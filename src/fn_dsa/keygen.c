#include <stdlib.h>
#include <string.h>
#include "libbitcoinpqc/fn_dsa.h"

/*
 * This file implements the key generation function for FN-DSA-512 (FALCON)
 */

/* Include necessary headers from FALCON reference implementation */
#include "../../falcon/falcon.h"

/* External declaration for utility functions */
extern void fn_dsa_shake256_with_entropy(void *out, size_t out_len,
                                      const void *in1, size_t in1_len,
                                      const void *in2, size_t in2_len,
                                      const uint8_t *entropy, size_t entropy_len);

int fn_dsa_512_keygen(
    uint8_t *pk,
    uint8_t *sk,
    const uint8_t *random_data,
    size_t random_data_size
) {
    if (!pk || !sk || !random_data || random_data_size < 128) {
        return -1;
    }

    /*
     * FN-DSA-512's key generation requires a source of randomness,
     * which we'll provide through a SHAKE256 instance pre-seeded
     * with our user-provided entropy
     */

    /* Buffer for SHAKE256 state */
    shake256_context rng;

    /* Initialize SHAKE256 with user-provided entropy */
    shake256_init(&rng);
    shake256_inject(&rng, random_data, random_data_size);
    shake256_flip(&rng);

    /*
     * Generate a FN-DSA-512 key pair
     * FALCON_TMPSIZE_KEYGEN(9) = size needed for temporary buffer in keygen for degree 2^9 = 512
     */
    uint8_t *tmp = malloc(FALCON_TMPSIZE_KEYGEN(9));
    if (!tmp) {
        return -1;
    }

    /* Generate the key pair using our RNG */
    int result = falcon_keygen_make(
        &rng,                /* RNG context */
        9,                   /* log of degree (9 for Falcon-512) */
        sk,                  /* output: private key */
        FN_DSA_512_SECRET_KEY_SIZE, /* size of private key buffer */
        pk,                  /* output: public key */
        FN_DSA_512_PUBLIC_KEY_SIZE, /* size of public key buffer */
        tmp,                 /* temporary buffer */
        FALCON_TMPSIZE_KEYGEN(9)    /* size of temporary buffer */
    );

    /* Clean up */
    memset(tmp, 0, FALCON_TMPSIZE_KEYGEN(9));
    free(tmp);

    return result;
}
