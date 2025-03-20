#include <stdlib.h>
#include <string.h>
#include "libbitcoinpqc/fn_dsa.h"

/*
 * This file implements the signing function for FN-DSA-512 (FALCON)
 */

/* Include necessary headers from FALCON reference implementation */
#include "../../falcon/falcon.h"

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
    const uint8_t *sk,
    const uint8_t *random_data,
    size_t random_data_size
) {
    if (!sig || !siglen || !m || !sk) {
        return -1;
    }

    /* Initialize a SHAKE256 context for randomness if provided */
    shake256_context rng;

    if (random_data && random_data_size >= 64) {
        /* Initialize SHAKE256 with user-provided entropy */
        shake256_init(&rng);
        shake256_inject(&rng, random_data, random_data_size);
        shake256_flip(&rng);
    }

    /*
     * Sign the message
     * FALCON_TMPSIZE_SIGNDYN(9) = size needed for temporary buffer in signing for degree 2^9 = 512
     */
    uint8_t *tmp = malloc(FALCON_TMPSIZE_SIGNDYN(9));
    if (!tmp) {
        return -1;
    }

    /* Compute signature */
    int result;

    if (random_data && random_data_size >= 64) {
        /* Use provided randomness */
        result = falcon_sign_dyn(
            &rng,                /* RNG context */
            sig,                 /* output: signature */
            siglen,              /* output: signature length */
            FALCON_SIG_PADDED,   /* signature format */
            sk,                  /* private key */
            FN_DSA_512_SECRET_KEY_SIZE, /* private key length */
            m,                   /* message to sign */
            mlen,                /* message length */
            tmp,                 /* temporary buffer */
            FALCON_TMPSIZE_SIGNDYN(9)   /* temporary buffer size */
        );
    } else {
        /* No external randomness, use deterministic signing */
        result = falcon_sign_dyn(
            NULL,                /* No RNG */
            sig,                 /* output: signature */
            siglen,              /* output: signature length */
            FALCON_SIG_PADDED,   /* signature format */
            sk,                  /* private key */
            FN_DSA_512_SECRET_KEY_SIZE, /* private key length */
            m,                   /* message to sign */
            mlen,                /* message length */
            tmp,                 /* temporary buffer */
            FALCON_TMPSIZE_SIGNDYN(9)   /* temporary buffer size */
        );
    }

    /* Clean up */
    memset(tmp, 0, FALCON_TMPSIZE_SIGNDYN(9));
    free(tmp);

    return result;
}
