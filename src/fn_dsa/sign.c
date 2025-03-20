#include <stdlib.h>
#include <string.h>
#include <stdio.h>
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
        printf("FN-DSA sign: Invalid arguments\n");
        return -1;
    }

    printf("FN-DSA sign: Starting to sign message of length %zu\n", mlen);
    printf("FN-DSA sign: Secret key size: %d bytes, first byte: 0x%02x\n", FN_DSA_512_SECRET_KEY_SIZE, sk[0]);

    /* Initialize a SHAKE256 context for randomness if provided */
    shake256_context rng;

    if (random_data && random_data_size >= 64) {
        /* Initialize SHAKE256 with user-provided entropy */
        shake256_init(&rng);
        shake256_inject(&rng, random_data, random_data_size);
        shake256_flip(&rng);
        printf("FN-DSA sign: Using provided random data of size %zu\n", random_data_size);
    } else {
        printf("FN-DSA sign: Using deterministic signing (no random data)\n");
    }

    /*
     * Sign the message
     * FALCON_TMPSIZE_SIGNDYN(9) = size needed for temporary buffer in signing for degree 2^9 = 512
     */
    uint8_t *tmp = malloc(FALCON_TMPSIZE_SIGNDYN(9));
    if (!tmp) {
        printf("FN-DSA sign: Memory allocation failed\n");
        return -1;
    }

    printf("FN-DSA sign: Allocated temporary buffer of size %d bytes\n", FALCON_TMPSIZE_SIGNDYN(9));

    /* Compute signature */
    int result;

    if (random_data && random_data_size >= 64) {
        /* Use provided randomness */
        printf("FN-DSA sign: Calling falcon_sign_dyn with RNG\n");
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
        printf("FN-DSA sign: Calling falcon_sign_dyn without RNG\n");
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

    printf("FN-DSA sign: falcon_sign_dyn returned %d, signature length: %zu\n", result, *siglen);
    if (result != 0) {
        switch (result) {
            case -1: printf("FN-DSA sign: Error code -1 (FALCON_ERR_SIZE)\n"); break;
            case -2: printf("FN-DSA sign: Error code -2 (FALCON_ERR_FORMAT) - Malformed key or signature\n"); break;
            case -3: printf("FN-DSA sign: Error code -3 (FALCON_ERR_BADARG) - Invalid parameters\n"); break;
            case -4: printf("FN-DSA sign: Error code -4 (FALCON_ERR_INTERNAL) - Internal error\n"); break;
            default: printf("FN-DSA sign: Unknown error code %d\n", result);
        }
    } else if (*siglen == 0) {
        printf("FN-DSA sign: Signature generation succeeded but signature length is 0!\n");
    }

    /* Clean up */
    memset(tmp, 0, FALCON_TMPSIZE_SIGNDYN(9));
    free(tmp);

    return result;
}
