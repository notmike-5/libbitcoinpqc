#include <stdlib.h>
#include <string.h>
#include "libbitcoinpqc/fndsa.h"

/*
 * This file integrates the reference implementation of FN-DSA-512 (FALCON)
 * We need to adapt the reference implementation API to our library's API.
 */

/* Include necessary headers from FALCON reference implementation */
#include "../../falcon/falcon.h"

/* Custom implementation of SHAKE256 for entropy */
static void shake256_with_entropy(void *out, size_t out_len,
                                const void *in1, size_t in1_len,
                                const void *in2, size_t in2_len,
                                const uint8_t *entropy, size_t entropy_len) {
    /* Combine inputs with entropy to get final output */
    size_t total_len = in1_len + in2_len + entropy_len;
    uint8_t *combined = malloc(total_len);

    if (!combined) {
        memset(out, 0, out_len); /* fallback to zeros */
        return;
    }

    /* Combine all inputs */
    memcpy(combined, in1, in1_len);
    memcpy(combined + in1_len, in2, in2_len);

    if (entropy && entropy_len > 0) {
        memcpy(combined + in1_len + in2_len, entropy, entropy_len);
    }

    /* Call FALCON's SHAKE256 */
    shake256(out, out_len, combined, total_len);

    /* Clean up */
    memset(combined, 0, total_len);
    free(combined);
}

int fndsa512_keygen(
    uint8_t *pk,
    uint8_t *sk,
    const uint8_t *random_data,
    size_t random_data_size
) {
    if (!pk || !sk || !random_data || random_data_size < 128) {
        return -1;
    }

    /*
     * FALCON's key generation requires a source of randomness,
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
    int result = falcon_keygen_make(&rng, (void (*)(void *, size_t, uint8_t *, size_t))shake256_extract,
                               FALCON_LOGN_512, sk, FNDSA512_SECRET_KEY_SIZE,
                               pk, FNDSA512_PUBLIC_KEY_SIZE, tmp, FALCON_TMPSIZE_KEYGEN(9));

    /* Clean up */
    memset(tmp, 0, FALCON_TMPSIZE_KEYGEN(9));
    free(tmp);

    return result;
}

int fndsa512_sign(
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
        result = falcon_sign_dyn(&rng, (void (*)(void *, size_t, uint8_t *, size_t))shake256_extract,
                           sig, siglen, FALCON_SIG_PADDED,
                           sk, FNDSA512_SECRET_KEY_SIZE,
                           m, mlen, tmp, FALCON_TMPSIZE_SIGNDYN(9));
    } else {
        /* No external randomness, use deterministic signing */
        result = falcon_sign_dyn(NULL, NULL,
                           sig, siglen, FALCON_SIG_PADDED,
                           sk, FNDSA512_SECRET_KEY_SIZE,
                           m, mlen, tmp, FALCON_TMPSIZE_SIGNDYN(9));
    }

    /* Clean up */
    memset(tmp, 0, FALCON_TMPSIZE_SIGNDYN(9));
    free(tmp);

    return result;
}

int fndsa512_verify(
    const uint8_t *sig,
    size_t siglen,
    const uint8_t *m,
    size_t mlen,
    const uint8_t *pk
) {
    if (!sig || !m || !pk) {
        return -1;
    }

    /*
     * Verify the signature
     * FALCON_TMPSIZE_VERIFY(9) = size needed for temporary buffer in verification for degree 2^9 = 512
     */
    uint8_t *tmp = malloc(FALCON_TMPSIZE_VERIFY(9));
    if (!tmp) {
        return -1;
    }

    /* Verify signature */
    int result = falcon_verify(sig, siglen, FALCON_SIG_PADDED,
                         pk, FNDSA512_PUBLIC_KEY_SIZE,
                         m, mlen, tmp, FALCON_TMPSIZE_VERIFY(9));

    /* Clean up */
    free(tmp);

    return result;
}
