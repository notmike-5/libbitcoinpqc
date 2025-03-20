#include <stdlib.h>
#include <string.h>
#include "../../falcon/falcon.h"

/*
 * This file implements utility functions for FN-DSA-512 (FALCON)
 * particularly related to random data handling
 */

/* Custom implementation of SHAKE256 for entropy */
void fn_dsa_shake256_with_entropy(void *out, size_t out_len,
                                const void *in1, size_t in1_len,
                                const void *in2, size_t in2_len,
                                const uint8_t *entropy, size_t entropy_len) {
    /* Combine inputs with entropy to get final output */
    size_t total_len = in1_len + in2_len + entropy_len;
    uint8_t *combined = malloc(total_len);
    shake256_context sc;

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
    shake256_init(&sc);
    shake256_inject(&sc, combined, total_len);
    shake256_flip(&sc);
    shake256_extract(&sc, out, out_len);

    /* Clean up */
    memset(combined, 0, total_len);
    free(combined);
}
