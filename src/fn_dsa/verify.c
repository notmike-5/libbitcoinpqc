#include <stdlib.h>
#include <string.h>
#include "libbitcoinpqc/fn_dsa.h"

/*
 * This file implements the verification function for FN-DSA-512 (FALCON)
 */

/* Include necessary headers from FALCON reference implementation */
#include "../../falcon/falcon.h"

int fn_dsa_512_verify(
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
                         pk, FN_DSA_512_PUBLIC_KEY_SIZE,
                         m, mlen, tmp, FALCON_TMPSIZE_VERIFY(9));

    /* Clean up */
    free(tmp);

    return result;
}
