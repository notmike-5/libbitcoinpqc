#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "libbitcoinpqc/fn_dsa.h"

/*
 * This file implements the verification function for FN-DSA-512 (FALCON)
 */

/* Include necessary headers from FALCON reference implementation */
#include "../../falcon/falcon.h"

// Debug mode flag - set to 0 to disable debug output
#define FN_DSA_DEBUG 0

// Conditional debug print macro
#define DEBUG_PRINT(fmt, ...) \
    do { if (FN_DSA_DEBUG) printf(fmt, ##__VA_ARGS__); } while (0)

int fn_dsa_512_verify(
    const uint8_t *sig,
    size_t siglen,
    const uint8_t *m,
    size_t mlen,
    const uint8_t *pk
) {
    if (!sig || !m || !pk) {
        DEBUG_PRINT("FN-DSA verify: Invalid arguments\n");
        return -1;
    }

    /*
     * Temporary buffer size needed for Falcon-512 verification
     * FALCON_TMPSIZE_VERIFY(9) is the buffer size for degree 2^9 = 512
     */
    size_t tmp_size = FALCON_TMPSIZE_VERIFY(9);
    uint8_t *tmp = malloc(tmp_size);
    if (!tmp) {
        DEBUG_PRINT("FN-DSA verify: Memory allocation failed\n");
        return -1;
    }

    DEBUG_PRINT("FN-DSA verify: Calling falcon_verify\n");

    // Verify the signature using the FALCON implementation
    int result = falcon_verify(
        sig,                   // signature to verify
        siglen,                // signature length
        FALCON_SIG_COMPRESSED, // signature format
        pk,                    // public key
        FN_DSA_512_PUBLIC_KEY_SIZE, // public key size
        m,                     // message
        mlen,                  // message length
        tmp,                   // temporary buffer
        tmp_size               // temporary buffer size
    );

    DEBUG_PRINT("FN-DSA verify: Verification result %d\n", result);

    // Clean up
    memset(tmp, 0, tmp_size);
    free(tmp);

    return result;
}
