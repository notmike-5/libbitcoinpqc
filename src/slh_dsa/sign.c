#include <stdlib.h>
#include <string.h>
#include "libbitcoinpqc/slh_dsa.h"

/*
 * This file implements the signing function for SLH-DSA-Shake-128s (SPHINCS+)
 */

/* Include necessary headers from SPHINCS+ reference implementation */
#include "../../sphincsplus/ref/api.h"
#include "../../sphincsplus/ref/randombytes.h"
#include "../../sphincsplus/ref/params.h"

/*
 * External declaration for the random data utilities
 * These are implemented in src/slh_dsa/utils.c
 */
extern void slh_dsa_init_random_source(const uint8_t *random_data, size_t random_data_size);
extern void slh_dsa_setup_custom_random(void);
extern void slh_dsa_restore_original_random(void);

int slh_dsa_shake_128s_sign(
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

    /* Use provided random data if available */
    if (random_data && random_data_size >= 64) {
        slh_dsa_init_random_source(random_data, random_data_size);
        slh_dsa_setup_custom_random();
    }

    /* The reference implementation prepends the message to the signature
     * but we want just the signature, so we need to use the detached API
     */
    int result = crypto_sign_signature(sig, siglen, m, mlen, sk);

    /* Restore original random bytes function if we changed it */
    if (random_data && random_data_size >= 64) {
        slh_dsa_restore_original_random();
    }

    return result;
}
