#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../include/libbitcoinpqc/bitcoinpqc.h"

int main() {
    printf("Testing ML-DSA-44 implementation\n");

    // Generate random data for keygen
    uint8_t random_data[128];
    FILE *f = fopen("/dev/urandom", "r");
    if (!f) {
        printf("Failed to open /dev/urandom\n");
        return 1;
    }
    fread(random_data, 1, sizeof(random_data), f);
    fclose(f);

    // Generate key pair
    bitcoin_pqc_keypair_t keypair;
    bitcoin_pqc_error_t result;

    result = bitcoin_pqc_keygen(BITCOIN_PQC_ML_DSA_44, &keypair, random_data, sizeof(random_data));
    if (result != BITCOIN_PQC_OK) {
        printf("Key generation failed with error %d\n", result);
        return 1;
    }

    printf("Key generation successful\n");
    printf("Public key size: %zu bytes\n", keypair.public_key_size);
    printf("Secret key size: %zu bytes\n", keypair.secret_key_size);

    // Test signing
    const uint8_t message[] = "Test message for ML-DSA-44";
    bitcoin_pqc_signature_t signature;

    result = bitcoin_pqc_sign(
        BITCOIN_PQC_ML_DSA_44,
        keypair.secret_key,
        keypair.secret_key_size,
        message,
        sizeof(message) - 1,  // Exclude null terminator
        &signature,
        random_data,  // Use same random data for simplicity
        sizeof(random_data)
    );

    if (result != BITCOIN_PQC_OK) {
        printf("Signing failed with error %d\n", result);
        bitcoin_pqc_keypair_free(&keypair);
        return 1;
    }

    printf("Signing successful\n");
    printf("Signature size: %zu bytes\n", signature.signature_size);

    // Test verification
    result = bitcoin_pqc_verify(
        BITCOIN_PQC_ML_DSA_44,
        keypair.public_key,
        keypair.public_key_size,
        message,
        sizeof(message) - 1,  // Exclude null terminator
        signature.signature,
        signature.signature_size
    );

    if (result != BITCOIN_PQC_OK) {
        printf("Verification failed with error %d\n", result);
        bitcoin_pqc_signature_free(&signature);
        bitcoin_pqc_keypair_free(&keypair);
        return 1;
    }

    printf("Verification successful\n");

    // Modify message and verify - should fail
    const uint8_t modified_message[] = "Modified message for ML-DSA-44";
    result = bitcoin_pqc_verify(
        BITCOIN_PQC_ML_DSA_44,
        keypair.public_key,
        keypair.public_key_size,
        modified_message,
        sizeof(modified_message) - 1,  // Exclude null terminator
        signature.signature,
        signature.signature_size
    );

    if (result == BITCOIN_PQC_OK) {
        printf("Verification unexpectedly succeeded with modified message\n");
        bitcoin_pqc_signature_free(&signature);
        bitcoin_pqc_keypair_free(&keypair);
        return 1;
    }

    printf("Verification correctly failed with modified message\n");

    // Clean up
    bitcoin_pqc_signature_free(&signature);
    bitcoin_pqc_keypair_free(&keypair);

    printf("ML-DSA-44 tests completed successfully\n");
    return 0;
}
