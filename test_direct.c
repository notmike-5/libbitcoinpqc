#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../../include/libbitcoinpqc/bitcoinpqc.h"

int main() {
    printf("Direct test of ML-DSA-44 algorithm\n");

    // Generate random data for keygen
    uint8_t random_data[128];
    FILE *f = fopen("/dev/urandom", "r");
    if (!f) {
        printf("Failed to open /dev/urandom\n");
        return 1;
    }
    fread(random_data, 1, sizeof(random_data), f);
    fclose(f);

    // Test message
    const char *message = "ML-DSA-44 Test Message";
    size_t message_len = strlen(message);

    printf("Test message: '%s' (length: %zu)\n", message, message_len);

    // Generate keys
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

    // Generate signature
    bitcoin_pqc_signature_t signature;

    printf("Signing message...\n");

    result = bitcoin_pqc_sign(
        BITCOIN_PQC_ML_DSA_44,
        keypair.secret_key,
        keypair.secret_key_size,
        (const uint8_t *)message,
        message_len,
        &signature,
        random_data,  // Reuse random data
        sizeof(random_data)
    );

    if (result != BITCOIN_PQC_OK) {
        printf("Signing failed with error %d\n", result);
        bitcoin_pqc_keypair_free(&keypair);
        return 1;
    }

    printf("Signing successful\n");
    printf("Signature size: %zu bytes\n", signature.signature_size);

    // Print first few bytes of signature
    printf("Signature prefix: ");
    for (size_t i = 0; i < (signature.signature_size < 16 ? signature.signature_size : 16); i++) {
        printf("%02x ", signature.signature[i]);
    }
    printf("...\n");

    // Verify signature
    printf("Verifying signature...\n");

    result = bitcoin_pqc_verify(
        BITCOIN_PQC_ML_DSA_44,
        keypair.public_key,
        keypair.public_key_size,
        (const uint8_t *)message,
        message_len,
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

    // Try verification with modified message
    const char *modified_message = "ML-DSA-44 Modified Message";
    size_t modified_message_len = strlen(modified_message);

    printf("Verifying with modified message: '%s'\n", modified_message);

    result = bitcoin_pqc_verify(
        BITCOIN_PQC_ML_DSA_44,
        keypair.public_key,
        keypair.public_key_size,
        (const uint8_t *)modified_message,
        modified_message_len,
        signature.signature,
        signature.signature_size
    );

    if (result == BITCOIN_PQC_OK) {
        printf("Verification succeeded with modified message - THIS IS AN ERROR!\n");
        bitcoin_pqc_signature_free(&signature);
        bitcoin_pqc_keypair_free(&keypair);
        return 1;
    }

    printf("Verification correctly failed with modified message\n");

    // Clean up
    bitcoin_pqc_signature_free(&signature);
    bitcoin_pqc_keypair_free(&keypair);

    printf("ML-DSA-44 direct test completed successfully\n");
    return 0;
}
