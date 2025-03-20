#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include "libbitcoinpqc/bitcoinpqc.h"
#include "libbitcoinpqc/ml_dsa.h"
#include "libbitcoinpqc/slh_dsa.h"
#include "libbitcoinpqc/fn_dsa.h"

// Helper function to print bytes in hex format
static void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len && i < 16; i++) {
        printf("%02x", data[i]);
    }
    if (len > 16) {
        printf("...");
    }
    printf("\n");
}

// Helper function to measure time
static double get_time_ms(struct timespec start, struct timespec end) {
    return (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_nsec - start.tv_nsec) / 1000000.0;
}

// Function to get random data from /dev/urandom
static int get_random_bytes(uint8_t *buffer, size_t length) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return -1;
    }

    size_t bytes_read = 0;
    while (bytes_read < length) {
        ssize_t result = read(fd, buffer + bytes_read, length - bytes_read);
        if (result < 0) {
            close(fd);
            return -1;
        }
        bytes_read += result;
    }

    close(fd);
    return 0;
}

// Test ML-DSA-44 directly
static void test_ml_dsa_44_direct(const uint8_t *random_data, size_t random_data_size) {
    printf("Testing ML-DSA-44 directly (bypassing main API):\n");
    printf("------------------------------------------------\n");

    // Key sizes from the header
    printf("Public key size: %d bytes\n", ML_DSA_44_PUBLIC_KEY_SIZE);
    printf("Secret key size: %d bytes\n", ML_DSA_44_SECRET_KEY_SIZE);
    printf("Signature size: %d bytes\n", ML_DSA_44_SIGNATURE_SIZE);

    // Allocate memory for keys and signature with additional padding to prevent buffer overflows
    const size_t padding = 64; // Extra padding to prevent buffer overflows
    uint8_t *pk = malloc(ML_DSA_44_PUBLIC_KEY_SIZE + padding);
    uint8_t *sk = malloc(ML_DSA_44_SECRET_KEY_SIZE + padding);
    uint8_t *sig = malloc(ML_DSA_44_SIGNATURE_SIZE + padding);

    if (!pk || !sk || !sig) {
        printf("Memory allocation failed\n");
        free(pk);
        free(sk);
        free(sig);
        return;
    }

    // Clear memory
    memset(pk, 0, ML_DSA_44_PUBLIC_KEY_SIZE + padding);
    memset(sk, 0, ML_DSA_44_SECRET_KEY_SIZE + padding);
    memset(sig, 0, ML_DSA_44_SIGNATURE_SIZE + padding);

    // Generate key pair
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    int result = ml_dsa_44_keygen(pk, sk, random_data, random_data_size);
    clock_gettime(CLOCK_MONOTONIC, &end);

    if (result != 0) {
        printf("Error generating key pair: %d\n", result);
        free(pk);
        free(sk);
        free(sig);
        return;
    }

    printf("Key generation time: %.2f ms\n", get_time_ms(start, end));

    // Create a message to sign
    const uint8_t message[] = "This is a test message for PQC signature verification";
    size_t message_len = strlen((const char *)message);

    // Use fresh random data for signing
    uint8_t signing_random_data[256];
    if (get_random_bytes(signing_random_data, sizeof(signing_random_data)) != 0) {
        printf("Error getting random data for signing\n");
        free(pk);
        free(sk);
        free(sig);
        return;
    }

    // Sign the message
    size_t sig_len;
    clock_gettime(CLOCK_MONOTONIC, &start);
    result = ml_dsa_44_sign(sig, &sig_len, message, message_len, sk, signing_random_data, sizeof(signing_random_data));
    clock_gettime(CLOCK_MONOTONIC, &end);

    if (result != 0) {
        printf("Error signing message: %d\n", result);
        free(pk);
        free(sk);
        free(sig);
        return;
    }

    printf("Signing time: %.2f ms\n", get_time_ms(start, end));
    printf("Actual signature size: %zu bytes\n", sig_len);

    // Print the first few bytes of the public key, secret key, and signature
    print_hex("Public key (partial)", pk, ML_DSA_44_PUBLIC_KEY_SIZE);
    print_hex("Signature (partial)", sig, sig_len);

    // Verify the signature
    clock_gettime(CLOCK_MONOTONIC, &start);
    result = ml_dsa_44_verify(sig, sig_len, message, message_len, pk);
    clock_gettime(CLOCK_MONOTONIC, &end);

    if (result == 0) {
        printf("Signature verified successfully!\n");
    } else {
        printf("Signature verification failed: %d\n", result);
    }
    printf("Verification time: %.2f ms\n", get_time_ms(start, end));

    // Try to verify with a modified message
    const uint8_t modified_message[] = "This is a MODIFIED message for PQC signature verification";
    size_t modified_message_len = strlen((const char *)modified_message);

    result = ml_dsa_44_verify(sig, sig_len, modified_message, modified_message_len, pk);

    if (result == 0) {
        printf("ERROR: Signature verified for modified message!\n");
    } else {
        printf("Correctly rejected signature for modified message\n");
    }

    printf("\n");

    printf("Cleaning up memory...\n");
    // Clean up memory properly
    free(pk);
    free(sk);
    free(sig);
    printf("Cleanup completed successfully\n");
}

// Test SLH-DSA-SHAKE-128S directly
static void test_slh_dsa_shake_128s_direct(const uint8_t *random_data, size_t random_data_size) {
    printf("Testing SLH-DSA-SHAKE-128S directly (bypassing main API):\n");
    printf("-------------------------------------------------------\n");

    // Key sizes from the header
    printf("Public key size: %d bytes\n", SLH_DSA_SHAKE_128S_PUBLIC_KEY_SIZE);
    printf("Secret key size: %d bytes\n", SLH_DSA_SHAKE_128S_SECRET_KEY_SIZE);
    printf("Signature size: %d bytes\n", SLH_DSA_SHAKE_128S_SIGNATURE_SIZE);

    // Allocate memory for keys and signature with additional padding to prevent buffer overflows
    const size_t padding = 64; // Extra padding to prevent buffer overflows
    uint8_t *pk = malloc(SLH_DSA_SHAKE_128S_PUBLIC_KEY_SIZE + padding);
    uint8_t *sk = malloc(SLH_DSA_SHAKE_128S_SECRET_KEY_SIZE + padding);
    uint8_t *sig = malloc(SLH_DSA_SHAKE_128S_SIGNATURE_SIZE + padding);

    if (!pk || !sk || !sig) {
        printf("Memory allocation failed\n");
        free(pk);
        free(sk);
        free(sig);
        return;
    }

    // Clear memory
    memset(pk, 0, SLH_DSA_SHAKE_128S_PUBLIC_KEY_SIZE + padding);
    memset(sk, 0, SLH_DSA_SHAKE_128S_SECRET_KEY_SIZE + padding);
    memset(sig, 0, SLH_DSA_SHAKE_128S_SIGNATURE_SIZE + padding);

    // Generate key pair
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    int result = slh_dsa_shake_128s_keygen(pk, sk, random_data, random_data_size);
    clock_gettime(CLOCK_MONOTONIC, &end);

    if (result != 0) {
        printf("Error generating key pair: %d\n", result);
        free(pk);
        free(sk);
        free(sig);
        return;
    }

    printf("Key generation time: %.2f ms\n", get_time_ms(start, end));

    // Create a message to sign
    const uint8_t message[] = "This is a test message for PQC signature verification";
    size_t message_len = strlen((const char *)message);

    // Use fresh random data for signing
    uint8_t signing_random_data[256];
    if (get_random_bytes(signing_random_data, sizeof(signing_random_data)) != 0) {
        printf("Error getting random data for signing\n");
        free(pk);
        free(sk);
        free(sig);
        return;
    }

    // Sign the message
    size_t sig_len;
    clock_gettime(CLOCK_MONOTONIC, &start);
    result = slh_dsa_shake_128s_sign(sig, &sig_len, message, message_len, sk, signing_random_data, sizeof(signing_random_data));
    clock_gettime(CLOCK_MONOTONIC, &end);

    if (result != 0) {
        printf("Error signing message: %d\n", result);
        free(pk);
        free(sk);
        free(sig);
        return;
    }

    printf("Signing time: %.2f ms\n", get_time_ms(start, end));
    printf("Actual signature size: %zu bytes\n", sig_len);

    // Print the first few bytes of the public key, secret key, and signature
    print_hex("Public key (partial)", pk, SLH_DSA_SHAKE_128S_PUBLIC_KEY_SIZE);
    print_hex("Signature (partial)", sig, sig_len);

    // Verify the signature
    clock_gettime(CLOCK_MONOTONIC, &start);
    result = slh_dsa_shake_128s_verify(sig, sig_len, message, message_len, pk);
    clock_gettime(CLOCK_MONOTONIC, &end);

    if (result == 0) {
        printf("Signature verified successfully!\n");
    } else {
        printf("Signature verification failed: %d\n", result);
    }
    printf("Verification time: %.2f ms\n", get_time_ms(start, end));

    // Try to verify with a modified message
    const uint8_t modified_message[] = "This is a MODIFIED message for PQC signature verification";
    size_t modified_message_len = strlen((const char *)modified_message);

    result = slh_dsa_shake_128s_verify(sig, sig_len, modified_message, modified_message_len, pk);

    if (result == 0) {
        printf("ERROR: Signature verified for modified message!\n");
    } else {
        printf("Correctly rejected signature for modified message\n");
    }

    printf("\n");

    printf("Cleaning up memory...\n");
    // Clean up memory properly
    free(pk);
    free(sk);
    free(sig);
    printf("Cleanup completed successfully\n");
}

// Test FN-DSA-512 directly
static void test_fn_dsa_512_direct(const uint8_t *random_data, size_t random_data_size) {
    printf("Testing FN-DSA-512 directly (bypassing main API):\n");
    printf("-----------------------------------------------\n");

    // Key sizes from the header
    printf("Public key size: %d bytes\n", FN_DSA_512_PUBLIC_KEY_SIZE);
    printf("Secret key size: %d bytes\n", FN_DSA_512_SECRET_KEY_SIZE);
    printf("Maximum signature size: %d bytes\n", FN_DSA_512_SIG_MAX_SIZE);

    // Allocate memory for keys and signature with additional padding to prevent buffer overflows
    const size_t padding = 64; // Extra padding to prevent buffer overflows
    uint8_t *pk = malloc(FN_DSA_512_PUBLIC_KEY_SIZE + padding);
    uint8_t *sk = malloc(FN_DSA_512_SECRET_KEY_SIZE + padding);
    uint8_t *sig = malloc(FN_DSA_512_SIG_MAX_SIZE + padding);

    if (!pk || !sk || !sig) {
        printf("Memory allocation failed\n");
        free(pk);
        free(sk);
        free(sig);
        return;
    }

    // Clear memory
    memset(pk, 0, FN_DSA_512_PUBLIC_KEY_SIZE + padding);
    memset(sk, 0, FN_DSA_512_SECRET_KEY_SIZE + padding);
    memset(sig, 0, FN_DSA_512_SIG_MAX_SIZE + padding);

    // Generate key pair
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    int result = fn_dsa_512_keygen(pk, sk, random_data, random_data_size);
    clock_gettime(CLOCK_MONOTONIC, &end);

    if (result != 0) {
        printf("Error generating key pair: %d\n", result);
        free(pk);
        free(sk);
        free(sig);
        return;
    }

    printf("Key generation time: %.2f ms\n", get_time_ms(start, end));

    // Create a message to sign
    const uint8_t message[] = "This is a test message for PQC signature verification";
    size_t message_len = strlen((const char *)message);

    // Use fresh random data for signing
    uint8_t signing_random_data[256];
    if (get_random_bytes(signing_random_data, sizeof(signing_random_data)) != 0) {
        printf("Error getting random data for signing\n");
        free(pk);
        free(sk);
        free(sig);
        return;
    }

    // Sign the message
    size_t sig_len;
    clock_gettime(CLOCK_MONOTONIC, &start);
    result = fn_dsa_512_sign(sig, &sig_len, message, message_len, sk, signing_random_data, sizeof(signing_random_data));
    clock_gettime(CLOCK_MONOTONIC, &end);

    if (result != 0) {
        printf("Error signing message: %d\n", result);
        free(pk);
        free(sk);
        free(sig);
        return;
    }

    printf("Signing time: %.2f ms\n", get_time_ms(start, end));
    printf("Actual signature size: %zu bytes\n", sig_len);

    // Print the first few bytes of the public key, secret key, and signature
    print_hex("Public key (partial)", pk, FN_DSA_512_PUBLIC_KEY_SIZE);
    print_hex("Signature (partial)", sig, sig_len);

    // Verify the signature
    clock_gettime(CLOCK_MONOTONIC, &start);
    result = fn_dsa_512_verify(sig, sig_len, message, message_len, pk);
    clock_gettime(CLOCK_MONOTONIC, &end);

    if (result == 0) {
        printf("Signature verified successfully!\n");
    } else {
        printf("Signature verification failed: %d\n", result);
    }
    printf("Verification time: %.2f ms\n", get_time_ms(start, end));

    // Try to verify with a modified message
    const uint8_t modified_message[] = "This is a MODIFIED message for PQC signature verification";
    size_t modified_message_len = strlen((const char *)modified_message);

    result = fn_dsa_512_verify(sig, sig_len, modified_message, modified_message_len, pk);

    if (result == 0) {
        printf("ERROR: Signature verified for modified message!\n");
    } else {
        printf("Correctly rejected signature for modified message\n");
    }

    printf("\n");

    printf("Cleaning up memory...\n");
    // Clean up memory properly
    free(pk);
    free(sk);
    free(sig);
    printf("Cleanup completed successfully\n");
}

int main() {
    printf("Bitcoin PQC Library Example\n");
    printf("==========================\n\n");
    printf("This example tests all three post-quantum signature algorithms directly.\n\n");

    // Generate random data for key generation and signing
    uint8_t random_data[256];
    if (get_random_bytes(random_data, sizeof(random_data)) != 0) {
        printf("Error getting random data\n");
        return 1;
    }

    // Test ML-DSA-44 directly
    test_ml_dsa_44_direct(random_data, sizeof(random_data));

    // Uncomment to test other algorithms
    test_slh_dsa_shake_128s_direct(random_data, sizeof(random_data));
    test_fn_dsa_512_direct(random_data, sizeof(random_data));

    return 0;
}
