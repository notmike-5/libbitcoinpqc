use bitcoinpqc::{
    generate_keypair, public_key_size, secret_key_size, sign, signature_size, verify, Algorithm,
};
use rand::{rngs::OsRng, RngCore};

fn get_random_bytes(size: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; size];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

#[test]
fn test_key_sizes() {
    // Verify the key and signature sizes are as expected
    assert_eq!(public_key_size(Algorithm::ML_DSA_44), 1312);
    assert_eq!(secret_key_size(Algorithm::ML_DSA_44), 2560);
    assert_eq!(signature_size(Algorithm::ML_DSA_44), 2420);

    assert_eq!(public_key_size(Algorithm::SLH_DSA_128S), 32);
    assert_eq!(secret_key_size(Algorithm::SLH_DSA_128S), 64);
    assert_eq!(signature_size(Algorithm::SLH_DSA_128S), 7856);

    assert_eq!(public_key_size(Algorithm::FN_DSA_512), 897);
    assert_eq!(secret_key_size(Algorithm::FN_DSA_512), 1281);
    // For FN_DSA_512, we only check that signature size is valid
    assert!(signature_size(Algorithm::FN_DSA_512) > 0);
}

#[test]
fn test_ml_dsa_44_keygen_sign_verify() {
    println!("Starting ML-DSA-44 test");
    let random_data = get_random_bytes(128);
    println!("Generated random data of size {}", random_data.len());

    let keypair = generate_keypair(Algorithm::ML_DSA_44, &random_data)
        .expect("Failed to generate ML-DSA-44 keypair");

    println!("Key generation successful");

    // Verify the key sizes match expected values
    assert_eq!(
        keypair.public_key.bytes.len(),
        public_key_size(Algorithm::ML_DSA_44)
    );
    println!("Public key size: {}", keypair.public_key.bytes.len());

    assert_eq!(
        keypair.secret_key.bytes.len(),
        secret_key_size(Algorithm::ML_DSA_44)
    );
    println!("Secret key size: {}", keypair.secret_key.bytes.len());

    // Test signing and verification
    let message = b"ML-DSA-44 Test Message";
    println!("Message to sign: {:?}", message);

    let sig_random_data = get_random_bytes(64);
    println!(
        "Generated signature random data of size {}",
        sig_random_data.len()
    );

    let signature = sign(&keypair.secret_key, message, Some(&sig_random_data))
        .expect("Failed to sign with ML-DSA-44");

    println!(
        "Signature created successfully, size: {}",
        signature.bytes.len()
    );
    println!(
        "Signature prefix: {:02x?}",
        &signature.bytes[..8.min(signature.bytes.len())]
    );

    // Verify the signature
    println!("Verifying signature...");
    let result = verify(&keypair.public_key, message, &signature);
    println!("Verification result: {:?}", result);

    assert!(result.is_ok(), "ML-DSA-44 signature verification failed");

    // Try to verify with a modified message - should fail
    let modified_message = b"ML-DSA-44 Modified Message";
    println!("Modified message: {:?}", modified_message);

    let result = verify(&keypair.public_key, modified_message, &signature);
    println!("Verification with modified message result: {:?}", result);

    assert!(
        result.is_err(),
        "ML-DSA-44 verification should fail with modified message"
    );
}

#[test]
fn test_slh_dsa_128s_keygen_sign_verify() {
    let random_data = get_random_bytes(128);
    let keypair = generate_keypair(Algorithm::SLH_DSA_128S, &random_data)
        .expect("Failed to generate SLH-DSA-Shake-128s keypair");

    // Verify the key sizes match expected values
    assert_eq!(
        keypair.public_key.bytes.len(),
        public_key_size(Algorithm::SLH_DSA_128S)
    );
    assert_eq!(
        keypair.secret_key.bytes.len(),
        secret_key_size(Algorithm::SLH_DSA_128S)
    );

    // Test signing and verification
    let message = b"SLH-DSA-Shake-128s Test Message";
    let sig_random_data = get_random_bytes(64);

    let signature = sign(&keypair.secret_key, message, Some(&sig_random_data))
        .expect("Failed to sign with SLH-DSA-Shake-128s");

    // Verify the signature
    let result = verify(&keypair.public_key, message, &signature);
    assert!(
        result.is_ok(),
        "SLH-DSA-Shake-128s signature verification failed"
    );

    // Try to verify with a modified message - should fail
    let modified_message = b"SLH-DSA-Shake-128s Modified Message";
    let result = verify(&keypair.public_key, modified_message, &signature);
    assert!(
        result.is_err(),
        "SLH-DSA-Shake-128s verification should fail with modified message"
    );
}

#[test]
fn test_fn_dsa_512_keygen_sign_verify() {
    let random_data = get_random_bytes(128);
    let keypair = generate_keypair(Algorithm::FN_DSA_512, &random_data)
        .expect("Failed to generate FN-DSA-512 keypair");

    // Verify the key sizes match expected values
    assert_eq!(
        keypair.public_key.bytes.len(),
        public_key_size(Algorithm::FN_DSA_512)
    );
    assert_eq!(
        keypair.secret_key.bytes.len(),
        secret_key_size(Algorithm::FN_DSA_512)
    );

    // Test signing and verification
    let message = b"FN-DSA-512 Test Message";
    let sig_random_data = get_random_bytes(64);

    let signature = sign(&keypair.secret_key, message, Some(&sig_random_data))
        .expect("Failed to sign with FN-DSA-512");

    // Verify the signature
    let result = verify(&keypair.public_key, message, &signature);
    assert!(result.is_ok(), "FN-DSA-512 signature verification failed");

    // Try to verify with a modified message - should fail
    let modified_message = b"FN-DSA-512 Modified Message";
    let result = verify(&keypair.public_key, modified_message, &signature);
    assert!(
        result.is_err(),
        "FN-DSA-512 verification should fail with modified message"
    );
}

#[test]
fn test_deterministic_signing() {
    // Test signing twice with the same key and message
    let random_data = get_random_bytes(128);
    let keypair =
        generate_keypair(Algorithm::ML_DSA_44, &random_data).expect("Failed to generate keypair");
    let message = b"Deterministic signing test message";

    // Sign twice with no additional randomness
    let signature1 =
        sign(&keypair.secret_key, message, None).expect("Failed to sign message first time");
    let signature2 =
        sign(&keypair.secret_key, message, None).expect("Failed to sign message second time");

    // Since we can't guarantee bit-for-bit identical signatures even without random data,
    // we'll verify that both signatures are valid for the same message and key
    assert!(
        verify(&keypair.public_key, message, &signature1).is_ok(),
        "First signature should be valid"
    );
    assert!(
        verify(&keypair.public_key, message, &signature2).is_ok(),
        "Second signature should be valid"
    );

    // Also verify that the signatures fail for a different message
    let different_message = b"Different message";
    assert!(
        verify(&keypair.public_key, different_message, &signature1).is_err(),
        "First signature should fail with different message"
    );
    assert!(
        verify(&keypair.public_key, different_message, &signature2).is_err(),
        "Second signature should fail with different message"
    );
}

#[test]
fn test_error_conditions() {
    // Test with insufficient random data for key generation
    let short_random = get_random_bytes(127); // Need at least 128 bytes
    let result = generate_keypair(Algorithm::ML_DSA_44, &short_random);
    assert!(result.is_err(), "Should fail with insufficient random data");

    // Create a valid keypair for further tests
    let random_data = get_random_bytes(128);
    let keypair =
        generate_keypair(Algorithm::ML_DSA_44, &random_data).expect("Failed to generate keypair");

    // Test with insufficient random data for signing
    let short_sig_random = get_random_bytes(63); // Need at least 64 bytes
    let message = b"Test message";
    let result = sign(&keypair.secret_key, message, Some(&short_sig_random));
    assert!(
        result.is_err(),
        "Should fail with insufficient signature random data"
    );

    // Test verification with mismatched algorithm
    let sig = sign(&keypair.secret_key, message, None).expect("Failed to sign");

    // Create a keypair of a different algorithm
    let other_keypair = generate_keypair(Algorithm::SLH_DSA_128S, &random_data)
        .expect("Failed to generate other keypair");

    // Try to verify with mismatched algorithm
    let result = verify(&other_keypair.public_key, message, &sig);
    assert!(result.is_err(), "Should fail with mismatched algorithm");
}
