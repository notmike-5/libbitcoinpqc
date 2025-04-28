#![no_main]

use bitcoinpqc::{algorithm_from_index, generate_keypair, sign, verify};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 150 {
        // Need sufficient bytes for all operations
        return;
    }

    // Use first byte to select an algorithm
    let alg_byte = data[0];
    let algorithm = algorithm_from_index(alg_byte);

    // Use 128 bytes for key generation
    let key_data = &data[1..129];

    // Try to generate a keypair
    let keypair = match generate_keypair(algorithm, key_data) {
        Ok(kp) => kp,
        Err(_) => return, // Skip if key generation fails
    };

    // Use remaining bytes as message to sign
    let message = &data[129..];

    // Try to sign the message
    let signature = match sign(&keypair.secret_key, message) {
        Ok(sig) => sig,
        Err(_) => return, // Skip if signing fails
    };

    // Try to verify the signature with the correct public key
    let verify_result = verify(&keypair.public_key, message, &signature);

    assert!(
        verify_result.is_ok(),
        "Verification failed for a signature generated with the corresponding private key! Algorithm: {algorithm:?}",
    );

    // Also try some invalid cases (if we have a valid signature)
    if message.len() > 1 {
        // Try with modified message
        let mut modified_msg = message.to_vec();
        modified_msg[0] ^= 0xFF; // Flip bits in first byte
        let _verify_result_bad_msg = verify(&keypair.public_key, &modified_msg, &signature);
    }

    if signature.bytes.len() > 1 {
        // Try with modified signature
        let mut modified_sig = signature.clone();
        modified_sig.bytes[0] ^= 0xFF; // Flip bits in first byte
        let _verify_result_bad_sig = verify(&keypair.public_key, message, &modified_sig);
    }
});
