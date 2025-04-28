#![no_main]

use bitcoinpqc::{algorithm_from_index, PublicKey, SecretKey};
use libfuzzer_sys::fuzz_target;

const NUM_ALGORITHMS: u8 = 4; // SECP256K1_SCHNORR, FN_DSA_512, ML_DSA_44, SLH_DSA_128S

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return; // Need at least one byte for algorithm selection
    }

    // Use first byte to select an algorithm
    let alg_byte = data[0];
    let algorithm = algorithm_from_index(alg_byte);

    // Use remaining bytes as potential key data
    let key_data = &data[1..];

    // Attempt to parse as PublicKey
    let _ = PublicKey::try_from_slice(algorithm, key_data);

    // Attempt to parse as SecretKey
    let secret_key_result = SecretKey::try_from_slice(algorithm, key_data);

    assert!(
        secret_key_result.is_ok(),
        "Secret key parsing failed! Algorithm: {algorithm:?}",
    );
});
