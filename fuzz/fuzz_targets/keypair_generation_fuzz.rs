#![no_main]

use bitcoinpqc::{generate_keypair, Algorithm};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 129 {
        // Need at least 129 bytes: 1 for algorithm selection and 128 for random data
        return;
    }

    // Use first byte to select an algorithm
    let alg_byte = data[0];
    let algorithm = match alg_byte % 4 {
        0 => Algorithm::SECP256K1_SCHNORR,
        1 => Algorithm::FN_DSA_512,
        2 => Algorithm::ML_DSA_44,
        _ => Algorithm::SLH_DSA_128S,
    };

    // Use remaining bytes as random data
    let random_data = &data[1..];

    // Try to generate a keypair with this data
    let _ = generate_keypair(algorithm, random_data);
});
