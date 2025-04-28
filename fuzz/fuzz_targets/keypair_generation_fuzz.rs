#![no_main]

use bitcoinpqc::{algorithm_from_index, generate_keypair};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 129 {
        // Need at least 129 bytes: 1 for algorithm selection and 128 for random data
        return;
    }

    // Use first byte to select an algorithm
    let alg_byte = data[0];
    let algorithm = algorithm_from_index(alg_byte);

    // Use remaining bytes as random data
    let random_data = &data[1..];

    // Try to generate a keypair with this data
    let keypair = generate_keypair(algorithm, random_data);

    assert!(
        keypair.is_ok(),
        "Keypair generation failed! Algorithm: {algorithm:?}",
    );
});
