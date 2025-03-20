use criterion::{criterion_group, criterion_main, Criterion};
use rand::{rngs::OsRng, RngCore};
use secp256k1::{Keypair, Secp256k1};
use std::time::Duration;

use bitcoinpqc::{generate_keypair, sign, verify, Algorithm};

// Set to true to enable debug output, false to disable
const DEBUG_MODE: bool = false;

// Conditional debug print macro
macro_rules! debug_println {
    ($($arg:tt)*) => {
        if DEBUG_MODE {
            println!($($arg)*);
        }
    };
}

// Function to create a 32-byte array from data for secp256k1
fn create_32byte_array(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    result.into()
}

// Get random data of a specified size
fn get_random_data(size: usize) -> Vec<u8> {
    let mut random_data = vec![0u8; size];
    OsRng.fill_bytes(&mut random_data);
    random_data
}

// Configure benchmark group with common settings
fn configure_group(group: &mut criterion::BenchmarkGroup<criterion::measurement::WallTime>) {
    group.measurement_time(Duration::from_secs(10));
}

// ML-DSA-44 BENCHMARKS

fn bench_ml_dsa_44_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("ml_dsa_keygen");
    configure_group(&mut group);

    group.bench_function("ML_DSA_44", |b| {
        b.iter(|| {
            let random_data = get_random_data(256);
            generate_keypair(Algorithm::ML_DSA_44, &random_data).unwrap()
        });
    });

    group.finish();
}

fn bench_ml_dsa_44_signing(c: &mut Criterion) {
    let mut group = c.benchmark_group("ml_dsa_signing");
    configure_group(&mut group);

    let message = b"This is a test message for benchmarking";
    let random_data = get_random_data(256);
    let ml_keypair = generate_keypair(Algorithm::ML_DSA_44, &random_data).unwrap();

    group.bench_function("ML_DSA_44", |b| {
        b.iter(|| {
            let random_data = get_random_data(256);
            sign(&ml_keypair.secret_key, message, Some(&random_data)).unwrap()
        });
    });

    group.finish();
}

fn bench_ml_dsa_44_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("ml_dsa_verification");
    configure_group(&mut group);

    let message = b"This is a test message for benchmarking";
    let random_data = get_random_data(256);
    let ml_keypair = generate_keypair(Algorithm::ML_DSA_44, &random_data).unwrap();
    let ml_sig = sign(&ml_keypair.secret_key, message, Some(&get_random_data(256))).unwrap();

    group.bench_function("ML_DSA_44", |b| {
        b.iter(|| verify(&ml_keypair.public_key, message, &ml_sig).unwrap());
    });

    group.finish();
}

// SLH-DSA-128S BENCHMARKS

fn bench_slh_dsa_128s_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("slh_dsa_keygen");
    configure_group(&mut group);
    group.sample_size(10); // Reduce sample count for SLH-DSA which is slower

    group.bench_function("SLH_DSA_128S", |b| {
        b.iter(|| {
            let random_data = get_random_data(256);
            generate_keypair(Algorithm::SLH_DSA_128S, &random_data).unwrap()
        });
    });

    group.finish();
}

fn bench_slh_dsa_128s_signing(c: &mut Criterion) {
    let mut group = c.benchmark_group("slh_dsa_signing");
    configure_group(&mut group);
    group.sample_size(10); // Reduce sample count for SLH-DSA which is slower

    let message = b"This is a test message for benchmarking";
    let random_data = get_random_data(256);
    let slh_keypair = generate_keypair(Algorithm::SLH_DSA_128S, &random_data).unwrap();

    group.bench_function("SLH_DSA_128S", |b| {
        b.iter(|| {
            let random_data = get_random_data(256);
            sign(&slh_keypair.secret_key, message, Some(&random_data)).unwrap()
        });
    });

    group.finish();
}

fn bench_slh_dsa_128s_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("slh_dsa_verification");
    configure_group(&mut group);
    group.sample_size(10); // Reduce sample count for SLH-DSA which is slower

    let message = b"This is a test message for benchmarking";
    let random_data = get_random_data(256);
    let slh_keypair = generate_keypair(Algorithm::SLH_DSA_128S, &random_data).unwrap();
    let slh_sig = sign(
        &slh_keypair.secret_key,
        message,
        Some(&get_random_data(256)),
    )
    .unwrap();

    group.bench_function("SLH_DSA_128S", |b| {
        b.iter(|| verify(&slh_keypair.public_key, message, &slh_sig).unwrap());
    });

    group.finish();
}

// FN-DSA-512 BENCHMARKS

fn bench_fn_dsa_512_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("fn_dsa_keygen");
    configure_group(&mut group);

    group.bench_function("FN_DSA_512", |b| {
        b.iter(|| {
            let random_data = get_random_data(256);
            generate_keypair(Algorithm::FN_DSA_512, &random_data).unwrap()
        });
    });

    group.finish();
}

fn bench_fn_dsa_512_signing(c: &mut Criterion) {
    let mut group = c.benchmark_group("fn_dsa_signing");
    configure_group(&mut group);

    let message = b"This is a test message for benchmarking";
    let random_data = get_random_data(256);
    let fn_keypair = generate_keypair(Algorithm::FN_DSA_512, &random_data).unwrap();

    // Only print debug info if DEBUG_MODE is true
    if DEBUG_MODE {
        println!("FN-DSA-512 Keypair created for benchmarking:");
        println!(
            "Public key size: {}, Secret key size: {}",
            fn_keypair.public_key.bytes.len(),
            fn_keypair.secret_key.bytes.len()
        );
        println!(
            "Secret key first bytes: {:02x?}",
            &fn_keypair.secret_key.bytes[..8.min(fn_keypair.secret_key.bytes.len())]
        );

        // Verify we can sign once before benchmarking
        let test_sig = sign(&fn_keypair.secret_key, message, Some(&get_random_data(256))).unwrap();
        println!("Test signature size: {}", test_sig.bytes.len());
        println!(
            "Test signature first bytes: {:02x?}",
            &test_sig.bytes[..8.min(test_sig.bytes.len())]
        );
    } else {
        // Generate a test signature without debug output
        sign(&fn_keypair.secret_key, message, Some(&get_random_data(256))).unwrap();
    }

    // Now benchmark
    group.bench_function("FN_DSA_512", |b| {
        b.iter(|| {
            let random_data = get_random_data(256);
            sign(&fn_keypair.secret_key, message, Some(&random_data)).unwrap()
        });
    });

    group.finish();
}

fn bench_fn_dsa_512_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("fn_dsa_verification");
    configure_group(&mut group);

    let message = b"This is a test message for benchmarking";
    let random_data = get_random_data(256);
    let fn_keypair = generate_keypair(Algorithm::FN_DSA_512, &random_data).unwrap();
    let fn_sig = sign(&fn_keypair.secret_key, message, Some(&get_random_data(256))).unwrap();

    group.bench_function("FN_DSA_512", |b| {
        b.iter(|| verify(&fn_keypair.public_key, message, &fn_sig).unwrap());
    });

    group.finish();
}

// SIZE REPORTING - Combined in one benchmark

fn bench_sizes(c: &mut Criterion) {
    let group = c.benchmark_group("sizes");

    let message = b"This is a test message for benchmarking";

    // ML-DSA-44
    let random_data = get_random_data(256);
    let ml_keypair = generate_keypair(Algorithm::ML_DSA_44, &random_data).unwrap();
    let ml_sig = sign(&ml_keypair.secret_key, message, Some(&get_random_data(256))).unwrap();

    // SLH-DSA-128S
    let random_data = get_random_data(256);
    let slh_keypair = generate_keypair(Algorithm::SLH_DSA_128S, &random_data).unwrap();
    let slh_sig = sign(
        &slh_keypair.secret_key,
        message,
        Some(&get_random_data(256)),
    )
    .unwrap();

    // FN-DSA-512
    let random_data = get_random_data(256);
    let fn_keypair = generate_keypair(Algorithm::FN_DSA_512, &random_data).unwrap();
    let fn_sig = sign(&fn_keypair.secret_key, message, Some(&get_random_data(256))).unwrap();

    // Print key and signature sizes
    debug_println!("Key and Signature Sizes (bytes):");
    debug_println!("ML-DSA-44:");
    debug_println!(
        "  Public key: {}, Secret key: {}, Signature: {}",
        ml_keypair.public_key.bytes.len(),
        ml_keypair.secret_key.bytes.len(),
        ml_sig.bytes.len()
    );

    debug_println!("SLH-DSA-128S:");
    debug_println!(
        "  Public key: {}, Secret key: {}, Signature: {}",
        slh_keypair.public_key.bytes.len(),
        slh_keypair.secret_key.bytes.len(),
        slh_sig.bytes.len()
    );

    debug_println!("FN-DSA-512:");
    debug_println!(
        "  Public key: {}, Secret key: {}, Signature: {}",
        fn_keypair.public_key.bytes.len(),
        fn_keypair.secret_key.bytes.len(),
        fn_sig.bytes.len()
    );

    // secp256k1 for comparison
    let secp = Secp256k1::new();
    let keypair = Keypair::new(&secp, &mut OsRng);
    let secret_key = keypair.secret_key();
    let (xonly_pubkey, _) = keypair.x_only_public_key();
    let msg_bytes = create_32byte_array(message);
    let sig = secp.sign_schnorr(&msg_bytes, &keypair);

    debug_println!("secp256k1:");
    debug_println!(
        "  Public key: {}, Secret key: {}, Signature: {}",
        xonly_pubkey.serialize().len(),
        secret_key.secret_bytes().len(),
        sig.as_ref().len()
    );

    group.finish();
}

// SECP256K1 BENCHMARKS

fn bench_secp256k1_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("secp256k1_keygen");
    configure_group(&mut group);

    group.bench_function("secp256k1", |b| {
        b.iter(|| Keypair::new(&Secp256k1::new(), &mut OsRng));
    });

    group.finish();
}

fn bench_secp256k1_signing(c: &mut Criterion) {
    let mut group = c.benchmark_group("secp256k1_signing");
    configure_group(&mut group);

    let message = b"This is a test message for benchmarking";
    let secp = Secp256k1::new();
    let keypair = Keypair::new(&secp, &mut OsRng);
    let msg_bytes = create_32byte_array(message);

    group.bench_function("secp256k1", |b| {
        b.iter(|| secp.sign_schnorr(&msg_bytes, &keypair));
    });

    group.finish();
}

fn bench_secp256k1_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("secp256k1_verification");
    configure_group(&mut group);

    let message = b"This is a test message for benchmarking";
    let secp = Secp256k1::new();
    let keypair = Keypair::new(&secp, &mut OsRng);
    let msg_bytes = create_32byte_array(message);
    let sig = secp.sign_schnorr(&msg_bytes, &keypair);
    let xonly_pubkey = keypair.x_only_public_key().0;

    group.bench_function("secp256k1", |b| {
        b.iter(|| {
            secp.verify_schnorr(&sig, &msg_bytes, &xonly_pubkey)
                .unwrap()
        });
    });

    group.finish();
}

// Organize the benchmarks by algorithm rather than by operation
criterion_group!(
    ml_dsa_44_benches,
    bench_ml_dsa_44_keygen,
    bench_ml_dsa_44_signing,
    bench_ml_dsa_44_verification
);

criterion_group!(
    slh_dsa_128s_benches,
    bench_slh_dsa_128s_keygen,
    bench_slh_dsa_128s_signing,
    bench_slh_dsa_128s_verification
);

criterion_group!(
    fn_dsa_512_benches,
    bench_fn_dsa_512_keygen,
    bench_fn_dsa_512_signing,
    bench_fn_dsa_512_verification
);

criterion_group!(sizes_benches, bench_sizes);

// Create criterion group for secp256k1 benchmarks
criterion_group!(
    secp256k1_benches,
    bench_secp256k1_keygen,
    bench_secp256k1_signing,
    bench_secp256k1_verification
);

criterion_main!(
    ml_dsa_44_benches,
    slh_dsa_128s_benches,
    fn_dsa_512_benches,
    secp256k1_benches,
    sizes_benches,
);
