# libbitcoinpqc

A C library with Rust bindings for Post-Quantum Cryptographic (PQC) signature algorithms. This library implements three NIST PQC standardized or candidate signature algorithms for use with [BIP-360](https://github.com/cryptoquick/bips/blob/p2qrh/bip-0360.mediawiki) and the Bitcoin QuBit soft fork:

1. **ML-DSA-44** (formerly CRYSTALS-Dilithium): A structured lattice-based digital signature scheme that is part of the NIST PQC standardization.
2. **SLH-DSA-Shake-128s** (formerly SPHINCS+): A stateless hash-based signature scheme with minimal security assumptions.
3. **FN-DSA-512** (formerly FALCON): A lattice-based signature scheme designed for efficiency and compact signatures.

Notice that all PQC signature algorithms used are certified according to the Federal Information Processing Standards, or FIPS. This should help in the future with native hardware support.

## Bitcoin QuBit Integration

This library serves as the cryptographic foundation for the Bitcoin QuBit soft fork, which aims to make Bitcoin's signature verification quantum-resistant through the implementation of BIP-360. QuBit introduces new post-quantum secure transaction types that can protect Bitcoin from potential threats posed by quantum computers.

## Features

- Clean, unified C API for all three signature algorithms
- Safe Rust bindings with memory safety and zero-copy operations
- User-provided entropy (bring your own randomness)
- Key generation, signing, and verification functions
- Minimal dependencies

## Key Characteristics

| Algorithm | Public Key Size | Secret Key Size | Signature Size | Security Level |
|-----------|----------------|----------------|----------------|----------------|
| ML-DSA-44 | 1,312 bytes | 2,528 bytes | 2,420 bytes | NIST Level 2 |
| SLH-DSA-Shake-128s | 32 bytes | 64 bytes | 7,856 bytes | NIST Level 1 |
| FN-DSA-512 | 897 bytes | 1,281 bytes | ~666 bytes (average) | NIST Level 1 |

See [REPORT.md](REPORT.md) for performance and size comparison to secp256k1.

## Dependencies

Cryptographic dependencies included in this project:

- https://github.com/sphincs/sphincsplus - `7ec789ace6874d875f4bb84cb61b81155398167e`
- https://github.com/pq-crystals/dilithium - `444cdcc84eb36b66fe27b3a2529ee48f6d8150c2`
- https://falcon-sign.info/Falcon-impl-20211101.zip

## Building the Library

### Prerequisites

- CMake 3.10 or higher
- C99 compiler
- Rust 1.50 or higher (for Rust bindings)

### Building

```bash
# Clone the repository
git clone https://github.com/bitcoin/libbitcoinpqc.git
cd libbitcoinpqc

# Build the C library using CMake
mkdir build
cd build
cmake ..
make

# Build the Rust library and bindings
cd ..
cargo build --release
```

## Fuzz Testing

This library includes fuzz testing targets using [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz).

### Prerequisites

```bash
# Install cargo-fuzz
cargo install cargo-fuzz
```

### Available Fuzz Targets

1. **keypair_generation** - Tests key pair generation with different algorithms
2. **sign_verify** - Tests signature creation and verification
3. **cross_algorithm** - Tests verification with mismatched keys and signatures from different algorithms

### Running Fuzz Tests

```bash
# Run a specific fuzz target
cargo fuzz run keypair_generation
cargo fuzz run sign_verify
cargo fuzz run cross_algorithm

# Run a fuzz target for a specific amount of time (in seconds)
cargo fuzz run keypair_generation -- -max_total_time=60

# Run a fuzz target with a specific number of iterations
cargo fuzz run sign_verify -- -runs=1000000
```

See `fuzz/README.md` for more details on fuzz testing.

## C API Usage

```c
#include <libbitcoinpqc/bitcoinpqc.h>

// Generate random data (from a secure source in production)
uint8_t random_data[256];
// Fill random_data with entropy...

// Generate a key pair
bitcoin_pqc_keypair_t keypair;
bitcoin_pqc_keygen(BITCOIN_PQC_MLDSA44, &keypair, random_data, sizeof(random_data));

// Sign a message
const uint8_t message[] = "Message to sign";
bitcoin_pqc_signature_t signature;
bitcoin_pqc_sign(BITCOIN_PQC_MLDSA44, keypair.secret_key, keypair.secret_key_size,
                message, sizeof(message) - 1, &signature);

// Verify the signature
bitcoin_pqc_error_t result = bitcoin_pqc_verify(BITCOIN_PQC_MLDSA44,
                                             keypair.public_key, keypair.public_key_size,
                                             message, sizeof(message) - 1,
                                             signature.signature, signature.signature_size);

// Clean up resources
bitcoin_pqc_signature_free(&signature);
bitcoin_pqc_keypair_free(&keypair);
```

## Rust API Usage

```rust
use bitcoinpqc::{Algorithm, generate_keypair, sign, verify};
use rand::{RngCore, rngs::OsRng};

// Generate random data for key generation
let mut random_data = vec![0u8; 128];
OsRng.fill_bytes(&mut random_data);

// Generate a key pair
let keypair = generate_keypair(Algorithm::MLDSA44, &random_data).unwrap();

// Create a message to sign
let message = b"Message to sign";

// Sign the message deterministically
let signature = sign(&keypair.secret_key, message).unwrap();

// Verify the signature
verify(&keypair.public_key, message, &signature).unwrap();
```

## Security Notes

- This library does not provide its own random number generation. Users must provide entropy from a secure source.
- Random data is required for key generation, but not for signing. All signatures are deterministic, based on the message and secret key.
- The implementations are based on reference code from the NIST PQC standardization process and are not production-hardened.
- Care should be taken to securely manage secret keys in applications.

## BIP-360 Compliance

This library implements the cryptographic primitives required by [BIP-360](https://github.com/bitcoin/bips/blob/master/bip-0360.mediawiki), which defines the standard for post-quantum resistant signatures in Bitcoin. It supports all three recommended algorithms with the specified parameter sets.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- The original NIST PQC competition teams for their reference implementations
- The NIST PQC standardization process for advancing post-quantum cryptography
- The Bitcoin QuBit soft fork contributors and BIP-360 authors
