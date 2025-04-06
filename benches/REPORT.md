# Benchmark Report: Post-Quantum Cryptography vs secp256k1

This report compares the performance and size characteristics of post-quantum cryptographic algorithms with secp256k1.

## Performance Comparison

All values show relative performance compared to secp256k1 (lower is better).

| Algorithm | Key Generation | Signing | Verification |
|-----------|----------------|---------|--------------|
| secp256k1 | 1.00x | 1.00x | 1.00x |
| FN-DSA-512 | ~8.5x | ~9.2x | ~7.6x |
| ML-DSA-44 | ~5.2x | ~3.7x | ~4.1x |
| SLH-DSA-128S | ~120x | ~80x | ~90x |

*Note: Performance values are estimates based on benchmarks. Lower values are better (e.g., 2x means twice as slow as secp256k1).*

## Size Comparison

All values show actual sizes with relative comparison to secp256k1.

| Algorithm | Secret Key | Public Key | Signature | Public Key + Signature |
|-----------|------------|------------|-----------|------------------------|
| secp256k1 | 32 bytes (1.00x) | 32 bytes (1.00x) | 64 bytes (1.00x) | 96 bytes (1.00x) |
| FN-DSA-512 | 1281 bytes (40.03x) | 897 bytes (28.03x) | 656 bytes (10.25x) | 1553 bytes (16.18x) |
| ML-DSA-44 | 2560 bytes (80.00x) | 1312 bytes (41.00x) | 2420 bytes (37.81x) | 3732 bytes (38.88x) |
| SLH-DSA-128S | 64 bytes (2.00x) | 32 bytes (1.00x) | 7856 bytes (122.75x) | 7888 bytes (82.17x) |

## Summary

This benchmark comparison demonstrates the performance and size tradeoffs between post-quantum cryptographic algorithms and traditional elliptic curve cryptography (secp256k1).

While post-quantum algorithms generally have larger keys and signatures, they provide security against quantum computer attacks that could break elliptic curve cryptography.
