# Fuzz Testing for libbitcoinpqc

This directory contains fuzz testing for the libbitcoinpqc library using [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz).

## Prerequisites

You need to have cargo-fuzz installed:

```
cargo install cargo-fuzz
```

## Available Fuzz Targets

1. **keypair_generation** - Tests key pair generation with different algorithms
2. **sign_verify** - Tests signature creation and verification
3. **cross_algorithm** - Tests verification with mismatched keys and signatures from different algorithms

## Running the Fuzz Tests

To run a specific fuzz target:

```
cargo fuzz run keypair_generation
cargo fuzz run sign_verify
cargo fuzz run cross_algorithm
```

To run a fuzz target for a specific amount of time:

```
cargo fuzz run keypair_generation -- -max_total_time=60
```

To run a fuzz target with a specific number of iterations:

```
cargo fuzz run keypair_generation -- -runs=1000000
```

## Corpus Management

Cargo-fuzz automatically manages a corpus of interesting inputs. You can find them in the `fuzz/corpus` directory once you've run the fuzz tests.

## Finding and Reporting Issues

If a fuzz test finds a crash, it will save the crashing input to `fuzz/artifacts`. You can reproduce the crash with:

```
cargo fuzz run target_name fuzz/artifacts/target_name/crash-*
```

When reporting an issue found by fuzzing, please include:
1. The exact command used to run the fuzzer
2. The crash input file
3. The full output of the crash

## Adding New Fuzz Targets

To add a new fuzz target:

1. Create a new Rust file in the `fuzz_targets` directory
2. Add the target to `fuzz/Cargo.toml`
3. Run the new target with `cargo fuzz run target_name`
