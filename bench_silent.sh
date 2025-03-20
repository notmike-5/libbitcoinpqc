#!/bin/bash
cargo bench $@ 2>/dev/null >/dev/null || (echo "Benchmark failed"; exit 1)
echo "Benchmarks completed successfully"
