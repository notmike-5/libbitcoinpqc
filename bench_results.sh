#!/bin/bash
OUTPUT_FILE="benchmark_results.txt"
echo "Running benchmarks (this might take a while)..."
cargo bench $@ > $OUTPUT_FILE 2>&1
echo "Benchmark results saved to $OUTPUT_FILE"
echo "Summary of benchmark results:"
grep -A 3 "time:" $OUTPUT_FILE | grep -v "change:" | grep -v "\-\-"
