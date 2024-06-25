#!/bin/bash
set -e
cd "$(dirname "$0")/../.."
mkdir -p bench/fri/logs

echo "Running with concurrency disabled..."
cargo build --bin benchmark --release --features "bench" &> /dev/null
./target/release/benchmark > bench/fri/logs/single.txt

echo "Running with concurrency enabled..."
cargo build --bin benchmark --release --features "concurrent, bench" &> /dev/null
./target/release/benchmark > bench/fri/logs/multi.txt
