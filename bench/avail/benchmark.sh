#!/bin/bash
set -e
cd "$(dirname "$0")/../.."
mkdir -p bench/avail/logs

echo "Running..."
cd "bench/avail"
cargo build --release &> /dev/null
./target/release/benchmark > logs/log.txt
