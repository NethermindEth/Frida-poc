# Frida Benchmark Suite

A comprehensive benchmark suite for evaluating the performance of Frida's FRI implementations across different usage patterns and configurations.

## Overview

This benchmark suite provides three distinct benchmarking modes to evaluate different aspects of the Frida FRI system:

- **FRIDA** (`frida`) - Complete FRI workflow including commitment, proof generation, and verification
- **FRIDA Single Proof Analysis** (`single-frida`) - Focused analysis of single proof generation
- **deFRIDA** (`defrida`) - Distributed proving workflow with per validator proof assignments

## File Structure
The benchmark suite is built on a modular, trait-based runner to maximize code reuse and simplify adding new benchmarks.

```
bench/
├── src/
│   ├── main.rs           # CLI entry point and command routing
│   ├── common.rs         # Shared utilities, types, and parsers
│   ├── runner.rs         # Generic benchmark runner and the core Benchmark trait
│   ├── frida.rs          # FRIDA benchmark implementation
│   ├── single_frida.rs   # Single proof analysis implementation
│   └── defrida.rs        # deFRIDA benchmark implementation
├── benchmark.sh          # Shell script wrapper for easy execution
├── results/              # Output directory for CSV files (auto-created)
└── README.md            
```

## Quick Start

### Prerequisites

- Rust toolchain with `cargo`
- Feature flag bench enabled for compilation (`cargo build --features "bench"`)

### Basic Usage

```bash
# Make script executable (first time only)
chmod +x benchmark.sh

# Run full benchmark suites
./benchmark.sh frida full
./benchmark.sh single-frida full  
./benchmark.sh defrida full

# Run custom benchmarks
./benchmark.sh frida custom --fri-options "(2,2,0),(2,2,256)" --data-size "32768,65536" --field "f128"
./benchmark.sh single-frida custom --fri-options "(2,2,0),(2,2,256)" --data-size 65536 --batch-size "2,4" --field both
./benchmark.sh defrida custom --fri-options "(4,2,15)" --data-size 65536 --num-validators "16,32" --batch-size "1,4" --num-queries 64 --field "f128"
```
## Command Line Interface

### Global Structure

```bash
./benchmark.sh [BENCHMARK_TYPE] [COMMAND] [OPTIONS]
```
- **BENCHMARK_TYPE**: `frida`, `single-frida`, or `defrida`.

- **COMMAND**:
    - `--full`: Runs a comprehensive benchmark across all standard configurations defined in common.rs.
    - `custom`: Runs a benchmark with the user-specified parameters below.

### Custom Benchmark Options
#### Common Options
- `--fri-options "(B,F,R),(B,F,R),..."`
    - One or more FRI option tuples for (Blowup, Folding, Remainder Degree).
    - Must be a single string with tuples separated by commas.
    - Example: `--fri-options "(2,2,0),(4,2,3)"`
- `--data-size N,N,...`
    - Comma-separated list of data sizes in bytes.
    - Example: `--data-size "32768,65536"`
- `--batch-size N,N,...`
    - Comma-separated list of batch sizes. 1 indicates a non-batched run.
- `--field [f64|f128|both]`
    - The field type to run the benchmark on. Defaults to both.
- `--output FILE`
    - Specify the output CSV file path.

#### Benchmark-Specific Options
- `frida`:
    - `--num-queries N,N,...`: Comma-separated list of query counts.
- `defrida`:
    - `--num-validators N,N,...`: Comma-separated list of validator counts.
    - `--num-queries N,N,...`: Comma-separated list of total query positions.

## Benchmark Types

### 1. Original FRIDA (`frida`)

Benchmarks the complete FRIDA workflow including commitment generation, proof creation, and verification.

**Key Metrics:**

- Erasure coding time
- Commitment generation time  
- Proof generation time (1, 16, 32 positions)
- Verification setup and execution time
- Commitment and proof sizes

**CSV Output:** `bench/results/frida_full.csv` or custom path

### 2. Single Proof Analysis (`single-frida`)

Analyzes single proof generation performance and calculates upper bound for all openings' proof size.

**Key Metrics:**

- Single proof generation time
- Single proof size
- All openings' proof size upper bound (domain_size × single_proof_size)


**CSV Output:** `bench/results/single_frida_full.csv` or custom path

### 3. Distributed deFRIDA (`defrida`)

Benchmarks the distributed proving workflow where validators receive proof for assigned query positions.

**Key Metrics:**

- Commitment phase time and size
- Per-validator proof generation time and size
- Verification setup and execution time

**CSV Output:** `bench/results/defrida_full.csv` or custom path

## Configuration Parameters

### FRI Options (Consistent Across All Benchmarks)

```
(blowup_factor, folding_factor, max_remainder_degree)
(2, 2, 0), (2, 2, 256), (2, 4, 2), (2, 4, 256),
(2, 8, 4), (2, 8, 256), (2, 16, 8), (2, 16, 256)
```

### Standard Data Sizes

- Field-dependent, ranging from ~128KB to ~2MB equivalent
- Automatically adjusted for f64 vs f128 field element sizes

### Batch Sizes

- **Non-batched:** 1 polynomial
- **Batched:** 2, 4, 8, 16 polynomials

### Field Types

- **f64:** 64-bit field elements
- **f128:** 128-bit field elements


## Integration

### How it Works
The core logic is in `runner.rs`, which defines a `Benchmark` trait and a generic `run_benchmark` function. The runner takes any struct that implements the `Benchmark` trait and automatically handles iterating through all parameter combinations using `itertools::iproduct!`.

### Adding a New Benchmark
1. **Create a New Module**: Add a new file in `src/`, for example, `my_benchmark.rs`.

2. **Define Result Struct**: Inside the new file, d efine a `pub struct MyBenchmarkResult` to hold the output data for a single run, and implement `csv_header()` and `to_csv()` methods for it.

3. **Implement Benchmark Logic**: Create the core `benchmark_non_batched` and `benchmark_batched` functions.

4. **Implement the Trait**:
    - Create an empty struct: `pub struct MyBenchmark`;
    - Implement the `runner::Benchmark` trait for `MyBenchmark`, calling your logic functions from within the trait methods.

5. **Update `main.rs`**:
    - Add your new module: `mod my_benchmark`;
    - Add a new variant to the `Commands` enum: `MyBenchmark(BenchmarkArgs<MyBenchmarkCustom>)`.
    - Create a `MyBenchmarkCustom` struct to define its specific CLI arguments.
    - Add a match arm to handle the new command, construct the `BenchmarkConfig`, and call `run_benchmark(my_benchmark::MyBenchmark, config)`.

## Troubleshooting

### Common Issues

- **Build failures:** Ensure `bench` feature is enabled
- **Permission errors:** Make sure `benchmark.sh` is executable
- **Memory issues:** Reduce concurrent configurations or data sizes
- **Invalid parameters:** Check FRI parameter validity (powers of 2, etc.)
