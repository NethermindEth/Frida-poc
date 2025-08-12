# Frida Benchmark Suite

A comprehensive benchmark suite for evaluating the performance of Frida's FRI implementations across different usage patterns and configurations.

## Overview

This benchmark suite provides three distinct benchmarking modes to evaluate different aspects of the Frida FRI system:

- **FRIDA** (`frida`) - Complete FRI workflow including commitment, proof generation, and verification
- **FRIDA Single Proof Analysis** (`single-frida`) - Focused analysis of single proof generation
- **deFRIDA** (`defrida`) - Distributed proving workflow with per validator proof assignments

## File Structure

```
bench/
├── src/
│   ├── main.rs           # CLI entry point with subcommand routing
│   ├── common.rs         # Shared utilities, FRI options, and type definitions
│   ├── frida.rs          # FRIDA benchmarking implementation
│   ├── single_frida.rs   # FRIDA single proof analysis implementation
│   └── defrida.rs        # DeFRIDA benchmarking implementation
├── benchmark.sh          # Shell script wrapper for easy execution
├── results/              # Output directory for CSV files (auto-created)
└── README.md            
```

## Quick Start

### Prerequisites
- Rust toolchain with `cargo`
- Feature flag `bench` enabled for compilation

### Basic Usage

```bash
# Make script executable (first time only)
chmod +x benchmark.sh

# Run full benchmark suites
./benchmark.sh frida full
./benchmark.sh single-frida full  
./benchmark.sh defrida full

# Run custom benchmarks
./benchmark.sh frida custom --blowup-factor 2 --folding-factor 2 --max-remainder-degree 256 --data-size 32768 --batch-size 4
./benchmark.sh single-frida custom --blowup-factor 2 --folding-factor 2 --max-remainder-degree 256 --data-size 32768 --batch-size 4
./benchmark.sh defrida custom --blowup-factor 2 --folding-factor 2 --max-remainder-degree 256 --data-size 32768 --num-validators 8 --num-queries 32 --batch-size 4
```

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

## Command Line Interface

### Global Structure
```bash
./benchmark.sh [BENCHMARK_TYPE] [COMMAND] [OPTIONS]
```

### Benchmark Types
- `frida` - Traditional FRI benchmarking
- `single-frida` - Single proof analysis  
- `defrida` - Distributed workflow

### Commands
- `full` - Run comprehensive benchmark across all standard configurations
- `custom` - Run with user-specified parameters
- `help` - Display usage information

### Common Options
- `--output FILE` - Specify output CSV file path
- `--blowup-factor N` - FRI blowup factor
- `--folding-factor N` - FRI folding factor  
- `--max-remainder-degree N` - Maximum remainder polynomial degree
- `--data-size N` - Input data size in bytes
- `--batch-size N` - Number of polynomials to batch (default: 1)

### Benchmark-Specific Options

**Frida:**
- `--num-queries N` - Number of query positions (default: 32)

**deFRIDA:**
- `--num-validators N` - Number of validators in distributed setup
- `--num-queries N` - Total number of query positions

## Output Format

All benchmarks generate CSV files with descriptive headers and consistent units:

- **Time:** Milliseconds (ms)
- **Size:** Bytes  
- **Data Size:** Kilobytes (KB)
- **Large Estimates:** Megabytes (MB)

## Integration

### Adding New Benchmarks
1. Create new module in `src/` 
2. Add benchmark type to CLI enum in `main.rs`
3. Update shell script with new commands
4. Follow existing patterns for consistency

### Extending Configurations
- Modify `common.rs` for new FRI parameter sets
- Update standard data sizes or batch configurations
- Maintain backward compatibility with existing output formats

## Troubleshooting

### Common Issues
- **Build failures:** Ensure `bench` feature is enabled
- **Permission errors:** Make sure `benchmark.sh` is executable
- **Memory issues:** Reduce concurrent configurations or data sizes
- **Invalid parameters:** Check FRI parameter validity (powers of 2, etc.)

