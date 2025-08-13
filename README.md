# Frida-PoC: A FRI-based DA Scheme

> **Disclaimer:** This is a proof-of-concept prototype. This implementation is provided for research and evaluation purposes. It has not undergone a formal security audit or comprehensive code review and is **NOT ready for production use**. Use at your own risk.

This repository contains a proof-of-concept implementation of a FRI based DA scheme. It leverages the robust and performant components of the Winterfell STARK prover and verifier library to demonstrate the core principles of FRI.

The primary goal of this project is to provide a clear and well-structured implementation of the FRIDA protocol, suitable for research purposes.

## Project Structure

The codebase is organized into logical modules to ensure clarity and separation of concerns:

```
.
├── src/
│   ├── prover/      # Core logic for the FRI Prover, including proof generation
│   ├── verifier/    # Core logic for the FRI Verifier
│   ├── core/        # Standalone components: data encoding, query calculation, randomness
│   ├── commands/    # Implementation of the interactive CLI
│   ├── lib.rs       
│   └── main.rs      # Binary entrypoint for the CLI
└── bench/
    └── src/         # Source code for the performance benchmark suite
```

## Getting Started

### Prerequisites

- Rust toolchain (latest stable version is recommended). You can install it from [rustup.rs](https://rustup.rs/)

### Building the Project

Clone the repository and build the project using Cargo:

```bash
git clone https://github.com/NethermindEth/Frida-poc
cd frida-poc
cargo build --release
```

### Using the Interactive CLI

The project includes an interactive CLI for demonstrating the prover and verifier functionalities.

Run the CLI:

```bash
cargo run --release --features cli --bin cli
```

**Example Workflow:**

```bash
# 1. Generate some random data
> generate-data 1024 --data-path my_data.bin

# 2. Initialize the prover with FRI parameters
> init --data-path my_data.bin --blowup-factor 8 --folding-factor 4

# 3. Create a commitment and a proof for 32 queries
> commit 32 --data-path my_data.bin --commitment-path my_commitment.bin

# 4. Open a proof for specific positions (requires prover to be initialized)
> open 10 25 42 --data-path my_data.bin --proof-path my_proof.bin

# 5. Verify the generated proof
> verify --commitment-path my_commitment.bin --proof-path my_proof.bin
```

### Running the Benchmarks

The `bench/` directory contains a powerful suite for performance evaluation. Use the provided shell script for convenience.

Make the script executable:

```bash
chmod +x bench/benchmark.sh
```

Run a full benchmark suite (e.g., the defrida distributed workflow):

```bash
./bench/benchmark.sh defrida full
```

Results will be saved as CSV files in the `bench/results/` directory.

Run a custom benchmark:

```bash
./bench/benchmark.sh frida custom --blowup-factor 8 --folding-factor 4 --max-remainder-degree 31 --data-size 65536
```

## API Overview

### Core Types

- **`FridaProverBuilder`**: Main entry point for creating provers with specified FRI parameters, and generating commitments and proofs
- **`FridaProver`**: Stateful prover that can generate multiple proofs from the same commitment
- **`Commitment`**: Struct containing both commitment roots and proof for specific queries
- **`ProverCommitment`**: Struct containing only commitment roots
- **`FridaProof`**: Proof object that can be verified against evaluations and positions

### Key Functions

#### Commitment and Proving
```rust
// Generates both commitment and proof for num_queries number of positions.
pub fn commit_and_prove(&self, data: &[u8], num_queries: usize) -> Result<(Commitment<H>, FridaProver<E, H>), FridaError>
pub fn commit_and_prove_batch(&self, data_list: &[Vec<u8>], num_queries: usize) -> Result<(Commitment<H>, FridaProver<E, H>), FridaError>

// Generates only a commitment to the given data.
pub fn commitment(&self, data: &[u8], num_queries: usize) -> Result<(ProverCommitment<H>, FridaProver<E, H>, Vec<usize>), FridaError>
pub fn commitment_batch(&self, data_list: &[Vec<u8>], num_queries: usize) -> Result<(ProverCommitment<H>, FridaProver<E, H>, Vec<usize>), FridaError>
```

#### Proof Generation
```rust
// Generate proof for specific positions
pub fn open(&self, positions: &[usize]) -> FridaProof
```

#### Verification
```rust
// Verify proof against evaluations and positions
pub fn verify(&self, proof: &FridaProof, evaluations: &[E], positions: &[usize]) -> Result<(), FridaError>
```

## Benchmark Suite

The comprehensive benchmark suite in `bench/` provides three types of performance analysis:

- **FRIDA** (`frida`): Complete workflow benchmarking (commitment + proof + verification)
- **Single Proof Analysis** (`single-frida`): Single proof size and time analysis with storage estimates
- **deFRIDA** (`defrida`): Distributed workflow with validator assignments

See `bench/README.md` for detailed information about the benchmark suite.

## Contributing

This is a research prototype. Contributions, bug reports, and feedback are welcome! See [Contributing](./CONTRIBUTING.md)

## License
The crates in this repository are licensed under the following licence.

* Apache 2.0 license ([LICENSE](./LICENSE)) is applied to all commits


## Acknowledgments

This implementation builds upon the excellent [Winterfell](https://github.com/facebook/winterfell) library by Meta for cryptographic primitives and FRI implementation details.