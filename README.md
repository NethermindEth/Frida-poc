# Frida-POC

## Getting Started

### Prerequisites

- rustc >= 1.78.0

### Run with Cargo

`cargo run --bin frida-poc`

## Getting Started

<!--TODO: Why do I start with this?-->

1. Generate data

## Commands

### Generate Data

**Usage:**

- `generate-data <size>`
  Generates a random data file of the specified size (in bytes)
  - `size`: Size of the data in bytes
  - e.g. `generate 200` (size ≥ 200)
- **Options**
  - `data_path`: Path to the data file. (default: data/data.bin)

**Note:** Use double dash(—) when using options.
e.g. `generate-data 200 --data_path custom/data.bin`

### Init

**Usage:**

- `init`
  Initializes the system with default values. Should be called at the start.
  - e.g. `init`
- **options**
  - `data_path`: Path to the data file. (default: data/data.bin)
  - `blowup_factor`: Blowup factor of the evaluation domain (power of two) (default: 8)
  - `folding_factor`: Factor by which the degree of a polynomial is reduced with each FRI layer (one of 2, 4, 8, 16) (default: 2)
  - `max_remainder_degree`: Maximum allowed remainder polynomial degree (default: 7)

**Note:** Ensure the data file is present at the specified path. If not, use the `generate-data` command to create the data first.

### Commit

**Usage:**

- `commit <num_queries>`
  - e.g. `commit 31`
- **options**

### Open

**Usage:**

- `open <positions>`
  - e.g. `open 1 2 4` , `open 5`
- **options**

### Verify

**Usage:**

- `verify`
- **options**

## Why Interactive?

When Prover `commit` to the polynomial, it stores layers and remainder polynomial.
And use them when `open` the position.

To implement this process in a normal CLI that terminates the program after every command, I would need to serialize and deserialize the entire Prover's state, sharing it via a file. Implementing all serialization and deserialization looked too time consuming.

So I just made it interactive, so that the state of the prover can remain between commands.
