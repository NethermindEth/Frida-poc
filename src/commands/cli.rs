use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "frida_cli")]
#[command(about = "A CLI for the Frida Verifier", long_about = None)]
pub(super) struct Cli {
    #[command(subcommand)]
    pub(super) command: Commands,
}

#[derive(Subcommand, Debug)]
pub(super) enum Commands {
    /// Initialize the prover with FRI parameters and a data file
    Init {
        /// Path to the data file that will be used
        #[arg(long, default_value = "data/data.bin")]
        data_path: PathBuf,
        /// Blowup factor for the FRI protocol
        #[arg(long, default_value = "8")]
        blowup_factor: usize,
        /// Folding factor for the FRI protocol
        #[arg(long, default_value = "2")]
        folding_factor: usize,
        /// Maximum degree of the remainder polynomial
        #[arg(long, default_value = "7")]
        max_remainder_degree: usize,
    },
    /// Generate a file with random data
    GenerateData {
        /// The size of the data to generate, in bytes
        size: usize,
        /// Path to write the data file
        #[arg(long, default_value = "data/data.bin")]
        data_path: PathBuf,
    },
    /// Commit to the data and generate a full proof for a set of queries
    Commit {
        /// Number of queries to generate in the proof
        num_queries: usize,
        /// Path to the data file to commit to
        #[arg(long, default_value = "data/data.bin")]
        data_path: PathBuf,
        /// Path to write the resulting commitment file
        #[arg(long, default_value = "data/commitment.bin")]
        commitment_path: PathBuf,
    },
    /// Open a proof for a given set of positions
    Open {
        /// The positions (indices) to open in the proof
        positions: Vec<usize>,
        /// Path to write the positions file
        #[arg(long, default_value = "data/positions.bin")]
        positions_path: PathBuf,
        /// Path to write the opened evaluations file
        #[arg(long, default_value = "data/evaluations.bin")]
        evaluations_path: PathBuf,
        /// Path to the source data file
        #[arg(long, default_value = "data/data.bin")]
        data_path: PathBuf,
        /// Path to write the resulting proof file
        #[arg(long, default_value = "data/proof.bin")]
        proof_path: PathBuf,
    },
    /// Verify a proof against a commitment
    Verify {
        /// Path to the commitment file
        #[arg(long, default_value = "data/commitment.bin")]
        commitment_path: PathBuf,
        /// Path to the positions file
        #[arg(long, default_value = "data/positions.bin")]
        positions_path: PathBuf,
        /// Path to the evaluations file
        #[arg(long, default_value = "data/evaluations.bin")]
        evaluations_path: PathBuf,
        /// Path to the proof file
        #[arg(long, default_value = "data/proof.bin")]
        proof_path: PathBuf,
    },
}
