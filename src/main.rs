use clap::{Parser, Subcommand};
use frida_poc::commands;
use frida_poc::frida_prover::{traits::BaseFriProver, FridaProver};
use frida_poc::utils;
use winter_crypto::hashers::Blake3_256;
use winter_math::fields::f128::BaseElement;

use frida_poc::{frida_prover_channel::FridaProverChannel, frida_random::FridaRandom};

type Blake3 = Blake3_256<BaseElement>;
type FridaChannel =
    FridaProverChannel<BaseElement, Blake3, Blake3, FridaRandom<Blake3, Blake3, BaseElement>>;
type FridaProverType = FridaProver<BaseElement, BaseElement, FridaChannel, Blake3>;

#[derive(Parser)]
#[command(name = "frida_cli")]
#[command(about = "A CLI for the Frida Verifier", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize settings
    Init,
    /// Generate random data
    GenerateData {
        /// Size of the data
        size: usize,
        /// Path to the data file
        #[arg(long, default_value = "data/data.bin")]
        file_path: String,
    },
    /// Commit data and generate a proof
    Commit {
        /// Number of queries to generate
        num_queries: usize,
        /// Path to the data file
        #[arg(long, default_value = "data/data.bin")]
        data_path: String,
        /// Path to the commitment file
        #[arg(long, default_value = "data/commitment.bin")]
        commitment_path: String,
    },
    /// Open a proof for a given position
    Open {
        /// Position to open
        positions: Vec<usize>,
        /// Path to the proof file
        #[arg(long, default_value = "data/proof.bin")]
        proof_path: String,
    },
    /// Verify a proof
    Verify {
        /// Path to the commitment file
        #[arg(long, default_value = "data/commitment.bin")]
        commitment_path: String,
        /// Path to the positions file
        #[arg(long, default_value = "data/positions.bin")]
        positions_path: String,
        /// Path to the evaluations file
        #[arg(long, default_value = "data/evaluations.bin")]
        evaluations_path: String,
        /// Path to the proof file
        #[arg(long, default_value = "data/proof.bin")]
        proof_path: String,
    },
}

fn main() {
    let cli = Cli::parse();
    let mut prover = FridaProverType::new(utils::load_fri_options(None));

    match &cli.command {
        Commands::Init => {
            let options = utils::load_fri_options(None);
            prover = FridaProverType::new(options);
        }
        Commands::GenerateData { size, file_path } => {
            commands::generate_data::run(*size, file_path).expect("Failed to generate data");
        }
        Commands::Commit {
            data_path,
            commitment_path,
            num_queries,
        } => {
            commands::commit::run(&mut prover, *num_queries, data_path, commitment_path)
                .expect("Failed to commit data");
        }
        Commands::Open {
            positions,
            proof_path,
        } => {
            commands::open::run(&mut prover, proof_path, positions).expect("Failed to open proof");
        }
        Commands::Verify {
            commitment_path,
            positions_path,
            evaluations_path,
            proof_path,
        } => commands::verify::run(
            commitment_path,
            positions_path,
            evaluations_path,
            proof_path,
        ),
    }
}
