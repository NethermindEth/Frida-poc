use clap::{Parser, Subcommand};
use frida_poc::commands;
use frida_poc::utils;

#[derive(Parser)]
#[command(name = "frida_cli")]
#[command(about = "A CLI for the Frida Verifier", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
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
        /// Path to the data file
        #[arg(long, default_value = "data/data.bin")]
        data: String,
        /// Path to the commitment file
        #[arg(long, default_value = "data/commitment.bin")]
        commitment_path: String,
        /// Number of queries to generate
        num_queries: usize,
        /// Path to the FriOptions file (optional)
        #[arg(long)]
        fri_options_path: Option<String>,
    },
    /// Open a proof for a given position
    Open {
        /// Path to the proof file
        proof: String,
        /// Position to open
        position: usize,
        /// Path to the FriOptions file (optional)
        #[arg(long)]
        fri_options_path: Option<String>,
    },
    /// Verify a proof
    Verify {
        /// Path to the proof file
        proof: String,
        /// Path to the data file
        data: String,
        /// Position to verify
        position: usize,
        /// Path to the FriOptions file (optional)
        #[arg(long)]
        fri_options_path: Option<String>,
    },
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::GenerateData { size, file_path } => {
            commands::generate_data::run(*size, file_path).unwrap();
        }
        Commands::Commit {
            data,
            commitment_path,
            num_queries,
            fri_options_path,
        } => {
            let options = utils::load_fri_options(fri_options_path.as_ref());
            commands::commit::run(data, commitment_path, *num_queries, options).unwrap();
        }
        Commands::Open {
            proof,
            position,
            fri_options_path,
        } => {
            let options = utils::load_fri_options(fri_options_path.as_ref());
            commands::open::run(proof, *position, options);
        }
        Commands::Verify {
            proof,
            data,
            position,
            fri_options_path,
        } => {
            let options = utils::load_fri_options(fri_options_path.as_ref());
            commands::verify::run(proof, data, *position, options);
        }
    }
}
