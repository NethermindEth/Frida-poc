use clap::{Parser, Subcommand};
use serde::Deserialize;
use std::fs;
use winter_fri::FriOptions;

mod commands;

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
        file_path: Option<String>,
    },
    /// Commit data and generate a proof
    Commit {
        /// Path to the data file
        #[arg(long, default_value = "data/data.bin")]
        data: String,
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

#[derive(Deserialize)]
struct FriOptionsConfig {
    blowup_factor: usize,
    folding_factor: usize,
    max_remainder_degree: usize,
}

fn load_fri_options(file_path: Option<&String>) -> FriOptions {
    if let Some(path) = file_path {
        let file_content = fs::read_to_string(path).expect("Unable to read FriOptions file");
        let config: FriOptionsConfig =
            serde_json::from_str(&file_content).expect("Invalid FriOptions file format");
        FriOptions::new(
            config.blowup_factor,
            config.folding_factor,
            config.max_remainder_degree,
        )
    } else {
        FriOptions::new(8, 2, 7)
    }
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::GenerateData { size, file_path } => {
            commands::generate_data::run(*size, file_path.as_deref().unwrap());
        }
        Commands::Commit {
            data,
            num_queries,
            fri_options_path,
        } => {
            let options = load_fri_options(fri_options_path.as_ref());
            commands::commit::run(data, *num_queries, options);
        }
        Commands::Open {
            proof,
            position,
            fri_options_path,
        } => {
            let options = load_fri_options(fri_options_path.as_ref());
            commands::open::run(proof, *position, options);
        }
        Commands::Verify {
            proof,
            data,
            position,
            fri_options_path,
        } => {
            let options = load_fri_options(fri_options_path.as_ref());
            commands::verify::run(proof, data, *position, options);
        }
    }
}
