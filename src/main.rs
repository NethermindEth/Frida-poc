use clap::{Parser, Subcommand};
use frida_poc::commands;
use frida_poc::frida_prover::{traits::BaseFriProver, FridaProver};
use std::fs;
use std::io::{self, Write};
use winter_crypto::hashers::Blake3_256;
use winter_fri::FriOptions;
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

#[derive(Subcommand, Debug)]
enum Commands {
    /// Initialize the prover and data
    Init {
        /// Data Path
        #[arg(long, default_value = "data/data.bin")]
        data_path: String,
        /// Blowup factor
        #[arg(long, default_value = "8")]
        blowup_factor: usize,
        /// Folding factor
        #[arg(long, default_value = "2")]
        folding_factor: usize,
        /// Number of layers
        #[arg(long, default_value = "7")]
        max_remainder_degree: usize,
    },
    /// Generate random data
    GenerateData {
        /// Size of the data
        size: usize,
        /// Path to the data file
        #[arg(long, default_value = "data/data.bin")]
        data_path: String,
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
    let mut prover: Option<FridaProverType> = None;

    loop {
        match read_and_parse_command() {
            Ok(cli) => match cli.command {
                Commands::Init { .. } => {
                    prover = handle_init(cli.command);
                }
                Commands::GenerateData { .. } => {
                    handle_generate_data(cli.command);
                }
                Commands::Commit { .. } => {
                    handle_commit(cli.command, &mut prover);
                }
                Commands::Open { .. } => {
                    handle_open(cli.command, &mut prover);
                }
                Commands::Verify { .. } => {
                    handle_verify(cli.command, &mut prover);
                }
            },
            Err(err) => {
                eprintln!("Error: {}", err);
            }
        }
    }
}

fn read_and_parse_command() -> Result<Cli, String> {
    print!("Enter command: ");
    io::stdout().flush().unwrap();

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|_| "Failed to read input.".to_string())?;
    let input = input.trim();

    if input.eq_ignore_ascii_case("exit") {
        std::process::exit(0);
    }

    let args = match shlex::split(input) {
        Some(mut args) => {
            args.insert(0, "frida-poc".to_string());
            args
        }
        None => return Err("Failed to parse input.".to_string()),
    };

    Cli::try_parse_from(args).map_err(|err| err.to_string())
}

fn handle_init(cmd: Commands) -> Option<FridaProverType> {
    if let Commands::Init {
        data_path,
        blowup_factor,
        folding_factor,
        max_remainder_degree,
    } = cmd
    {
        println!(
            "Initializing prover with data path: {}, blowup factor: {}, folding factor: {}, max remainder degree: {}",
            data_path, blowup_factor, folding_factor, max_remainder_degree
        );
        let options = FriOptions::new(blowup_factor, folding_factor, max_remainder_degree);
        if let Err(err) = fs::read(&data_path) {
            eprintln!(
                "Failed to read data file: {}\nUse `generate-data <SIZE>` command.",
                err
            );
            return None;
        }
        Some(FridaProverType::new(options))
    } else {
        None
    }
}

fn handle_generate_data(cmd: Commands) {
    if let Commands::GenerateData { size, data_path } = cmd {
        if let Err(err) = commands::generate_data::run(size, &data_path) {
            eprintln!("Failed to generate data: {}", err);
        }
    }
}

fn handle_commit(cmd: Commands, prover: &mut Option<FridaProverType>) {
    let prover = match_prover(prover);

    if let Commands::Commit {
        num_queries,
        data_path,
        commitment_path,
    } = cmd
    {
        if let Err(err) = commands::commit::run(prover, num_queries, &data_path, &commitment_path) {
            eprintln!("Failed to commit data: {}", err);
        }
    }
}

fn handle_open(cmd: Commands, prover: &mut Option<FridaProverType>) {
    let prover = match_prover(prover);

    if let Commands::Open {
        positions,
        positions_path,
        evaluations_path,
        proof_path,
    } = cmd
    {
        if let Err(err) = commands::open::run(
            prover,
            &positions,
            &positions_path,
            &evaluations_path,
            &proof_path,
        ) {
            eprintln!("Failed to open proof: {}", err);
        }
    }
}

fn handle_verify(cmd: Commands, prover: &mut Option<FridaProverType>) {
    let prover = match_prover(prover);

    if let Commands::Verify {
        commitment_path,
        positions_path,
        evaluations_path,
        proof_path,
    } = cmd
    {
        if let Err(err) = commands::verify::run(
            &commitment_path,
            &positions_path,
            &evaluations_path,
            &proof_path,
            prover.options().clone(),
        ) {
            eprintln!("Failed to verify proof: {}", err);
            return;
        }
        println!("Verification successful");
    }
}

fn match_prover(prover: &mut Option<FridaProverType>) -> &mut FridaProverType {
    match prover.as_mut() {
        Some(prover) => prover,
        None => {
            eprintln!("Please call the init command first.");
            std::process::exit(1);
        }
    }
}
