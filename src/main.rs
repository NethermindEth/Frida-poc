use clap::{Parser, Subcommand};
use frida_poc::commands;
use frida_poc::frida_data::encoded_data_element_count;
use frida_poc::frida_prover::{traits::BaseFriProver, FridaProver};
use frida_poc::utils;
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
    // Initialize prover with default options
    let mut prover = FridaProverType::new(utils::load_fri_options(None));
    let mut encoded_element_count: usize = 0;
    let mut init_done = false;

    loop {
        print!("Enter command: ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        let input = input.trim();

        // Allow user to exit the loop
        if input.eq_ignore_ascii_case("exit") {
            break;
        }

        // Split input into arguments and parse them
        let args = match shlex::split(input) {
            Some(mut args) => {
                args.insert(0, "frida-poc".to_string());
                args
            }
            None => {
                eprintln!("Failed to parse input.");
                continue;
            }
        };

        let cli = match Cli::try_parse_from(args) {
            Ok(cli) => cli,
            Err(err) => {
                eprintln!("Error: {}", err);
                continue;
            }
        };

        match &cli.command {
            Commands::Init {
                data_path,
                blowup_factor,
                folding_factor,
                max_remainder_degree,
            } => {
                handle_init(
                    &mut prover,
                    data_path,
                    *blowup_factor,
                    *folding_factor,
                    *max_remainder_degree,
                    &mut encoded_element_count,
                    &mut init_done,
                );
            }

            Commands::GenerateData { size, file_path } => {
                handle_generate_data(*size, file_path);
            }

            Commands::Commit {
                num_queries,
                data_path,
                commitment_path,
            } => {
                if !init_done {
                    eprintln!("Please call the init command first.");
                    continue;
                }
                handle_commit(&mut prover, *num_queries, data_path, commitment_path);
            }

            Commands::Open {
                positions,
                positions_path,
                evaluations_path,
                proof_path,
            } => {
                if !init_done {
                    eprintln!("Please call the init command first.");
                    continue;
                }
                handle_open(
                    &mut prover,
                    positions,
                    positions_path,
                    evaluations_path,
                    proof_path,
                );
            }

            Commands::Verify {
                commitment_path,
                positions_path,
                evaluations_path,
                proof_path,
            } => {
                if !init_done {
                    eprintln!("Please call the init command first.");
                    continue;
                }
                handle_verify(
                    commitment_path,
                    positions_path,
                    evaluations_path,
                    proof_path,
                    encoded_element_count,
                    prover.options().clone(),
                );
            }
        }
    }
}

fn handle_init(
    prover: &mut FridaProverType,
    data_path: &str,
    blowup_factor: usize,
    folding_factor: usize,
    max_remainder_degree: usize,
    encoded_element_count: &mut usize,
    init_done: &mut bool,
) {
    println!(
        "Initializing prover with data path: {}, blowup factor: {}, folding factor: {}, max remainder degree: {}",
        data_path, blowup_factor, folding_factor, max_remainder_degree
    );
    let options = FriOptions::new(blowup_factor, folding_factor, max_remainder_degree);
    *prover = FridaProverType::new(options);
    if let Err(err) = fs::read(data_path) {
        eprintln!(
            "Failed to read data file: {}\nUse `generate-data <SIZE>` command.",
            err
        );
        return;
    }
    *encoded_element_count =
        encoded_data_element_count::<BaseElement>(fs::read(data_path).unwrap().len())
            .next_power_of_two();
    *init_done = true;
}

fn handle_generate_data(size: usize, file_path: &str) {
    if let Err(err) = commands::generate_data::run(size, file_path) {
        eprintln!("Failed to generate data: {}", err);
    }
}

fn handle_commit(
    prover: &mut FridaProverType,
    num_queries: usize,
    data_path: &str,
    commitment_path: &str,
) {
    if let Err(err) = commands::commit::run(prover, num_queries, data_path, commitment_path) {
        eprintln!("Failed to commit data: {}", err);
    }
}

fn handle_open(
    prover: &mut FridaProverType,
    positions: &[usize],
    positions_path: &str,
    evaluations_path: &str,
    proof_path: &str,
) {
    if let Err(err) = commands::open::run(
        prover,
        positions,
        positions_path,
        evaluations_path,
        proof_path,
    ) {
        eprintln!("Failed to open proof: {}", err);
    }
}

fn handle_verify(
    commitment_path: &str,
    positions_path: &str,
    evaluations_path: &str,
    proof_path: &str,
    encoded_element_count: usize,
    options: FriOptions,
) {
    if commands::verify::run(
        commitment_path,
        positions_path,
        evaluations_path,
        proof_path,
        encoded_element_count,
        options,
    )
    .is_err()
    {
        eprintln!("Verification failed");
        return;
    }
    println!("Verification successful");
}
