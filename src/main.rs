use clap::{Parser, Subcommand};
use frida_poc::{
    commands,
    frida_prover::{traits::BaseFriProver, FridaProver},
    frida_prover_channel::FridaProverChannel,
    frida_random::FridaRandom,
};
use std::{
    fs,
    io::{self, Write},
    path::PathBuf,
};
use winter_crypto::hashers::Blake3_256;
use winter_fri::FriOptions;
use winter_math::fields::f128::BaseElement;

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
        data_path: PathBuf,
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
        data_path: PathBuf,
    },
    /// Commit data and generate a proof
    Commit {
        /// Number of queries to generate
        num_queries: usize,
        /// Path to the data file
        #[arg(long, default_value = "data/data.bin")]
        data_path: PathBuf,
        /// Path to the commitment file
        #[arg(long, default_value = "data/commitment.bin")]
        commitment_path: PathBuf,
    },
    /// Open a proof for a given position
    Open {
        /// Position to open
        positions: Vec<usize>,
        /// Path to the positions file
        #[arg(long, default_value = "data/positions.bin")]
        positions_path: PathBuf,
        /// Path to the evaluations file
        #[arg(long, default_value = "data/evaluations.bin")]
        evaluations_path: PathBuf,
        /// Path to the data file
        #[arg(long, default_value = "data/data.bin")]
        data_path: PathBuf,
        /// Path to the proof file
        #[arg(long, default_value = "data/proof.bin")]
        proof_path: PathBuf,
    },
    /// Verify a proof
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

fn main() {
    let mut prover: Option<FridaProverType> = None;

    fn try_unwrap_mut<T>(prover: &mut Option<T>) -> Result<&mut T, String> {
        prover
            .as_mut()
            .ok_or("Please call the init command first.".to_owned())
    }

    let mut iteration = || -> Result<(), String> {
        let cli = read_and_parse_command()?;

        match cli.command {
            Commands::Init { .. } => {
                prover = handle_init(cli.command);
            }
            Commands::GenerateData { .. } => {
                handle_generate_data(cli.command);
            }
            Commands::Commit { .. } => {
                handle_commit(cli.command, try_unwrap_mut(&mut prover)?);
            }
            Commands::Open { .. } => {
                handle_open(cli.command, try_unwrap_mut(&mut prover)?);
            }
            Commands::Verify { .. } => {
                handle_verify(cli.command, try_unwrap_mut(&mut prover)?);
            }
        }
        Ok(())
    };

    loop {
        if let Err(err) = iteration() {
            eprintln!("Error: {}", err);
        }
    }
}

fn read_and_parse_command() -> Result<Cli, String> {
    print!("Enter command: ");
    io::stdout().flush().unwrap();

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read input.");
    let input = input.trim();

    if input.eq_ignore_ascii_case("exit") {
        std::process::exit(0);
    }

    let args = shlex::split(input)
        .ok_or_else(|| "Failed to parse input.".to_string())?
        .into_iter()
        .chain(Some("frida-poc".to_string()))
        .collect::<Vec<_>>();

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
            data_path.display(), blowup_factor, folding_factor, max_remainder_degree
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

fn handle_commit(cmd: Commands, prover: &mut FridaProverType) {
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

fn handle_open(cmd: Commands, prover: &mut FridaProverType) {
    if let Commands::Open {
        positions,
        positions_path,
        evaluations_path,
        data_path,
        proof_path,
    } = cmd
    {
        if let Err(err) = commands::open::run(
            prover,
            &positions,
            &positions_path,
            &evaluations_path,
            &data_path,
            &proof_path,
        ) {
            eprintln!("Failed to open proof: {}", err);
        }
    }
}

fn handle_verify(cmd: Commands, prover: &mut FridaProverType) {
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
