pub mod commit;
pub mod generate_data;
pub mod open;
pub mod verify;

mod cli;

use self::cli::{Cli, Commands};
use crate::{
    prover::builder::FridaProverBuilder,
    winterfell::{f128::BaseElement, winter_crypto::hashers::Blake3_256, FriOptions},
};
use clap::Parser;
use std::{
    fs,
    io::{self, Write},
};

type Blake3 = Blake3_256<BaseElement>;
type FridaProverBuilderType = FridaProverBuilder<BaseElement, Blake3>;

/// Runs the main interactive CLI loop.
pub fn run_cli() {
    let mut prover_builder: Option<FridaProverBuilderType> = None;

    loop {
        if let Err(e) = handle_iteration(&mut prover_builder) {
            eprintln!("Error: {e}");
        }
    }
}

/// Handles a single iteration of the command loop.
fn handle_iteration(
    prover_builder: &mut Option<FridaProverBuilderType>,
) -> Result<(), Box<dyn std::error::Error>> {
    let cli = read_and_parse_command()?;

    match cli.command {
        Commands::Init {
            data_path,
            blowup_factor,
            folding_factor,
            max_remainder_degree,
        } => {
            println!(
                "Initializing prover with FRI options: blowup={blowup_factor}, folding={folding_factor}, max_degree={max_remainder_degree}"
            );

            // Check if the data file exists before initializing
            fs::read(&data_path).map_err(|e| {
                format!(
                    "Failed to read data file '{}': {}. Use the 'generate-data' command first.",
                    data_path.display(),
                    e
                )
            })?;

            let options = FriOptions::new(blowup_factor, folding_factor, max_remainder_degree);
            *prover_builder = Some(FridaProverBuilderType::new(options));
            println!("Prover initialized successfully.");
        }
        Commands::GenerateData { size, data_path } => {
            generate_data::run(size, &data_path)?;
        }
        Commands::Commit {
            num_queries,
            data_path,
            commitment_path,
        } => {
            let builder = prover_builder
                .as_mut()
                .ok_or("Prover not initialized. Please run the 'init' command first.")?;
            commit::run(builder, num_queries, &data_path, &commitment_path)?;
        }
        Commands::Open {
            positions,
            positions_path,
            evaluations_path,
            data_path,
            proof_path,
        } => {
            let builder = prover_builder
                .as_mut()
                .ok_or("Prover not initialized. Please run the 'init' command first.")?;
            open::run(
                builder,
                &positions,
                &positions_path,
                &evaluations_path,
                &data_path,
                &proof_path,
            )?;
        }
        Commands::Verify {
            commitment_path,
            positions_path,
            evaluations_path,
            proof_path,
        } => {
            let builder = prover_builder
                .as_ref()
                .ok_or("Prover not initialized. Please run the 'init' command first.")?;
            verify::run(
                &commitment_path,
                &positions_path,
                &evaluations_path,
                &proof_path,
                builder.options.clone(),
            )?;
            println!("Verification successful!");
        }
    }
    Ok(())
}

/// Reads a line from stdin and parses it into a CLI command.
fn read_and_parse_command() -> Result<Cli, String> {
    print!("> ");
    io::stdout().flush().unwrap();

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|e| e.to_string())?;
    let input = input.trim();

    if input.eq_ignore_ascii_case("exit") {
        println!("Exiting.");
        std::process::exit(0);
    }

    // `shlex::split` correctly handles quoted arguments
    let args = shlex::split(input).ok_or_else(|| "Failed to parse input.".to_string())?;

    // We prepend the binary name to satisfy clap's parsing requirements
    let mut full_args = vec!["frida-poc"];
    full_args.extend(args.iter().map(String::as_str));

    Cli::try_parse_from(full_args).map_err(|err| err.to_string())
}
