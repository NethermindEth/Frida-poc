#![cfg(feature = "bench")]

use clap::{Parser, Subcommand};

mod common;
mod defrida;
mod frida;
mod single_frida;

#[derive(Parser)]
#[command(name = "frida-bench")]
#[command(about = "Comprehensive benchmark suite for FRI implementations")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Traditional FRIDA benchmarking (commitment + proof + verification)
    Frida {
        #[command(subcommand)]
        subcommand: BenchmarkSubcommand,
    },
    /// Single proof size and time analysis
    SingleFrida {
        #[command(subcommand)]
        subcommand: SingleFridaSubcommand,
    },
    /// Distributed deFRIDA workflow benchmarking
    Defrida {
        #[command(subcommand)]
        subcommand: DefridaSubcommand,
    },
}

#[derive(Subcommand)]
enum BenchmarkSubcommand {
    Full {
        #[arg(long, default_value = "bench/results/frida_full.csv")]
        output: String,
    },
    Custom {
        #[arg(long)]
        blowup_factor: usize,
        #[arg(long)]
        folding_factor: usize,
        #[arg(long)]
        max_remainder_degree: usize,
        #[arg(long)]
        data_size: usize,
        #[arg(long, default_value = "1")]
        batch_size: usize,
        #[arg(long, default_value = "32")]
        num_queries: usize,
        #[arg(long, default_value = "bench/results/frida_custom.csv")]
        output: String,
    },
}

#[derive(Subcommand)]
enum SingleFridaSubcommand {
    Full {
        #[arg(long, default_value = "bench/results/single_frida_full.csv")]
        output: String,
    },
    Custom {
        #[arg(long)]
        blowup_factor: usize,
        #[arg(long)]
        folding_factor: usize,
        #[arg(long)]
        max_remainder_degree: usize,
        #[arg(long)]
        data_size: usize,
        #[arg(long, default_value = "1")]
        batch_size: usize,
        #[arg(long, default_value = "bench/results/single_frida_custom.csv")]
        output: String,
    },
}

#[derive(Subcommand)]
enum DefridaSubcommand {
    Full {
        #[arg(long, default_value = "bench/results/defrida_full.csv")]
        output: String,
    },
    Custom {
        #[arg(long)]
        blowup_factor: usize,
        #[arg(long)]
        folding_factor: usize,
        #[arg(long)]
        max_remainder_degree: usize,
        #[arg(long)]
        data_size: usize,
        #[arg(long)]
        num_validators: usize,
        #[arg(long)]
        num_queries: usize,
        #[arg(long, default_value = "1")]
        batch_size: usize,
        #[arg(long, default_value = "bench/results/defrida_custom.csv")]
        output: String,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Frida { subcommand } => match subcommand {
            BenchmarkSubcommand::Full { output } => {
                frida::run_full_benchmark(&output);
            }
            BenchmarkSubcommand::Custom {
                blowup_factor,
                folding_factor,
                max_remainder_degree,
                data_size,
                batch_size,
                num_queries,
                output,
            } => {
                frida::run_custom_benchmark(
                    blowup_factor,
                    folding_factor,
                    max_remainder_degree,
                    data_size,
                    batch_size,
                    num_queries,
                    &output,
                );
            }
        },
        Commands::SingleFrida { subcommand } => match subcommand {
            SingleFridaSubcommand::Full { output } => {
                single_frida::run_full_benchmark(&output);
            }
            SingleFridaSubcommand::Custom {
                blowup_factor,
                folding_factor,
                max_remainder_degree,
                data_size,
                batch_size,
                output,
            } => {
                single_frida::run_custom_benchmark(
                    blowup_factor,
                    folding_factor,
                    max_remainder_degree,
                    data_size,
                    batch_size,
                    &output,
                );
            }
        },
        Commands::Defrida { subcommand } => match subcommand {
            DefridaSubcommand::Full { output } => {
                defrida::run_full_benchmark(&output);
            }
            DefridaSubcommand::Custom {
                blowup_factor,
                folding_factor,
                max_remainder_degree,
                data_size,
                num_validators,
                num_queries,
                batch_size,
                output,
            } => {
                let config = defrida::CustomDefridaBenchmarkConfig {
                    blowup_factor,
                    folding_factor,
                    max_remainder_degree,
                    data_size,
                    num_validators,
                    num_queries,
                    batch_size,
                    output_path: &output,
                };
                defrida::run_custom_benchmark(config);
            }
        },
    }
}
