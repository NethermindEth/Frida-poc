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
        #[arg(long, value_delimiter = ',', value_parser = clap::value_parser!(usize))]
        blowup_factor: Vec<usize>,
        #[arg(long, value_delimiter = ',', value_parser = clap::value_parser!(usize))]
        folding_factor: Vec<usize>,
        #[arg(long, value_delimiter = ',', value_parser = clap::value_parser!(usize))]
        max_remainder_degree: Vec<usize>,
        #[arg(long, value_delimiter = ',', value_parser = clap::value_parser!(usize))]
        data_size: Vec<usize>,
        #[arg(long, value_delimiter = ',', value_parser = clap::value_parser!(usize), default_value = "1")]
        batch_size: Vec<usize>,
        #[arg(long, value_delimiter = ',', value_parser = clap::value_parser!(usize), default_value = "32")]
        num_queries: Vec<usize>,
        #[arg(long, value_delimiter = ',', value_parser = clap::value_parser!(usize), default_value = "64,128")]
        field_size: Vec<usize>,  // 64: only f64, 128: only f128
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
        #[arg(long, value_delimiter = ',', value_parser = clap::value_parser!(usize))]
        blowup_factor: Vec<usize>,
        #[arg(long, value_delimiter = ',', value_parser = clap::value_parser!(usize))]
        folding_factor: Vec<usize>,
        #[arg(long, value_delimiter = ',', value_parser = clap::value_parser!(usize))]
        max_remainder_degree: Vec<usize>,
        #[arg(long, value_delimiter = ',', value_parser = clap::value_parser!(usize))]
        data_size: Vec<usize>,
        #[arg(long, value_delimiter = ',', value_parser = clap::value_parser!(usize), default_value = "1")]
        batch_size: Vec<usize>,
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
        #[arg(long, value_delimiter = ',', value_parser = clap::value_parser!(usize))]
        blowup_factor: Vec<usize>,
        #[arg(long, value_delimiter = ',', value_parser = clap::value_parser!(usize))]
        folding_factor: Vec<usize>,
        #[arg(long, value_delimiter = ',', value_parser = clap::value_parser!(usize))]
        max_remainder_degree: Vec<usize>,
        #[arg(long, value_delimiter = ',', value_parser = clap::value_parser!(usize))]
        data_size: Vec<usize>,
        #[arg(long, value_delimiter = ',', value_parser = clap::value_parser!(usize))]
        num_validators: Vec<usize>,
        #[arg(long, value_delimiter = ',', value_parser = clap::value_parser!(usize), default_value = "32")]
        num_queries: Vec<usize>,
        #[arg(long, value_delimiter = ',', value_parser = clap::value_parser!(usize), default_value = "1")]
        batch_size: Vec<usize>,
        #[arg(long, default_value = "bench/results/defrida_custom.csv")]
        output: String,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Frida { subcommand } => {
            match subcommand {
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
                    field_size,
                    output,
                } => {
                    frida::run_custom_benchmark(
                        blowup_factor,
                        folding_factor,
                        max_remainder_degree,
                        data_size,
                        batch_size,
                        num_queries,
                        field_size,
                        &output,
                    );
                }
            }
        }
        Commands::SingleFrida { subcommand } => {
            match subcommand {
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
            }
        }
        Commands::Defrida { subcommand } => {
            match subcommand {
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
                    defrida::run_custom_benchmark(
                        blowup_factor,
                        folding_factor,
                        max_remainder_degree,
                        data_size,
                        num_validators,
                        num_queries,
                        batch_size,
                        &output,
                    );
                }
            }
        }
    }
}