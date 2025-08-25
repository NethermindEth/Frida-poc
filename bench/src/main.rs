#![cfg(feature = "bench")]

use clap::{Parser, Subcommand};
use common::{parse_fri_options, FieldType};

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
        #[arg(long, default_value = "(2,2,0)")]
        fri_options: String,
        #[arg(long, use_value_delimiter = true, default_value = "65536")]
        data_size: Vec<usize>,
        #[arg(long, use_value_delimiter = true, default_value = "1")]
        batch_size: Vec<usize>,
        #[arg(long, use_value_delimiter = true, default_value = "32")]
        num_queries: Vec<usize>,
        #[arg(long, value_enum, default_value = "both")]
        field: FieldType,
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
        #[arg(long, default_value = "(2,2,0)")]
        fri_options: String,
        #[arg(long, use_value_delimiter = true, default_value = "65536")]
        data_size: Vec<usize>,
        #[arg(long, use_value_delimiter = true, default_value = "1")]
        batch_size: Vec<usize>,
        #[arg(long, value_enum, default_value = "both")]
        field: FieldType,
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
        #[arg(long, default_value = "(2,2,0)")]
        fri_options: String,
        #[arg(long, use_value_delimiter = true, default_value = "65536")]
        data_size: Vec<usize>,
        #[arg(long, use_value_delimiter = true, default_value = "16")]
        num_validators: Vec<usize>,
        #[arg(long, use_value_delimiter = true, default_value = "64")]
        num_queries: Vec<usize>,
        #[arg(long, use_value_delimiter = true, default_value = "1")]
        batch_size: Vec<usize>,
        #[arg(long, value_enum, default_value = "both")]
        field: FieldType,
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
                fri_options,
                data_size,
                batch_size,
                num_queries,
                field,
                output,
            } => {
                let parsed_fri_options =
                    parse_fri_options(&fri_options).expect("Invalid format for --fri-options");
                let config = frida::CustomFridaBenchmarkConfig {
                    fri_options: parsed_fri_options,
                    data_sizes: data_size,
                    batch_sizes: batch_size,
                    num_queries,
                    field_type: field,
                    output_path: &output,
                };
                frida::run_custom_benchmark(config);
            }
        },
        Commands::SingleFrida { subcommand } => match subcommand {
            SingleFridaSubcommand::Full { output } => {
                single_frida::run_full_benchmark(&output);
            }
            SingleFridaSubcommand::Custom {
                fri_options,
                data_size,
                batch_size,
                field,
                output,
            } => {
                let parsed_fri_options =
                    parse_fri_options(&fri_options).expect("Invalid format for --fri-options");
                let config = single_frida::CustomSingleFridaBenchmarkConfig {
                    fri_options: parsed_fri_options,
                    data_sizes: data_size,
                    batch_sizes: batch_size,
                    field_type: field,
                    output_path: &output,
                };
                single_frida::run_custom_benchmark(config);
            }
        },
        Commands::Defrida { subcommand } => match subcommand {
            DefridaSubcommand::Full { output } => {
                defrida::run_full_benchmark(&output);
            }
            DefridaSubcommand::Custom {
                fri_options,
                data_size,
                num_validators,
                num_queries,
                batch_size,
                field,
                output,
            } => {
                let parsed_fri_options =
                    parse_fri_options(&fri_options).expect("Invalid format for --fri-options");
                let config = defrida::CustomDefridaBenchmarkConfig {
                    fri_options: parsed_fri_options,
                    data_sizes: data_size,
                    num_validators,
                    num_queries,
                    batch_sizes: batch_size,
                    field_type: field,
                    output_path: &output,
                };
                defrida::run_custom_benchmark(config);
            }
        },
    }
}
