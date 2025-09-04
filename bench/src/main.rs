#![cfg(feature = "bench")]

use clap::{Args, Parser, Subcommand};
use common::{
    get_standard_batch_sizes, get_standard_data_sizes, get_standard_fri_options,
    get_standard_num_queries, get_standard_validator_counts, parse_fri_options, F64Element,
    FieldType,
};
use runner::{run_benchmark, BenchmarkConfig};

mod common;
mod defrida;
mod frida;
mod runner;
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
    /// Traditional FRIDA benchmarking (commitment + proof + verification).
    Frida(BenchmarkArgs<FridaCustom>),
    /// Single proof size and time analysis.
    SingleFrida(BenchmarkArgs<SingleFridaCustom>),
    /// Distributed deFRIDA workflow benchmarking.
    Defrida(BenchmarkArgs<DefridaCustom>),
}

#[derive(Args, Debug)]
pub struct BenchmarkArgs<T: Subcommand> {
    #[command(subcommand)]
    command: Option<T>,
    #[arg(long, conflicts_with = "command")]
    full: bool,
}

#[derive(Subcommand, Debug)]
enum FridaCustom {
    Custom {
        #[arg(long, default_value = "(2,2,0)")]
        fri_options: String,
        #[arg(long, use_value_delimiter = true, default_value = "65536")]
        data_size: Vec<u64>,
        #[arg(long, use_value_delimiter = true, default_value = "1")]
        batch_size: Vec<u32>,
        #[arg(long, use_value_delimiter = true, default_value = "32")]
        num_queries: Vec<u32>,
        #[arg(long, value_enum, default_value = "both")]
        field: FieldType,
        #[arg(long, default_value = "bench/results/frida_custom.csv")]
        output: String,
    },
}

#[derive(Subcommand, Debug)]
enum SingleFridaCustom {
    Custom {
        #[arg(long, default_value = "(2,2,0)")]
        fri_options: String,
        #[arg(long, use_value_delimiter = true, default_value = "65536")]
        data_size: Vec<u64>,
        #[arg(long, use_value_delimiter = true, default_value = "1")]
        batch_size: Vec<u32>,
        #[arg(long, value_enum, default_value = "both")]
        field: FieldType,
        #[arg(long, default_value = "bench/results/single_frida_custom.csv")]
        output: String,
    },
}

#[derive(Subcommand, Debug)]
enum DefridaCustom {
    Custom {
        #[arg(long, default_value = "(2,2,0)")]
        fri_options: String,
        #[arg(long, use_value_delimiter = true, default_value = "65536")]
        data_size: Vec<u64>,
        #[arg(long, use_value_delimiter = true, default_value = "16")]
        num_validators: Vec<u32>,
        #[arg(long, use_value_delimiter = true, default_value = "64")]
        num_queries: Vec<u32>,
        #[arg(long, use_value_delimiter = true, default_value = "1")]
        batch_size: Vec<u32>,
        #[arg(long, value_enum, default_value = "both")]
        field: FieldType,
        #[arg(long, default_value = "bench/results/defrida_custom.csv")]
        output: String,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Frida(args) => {
            let config = if args.full {
                BenchmarkConfig {
                    fri_options: get_standard_fri_options(),
                    data_sizes: get_standard_data_sizes::<F64Element>(),
                    batch_sizes: [1]
                        .iter()
                        .cloned()
                        .chain(get_standard_batch_sizes())
                        .collect(),
                    field_type: FieldType::Both,
                    output_path: "bench/results/frida_full.csv".to_string(),
                    num_queries: Some(get_standard_num_queries()),
                    num_validators: None,
                }
            } else if let Some(FridaCustom::Custom {
                fri_options,
                data_size,
                batch_size,
                num_queries,
                field,
                output,
            }) = args.command
            {
                let parsed_fri_options =
                    parse_fri_options(&fri_options).expect("Invalid format for --fri-options");
                BenchmarkConfig {
                    fri_options: parsed_fri_options,
                    data_sizes: data_size,
                    batch_sizes: batch_size,
                    field_type: field,
                    output_path: output,
                    num_queries: Some(num_queries),
                    num_validators: None,
                }
            } else {
                return;
            };
            run_benchmark(frida::FridaBenchmark, config);
        }
        Commands::SingleFrida(args) => {
            let config = if args.full {
                BenchmarkConfig {
                    fri_options: get_standard_fri_options(),
                    data_sizes: get_standard_data_sizes::<F64Element>(),
                    batch_sizes: [1]
                        .iter()
                        .cloned()
                        .chain(get_standard_batch_sizes())
                        .collect(),
                    field_type: FieldType::Both,
                    output_path: "bench/results/single_frida_full.csv".to_string(),
                    num_queries: None,
                    num_validators: None,
                }
            } else if let Some(SingleFridaCustom::Custom {
                fri_options,
                data_size,
                batch_size,
                field,
                output,
            }) = args.command
            {
                let parsed_fri_options =
                    parse_fri_options(&fri_options).expect("Invalid format for --fri-options");
                BenchmarkConfig {
                    fri_options: parsed_fri_options,
                    data_sizes: data_size,
                    batch_sizes: batch_size,
                    field_type: field,
                    output_path: output,
                    num_queries: None,
                    num_validators: None,
                }
            } else {
                return;
            };
            run_benchmark(single_frida::SingleFridaBenchmark, config);
        }
        Commands::Defrida(args) => {
            let config = if args.full {
                BenchmarkConfig {
                    fri_options: get_standard_fri_options(),
                    data_sizes: get_standard_data_sizes::<F64Element>(),
                    batch_sizes: [1]
                        .iter()
                        .cloned()
                        .chain(get_standard_batch_sizes())
                        .collect(),
                    field_type: FieldType::Both,
                    output_path: "bench/results/defrida_full.csv".to_string(),
                    num_queries: Some(get_standard_num_queries()),
                    num_validators: Some(get_standard_validator_counts()),
                }
            } else if let Some(DefridaCustom::Custom {
                fri_options,
                data_size,
                num_validators,
                num_queries,
                batch_size,
                field,
                output,
            }) = args.command
            {
                let parsed_fri_options =
                    parse_fri_options(&fri_options).expect("Invalid format for --fri-options");
                BenchmarkConfig {
                    fri_options: parsed_fri_options,
                    data_sizes: data_size,
                    batch_sizes: batch_size,
                    field_type: field,
                    output_path: output,
                    num_queries: Some(num_queries),
                    num_validators: Some(num_validators),
                }
            } else {
                return;
            };
            run_benchmark(defrida::DefridaBenchmark, config);
        }
    }
}
