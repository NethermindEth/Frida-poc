#![cfg(feature = "bench")]
use std::{
    fs,
    path::Path,
    time::{Duration, Instant},
    io::Write,
};

use clap::{Parser, Subcommand};
use frida_poc::{
    frida_data::{build_evaluations_from_data, encoded_data_element_count},
    frida_prover::{batch_data_to_evaluations, FridaProverBuilder},
    frida_const,
};
use winter_crypto::{hashers::Blake3_256, ElementHasher};
use winter_fri::FriOptions;
use winter_math::{
    fields::{f128, f64},
    FieldElement,
};
use winter_rand_utils::rand_vector;

const RUNS: usize = 10;

#[derive(Parser)]
#[command(name = "frida-bench")]
#[command(about = "Benchmark suite for Frida proof size and time analysis")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Full {
        #[arg(long, default_value = "bench/frida/results_full.csv")]
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
        #[arg(long, default_value = "bench/frida/results_custom.csv")]
        output: String,
    },
}

#[derive(Debug)]
struct FridaBenchmarkResult {
    field_type: String,
    batch_size: usize,
    blowup_factor: usize,
    folding_factor: usize,
    max_remainder_degree: usize,
    data_size_kb: usize,
    domain_size: usize,
    single_proof_time_ms: f64,
    single_proof_size_bytes: usize,
    total_proof_size_estimate_mb: f64,
}

impl FridaBenchmarkResult {
    fn csv_header() -> String {
        "field_type,batch_size,blowup_factor,folding_factor,max_remainder_degree,data_size_kb,domain_size,single_proof_time_ms,single_proof_size_bytes,total_proof_size_estimate_mb".to_string()
    }

    fn to_csv(&self) -> String {
        format!(
            "{},{},{},{},{},{},{},{:.3},{},{:.3}",
            self.field_type,
            self.batch_size,
            self.blowup_factor,
            self.folding_factor,
            self.max_remainder_degree,
            self.data_size_kb,
            self.domain_size,
            self.single_proof_time_ms,
            self.single_proof_size_bytes,
            self.total_proof_size_estimate_mb
        )
    }
}

fn benchmark_non_batched<E, H>(
    options: FriOptions,
    data_size: usize,
    field_name: &str,
) -> FridaBenchmarkResult
where
    E: FieldElement,
    H: ElementHasher<BaseField = E::BaseField>,
{
    let mut total_proof_time = Duration::ZERO;
    let mut total_proof_size = 0;

    let encoded_element_count = encoded_data_element_count::<E>(data_size);
    let domain_size = usize::max(
        encoded_element_count.next_power_of_two() * options.blowup_factor(),
        frida_const::MIN_DOMAIN_SIZE,
    );

    for _ in 0..RUNS {
        let data = rand_vector::<u8>(data_size);
        let prover_builder = FridaProverBuilder::<E, H>::new(options.clone());

        let (_, prover, base_positions) = prover_builder
            .calculate_commitment(&data, 1)
            .expect("Commitment calculation failed");

        let drawn_position = vec![base_positions[0]];
        
        let start = Instant::now();
        let proof = prover.open(&drawn_position);
        total_proof_time += start.elapsed();
        total_proof_size += proof.size();
    }

    let avg_proof_time_ms = total_proof_time.as_secs_f64() * 1000.0 / RUNS as f64;
    let avg_proof_size_bytes = total_proof_size / RUNS;
    let total_proof_size_estimate_mb = (domain_size * avg_proof_size_bytes) as f64 / (1024.0 * 1024.0);

    FridaBenchmarkResult {
        field_type: field_name.to_string(),
        batch_size: 1,
        blowup_factor: options.blowup_factor(),
        folding_factor: options.folding_factor(),
        max_remainder_degree: options.remainder_max_degree(),
        data_size_kb: data_size / 1024,
        domain_size,
        single_proof_time_ms: avg_proof_time_ms,
        single_proof_size_bytes: avg_proof_size_bytes,
        total_proof_size_estimate_mb,
    }
}

fn benchmark_batched<E, H>(
    options: FriOptions,
    data_size: usize,
    batch_size: usize,
    field_name: &str,
) -> FridaBenchmarkResult
where
    E: FieldElement,
    H: ElementHasher<BaseField = E::BaseField>,
{
    let mut total_proof_time = Duration::ZERO;
    let mut total_proof_size = 0;

    let max_data_len = encoded_data_element_count::<E>(data_size);
    let domain_size = usize::max(
        (max_data_len * options.blowup_factor()).next_power_of_two(),
        frida_const::MIN_DOMAIN_SIZE,
    );

    for _ in 0..RUNS {
        let mut data_list = vec![];
        for _ in 0..batch_size {
            data_list.push(rand_vector::<u8>(data_size));
        }

        let prover_builder = FridaProverBuilder::<E, H>::new(options.clone());

        let (_, prover, base_positions) = prover_builder
            .calculate_commitment_batch(&data_list, 1)
            .expect("Batch commitment calculation failed");

        let drawn_position = vec![base_positions[0]];
        
        let start = Instant::now();
        let proof = prover.open(&drawn_position);
        total_proof_time += start.elapsed();
        total_proof_size += proof.size();
    }

    let avg_proof_time_ms = total_proof_time.as_secs_f64() * 1000.0 / RUNS as f64;
    let avg_proof_size_bytes = total_proof_size / RUNS;
    let total_proof_size_estimate_mb = (domain_size * avg_proof_size_bytes) as f64 / (1024.0 * 1024.0);

    FridaBenchmarkResult {
        field_type: field_name.to_string(),
        batch_size,
        blowup_factor: options.blowup_factor(),
        folding_factor: options.folding_factor(),
        max_remainder_degree: options.remainder_max_degree(),
        data_size_kb: data_size / 1024,
        domain_size,
        single_proof_time_ms: avg_proof_time_ms,
        single_proof_size_bytes: avg_proof_size_bytes,
        total_proof_size_estimate_mb,
    }
}

fn save_results(results: &[FridaBenchmarkResult], output_path: &str) -> std::io::Result<()> {
    if let Some(parent) = Path::new(output_path).parent() {
        fs::create_dir_all(parent)?;
    }

    let mut file = fs::File::create(output_path)?;
    writeln!(file, "{}", FridaBenchmarkResult::csv_header())?;
    
    for result in results {
        writeln!(file, "{}", result.to_csv())?;
    }
    
    println!("Results saved to: {}", output_path);
    Ok(())
}

fn run_full_benchmark(output_path: &str) {
    let fri_options = vec![
        (2, 2, 0),
        (2, 2, 256),
        (2, 4, 2),
        (2, 4, 256),
        (2, 8, 4),
        (2, 8, 256),
        (2, 16, 8),
        (2, 16, 256),
    ];

    let data_sizes = vec![
        16 * 1024,   // 16KB
        32 * 1024,   // 32KB
        64 * 1024,   // 64KB
        128 * 1024,  // 128KB
        256 * 1024,  // 256KB
        512 * 1024,  // 512KB
        1024 * 1024, // 1MB
    ];

    let batch_sizes = vec![1, 2, 4, 8, 16, 32];

    let mut results = Vec::new();

    println!("Running full Frida benchmark suite...");
    let total_configs = fri_options.len() * data_sizes.len() * batch_sizes.len() * 2;
    println!("Total configurations: {}", total_configs);

    let mut completed = 0;

    for &(blowup_factor, folding_factor, max_remainder_degree) in &fri_options {
        let options = FriOptions::new(blowup_factor, folding_factor, max_remainder_degree);
        
        for &data_size in &data_sizes {
            for &batch_size in &batch_sizes {
                if completed % 50 == 0 {
                    println!("Progress: {}/{} configurations completed", completed, total_configs);
                }

                if batch_size == 1 {
                    if let Ok(result) = std::panic::catch_unwind(|| {
                        benchmark_non_batched::<f64::BaseElement, Blake3_256<f64::BaseElement>>(
                            options.clone(),
                            data_size,
                            "f64",
                        )
                    }) {
                        results.push(result);
                    }
                    completed += 1;

                    if let Ok(result) = std::panic::catch_unwind(|| {
                        benchmark_non_batched::<f128::BaseElement, Blake3_256<f128::BaseElement>>(
                            options.clone(),
                            data_size,
                            "f128",
                        )
                    }) {
                        results.push(result);
                    }
                    completed += 1;
                } else {
                    if let Ok(result) = std::panic::catch_unwind(|| {
                        benchmark_batched::<f64::BaseElement, Blake3_256<f64::BaseElement>>(
                            options.clone(),
                            data_size,
                            batch_size,
                            "f64",
                        )
                    }) {
                        results.push(result);
                    }
                    completed += 1;

                    if let Ok(result) = std::panic::catch_unwind(|| {
                        benchmark_batched::<f128::BaseElement, Blake3_256<f128::BaseElement>>(
                            options.clone(),
                            data_size,
                            batch_size,
                            "f128",
                        )
                    }) {
                        results.push(result);
                    }
                    completed += 1;
                }
            }
        }
    }

    save_results(&results, output_path).expect("Failed to save results");
    println!("Full Frida benchmark completed. Results saved to {}", output_path);
    println!("Total successful configurations: {}", results.len());
}

fn run_custom_benchmark(
    blowup_factor: usize,
    folding_factor: usize,
    max_remainder_degree: usize,
    data_size: usize,
    batch_size: usize,
    output_path: &str,
) {
    let options = FriOptions::new(blowup_factor, folding_factor, max_remainder_degree);
    let mut results = Vec::new();

    println!("Running custom Frida benchmark...");
    println!("Parameters: blowup={}, folding={}, remainder={}, data={}KB, batch_size={}",
        blowup_factor, folding_factor, max_remainder_degree, data_size / 1024, batch_size);

    if batch_size > 1 {
        println!("Running batched benchmarks...");
        
        let result_f64 = benchmark_batched::<f64::BaseElement, Blake3_256<f64::BaseElement>>(
            options.clone(),
            data_size,
            batch_size,
            "f64",
        );
        results.push(result_f64);

        let result_f128 = benchmark_batched::<f128::BaseElement, Blake3_256<f128::BaseElement>>(
            options.clone(),
            data_size,
            batch_size,
            "f128",
        );
        results.push(result_f128);
    } else {
        println!("Running non-batched benchmarks...");
        
        let result_f64 = benchmark_non_batched::<f64::BaseElement, Blake3_256<f64::BaseElement>>(
            options.clone(),
            data_size,
            "f64",
        );
        results.push(result_f64);

        let result_f128 = benchmark_non_batched::<f128::BaseElement, Blake3_256<f128::BaseElement>>(
            options.clone(),
            data_size,
            "f128",
        );
        results.push(result_f128);
    }

    save_results(&results, output_path).expect("Failed to save results");
    println!("Custom Frida benchmark completed. Results saved to {}", output_path);
    
    println!("\nResults Summary:");
    for result in &results {
        println!("  {}: Single proof = {} bytes, {:.3} ms | Total estimate = {:.2} MB", 
            result.field_type,
            result.single_proof_size_bytes,
            result.single_proof_time_ms,
            result.total_proof_size_estimate_mb
        );
    }
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Full { output } => {
            run_full_benchmark(&output);
        }
        Commands::Custom {
            blowup_factor,
            folding_factor,
            max_remainder_degree,
            data_size,
            batch_size,
            output,
        } => {
            run_custom_benchmark(
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