use std::time::{Duration, Instant};
use winter_crypto::{hashers::Blake3_256, ElementHasher};
use winter_fri::FriOptions;
use winter_math::FieldElement;
use winter_rand_utils::rand_vector;

use frida_poc::{
    core::data::encoded_data_element_count,
    prover::builder::FridaProverBuilder,
    constants,
};

use crate::common::{
    self, field_names, Blake3_F128, Blake3_F64, F128Element, F64Element, RUNS
};

#[derive(Debug)]
struct SingleFridaBenchmarkResult {
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

impl SingleFridaBenchmarkResult {
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
) -> SingleFridaBenchmarkResult
where
    E: FieldElement,
    H: ElementHasher<BaseField = E::BaseField>,
{
    let mut total_proof_time = Duration::ZERO;
    let mut total_proof_size = 0;

    let encoded_element_count = encoded_data_element_count::<E>(data_size);
    let domain_size = usize::max(
        encoded_element_count.next_power_of_two() * options.blowup_factor(),
        constants::MIN_DOMAIN_SIZE,
    );

    for _ in 0..RUNS {
        let data = rand_vector::<u8>(data_size);
        let prover_builder = FridaProverBuilder::<E, H>::new(options.clone());

        let (_, prover, base_positions) = prover_builder
            .commitment(&data, 1)
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

    SingleFridaBenchmarkResult {
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
) -> SingleFridaBenchmarkResult
where
    E: FieldElement,
    H: ElementHasher<BaseField = E::BaseField>,
{
    let mut total_proof_time = Duration::ZERO;
    let mut total_proof_size = 0;

    let max_data_len = encoded_data_element_count::<E>(data_size);
    let domain_size = usize::max(
        (max_data_len * options.blowup_factor()).next_power_of_two(),
        constants::MIN_DOMAIN_SIZE,
    );

    for _ in 0..RUNS {
        let mut data_list = vec![];
        for _ in 0..batch_size {
            data_list.push(rand_vector::<u8>(data_size));
        }

        let prover_builder = FridaProverBuilder::<E, H>::new(options.clone());

        let (_, prover, base_positions) = prover_builder
            .commitment_batch(&data_list, 1)
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

    SingleFridaBenchmarkResult {
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

pub fn run_full_benchmark(output_path: &str) {
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

    println!("Running full Single Frida benchmark suite...");
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
                        benchmark_non_batched::<F64Element, Blake3_F64>(
                            options.clone(),
                            data_size,
                            field_names::F64,
                        )
                    }) {
                        results.push(result);
                    }
                    completed += 1;

                    if let Ok(result) = std::panic::catch_unwind(|| {
                        benchmark_non_batched::<F128Element, Blake3_F128>(
                            options.clone(),
                            data_size,
                            field_names::F128,
                        )
                    }) {
                        results.push(result);
                    }
                    completed += 1;
                } else {
                    if let Ok(result) = std::panic::catch_unwind(|| {
                        benchmark_batched::<F64Element, Blake3_F64>(
                            options.clone(),
                            data_size,
                            batch_size,
                            field_names::F64,
                        )
                    }) {
                        results.push(result);
                    }
                    completed += 1;

                    if let Ok(result) = std::panic::catch_unwind(|| {
                        benchmark_batched::<F128Element, Blake3_F128>(
                            options.clone(),
                            data_size,
                            batch_size,
                            field_names::F128,
                        )
                    }) {
                        results.push(result);
                    }
                    completed += 1;
                }
            }
        }
    }

    common::save_results_with_header(&results, output_path, &SingleFridaBenchmarkResult::csv_header(), |r| r.to_csv())
        .expect("Failed to save results");
    println!("Single Frida benchmark completed with {} successful results", results.len());
}

pub fn run_custom_benchmark(
    blowup_factors: Vec<usize>,
    folding_factors: Vec<usize>,
    max_remainder_degrees: Vec<usize>,
    data_sizes: Vec<usize>,
    batch_sizes: Vec<usize>,
    output_path: &str,
) {
    let mut results = Vec::new();
    let total_configs = blowup_factors.len() * folding_factors.len() * max_remainder_degrees.len() * data_sizes.len() * batch_sizes.len();
    let mut completed = 0;

    println!("Running custom Single Frida benchmark...");
    println!("Total configurations: {}", total_configs);

    for &blowup_factor in &blowup_factors {
        for &folding_factor in &folding_factors {
            for &max_remainder_degree in &max_remainder_degrees {
                for &data_size in &data_sizes {
                    for &batch_size in &batch_sizes {
                        if completed % 50 == 0 {
                            println!("Progress: {}/{} configurations completed", completed, total_configs);
                        }

                        let options = FriOptions::new(blowup_factor, folding_factor, max_remainder_degree);
                        if batch_size > 1 {
                            let result_f64 = benchmark_batched::<F64Element, Blake3_F64>(
                                options.clone(),
                                data_size,
                                batch_size,
                                field_names::F64,
                            );
                            results.push(result_f64);

                            let result_f128 = benchmark_batched::<F128Element, Blake3_F128>(
                                options.clone(),
                                data_size,
                                batch_size,
                                field_names::F128,
                            );
                            results.push(result_f128);
                        } else {
                            let result_f64 = benchmark_non_batched::<F64Element, Blake3_F64>(
                                options.clone(),
                                data_size,
                                field_names::F64,
                            );
                            results.push(result_f64);

                            let result_f128 = benchmark_non_batched::<F128Element, Blake3_F128>(
                                options.clone(),
                                data_size,
                                field_names::F128,
                            );
                            results.push(result_f128);
                        }
                        completed += 1;
                    }
                }
            }
        }
    }

    common::save_results_with_header(&results, output_path, &SingleFridaBenchmarkResult::csv_header(), |r| r.to_csv())
        .expect("Failed to save results");
    
    println!("Custom Single Frida benchmark completed with {} successful results", results.len());
    
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