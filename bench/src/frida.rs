use std::time::{Duration, Instant};
use winter_crypto::{hashers::Blake3_256, ElementHasher};
use winter_fri::FriOptions;
use winter_math::FieldElement;
use winter_rand_utils::rand_vector;

use frida_poc::{
    prover::{
        bench::{COMMIT_TIME, ERASURE_TIME},
        get_evaluations_from_positions, Commitment, builder::FridaProverBuilder,
    },
    verifier::das::FridaDasVerifier,
};

use crate::common::{
    self, field_names, get_standard_data_sizes, get_standard_fri_options, 
    get_standard_num_queries, get_standard_batch_sizes, Blake3_F128, Blake3_F64, F128Element, F64Element, RUNS
};

#[derive(Debug)]
struct FridaBenchmarkResult {
    field_type: String,
    batch_size: usize,
    blowup_factor: usize,
    folding_factor: usize,
    max_remainder_degree: usize,
    data_size_kb: usize,
    num_queries: usize,
    erasure_time_ms: f64,
    commitment_time_ms: f64,
    proof_time_1_ms: f64,
    proof_time_16_ms: f64,
    proof_time_32_ms: f64,
    verification_setup_ms: f64,
    verification_1_ms: f64,
    verification_16_ms: f64,
    verification_32_ms: f64,
    commitment_size_bytes: usize,
    proof_size_1_bytes: usize,
    proof_size_16_bytes: usize,
    proof_size_32_bytes: usize,
}

impl FridaBenchmarkResult {
    fn csv_header() -> String {
        "field_type,batch_size,blowup_factor,folding_factor,max_remainder_degree,data_size_kb,num_queries,erasure_time_ms,commitment_time_ms,proof_time_1_ms,proof_time_16_ms,proof_time_32_ms,verification_setup_ms,verification_1_ms,verification_16_ms,verification_32_ms,commitment_size_bytes,proof_size_1_bytes,proof_size_16_bytes,proof_size_32_bytes".to_string()
    }

    fn to_csv(&self) -> String {
        format!(
            "{},{},{},{},{},{},{},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{},{},{},{}",
            self.field_type, self.batch_size, self.blowup_factor, self.folding_factor,
            self.max_remainder_degree, self.data_size_kb, self.num_queries,
            self.erasure_time_ms, self.commitment_time_ms,
            self.proof_time_1_ms, self.proof_time_16_ms, self.proof_time_32_ms,
            self.verification_setup_ms, self.verification_1_ms, self.verification_16_ms, self.verification_32_ms,
            self.commitment_size_bytes, self.proof_size_1_bytes, self.proof_size_16_bytes, self.proof_size_32_bytes
        )
    }
}

fn prepare_verifier<E: FieldElement, H: ElementHasher<BaseField = E::BaseField>>(
    blowup_factor: usize,
    folding_factor: usize,
    remainder_max_degree: usize,
    com: Commitment<H>,
) -> FridaDasVerifier<E, H, H> {
    let options = FriOptions::new(blowup_factor, folding_factor, remainder_max_degree);
    FridaDasVerifier::new(com, options).unwrap().0
}

fn benchmark_non_batched<E, H>(
    options: FriOptions,
    data_size: usize,
    num_queries: usize,
    field_name: &str,
) -> FridaBenchmarkResult
where
    E: FieldElement,
    H: ElementHasher<BaseField = E::BaseField>,
{
    let mut total_erasure_time = Duration::ZERO;
    let mut total_commitment_time = Duration::ZERO;
    let mut total_proof_times = (Duration::ZERO, Duration::ZERO, Duration::ZERO);
    let mut total_verify_times = (Duration::ZERO, Duration::ZERO, Duration::ZERO, Duration::ZERO);
    let mut total_commitment_size = 0;
    let mut total_proof_sizes = (0, 0, 0);

    for _ in 0..RUNS {
        let data = rand_vector::<u8>(data_size);
        let prover_builder = FridaProverBuilder::<E, H>::new(options.clone());

        let (com, prover) = prover_builder.commit_and_prove(&data, num_queries).unwrap();
        
        unsafe {
            total_erasure_time += ERASURE_TIME.unwrap_or_default();
            total_commitment_time += COMMIT_TIME.unwrap_or_default();
            ERASURE_TIME = None;
            COMMIT_TIME = None;
        }

        total_commitment_size += com.proof.size() + com.roots.len() * 32 + 3;

        let positions = rand_vector::<u64>(32)
            .into_iter()
            .map(|v| (v as usize) % com.domain_size)
            .collect::<Vec<_>>();

        let evaluations = positions
            .iter()
            .map(|pos| {
                prover.get_first_layer_evalutaions()[(pos % (com.domain_size / options.folding_factor()))
                    * options.folding_factor()
                    + (pos / (com.domain_size / options.folding_factor()))]
            })
            .collect::<Vec<_>>();

        // Benchmark proof generation for different position counts
        let timer = Instant::now();
        let proof_1 = prover.open(&positions[0..1]);
        total_proof_sizes.0 += proof_1.size();
        total_proof_times.0 += timer.elapsed();

        let timer = Instant::now();
        let proof_16 = prover.open(&positions[0..16]);
        total_proof_sizes.1 += proof_16.size();
        total_proof_times.1 += timer.elapsed();

        let timer = Instant::now();
        let proof_32 = prover.open(&positions);
        total_proof_sizes.2 += proof_32.size();
        total_proof_times.2 += timer.elapsed();

        // Benchmark verification
        let timer = Instant::now();
        let verifier = prepare_verifier::<E, H>(
            options.blowup_factor(),
            options.folding_factor(),
            options.remainder_max_degree(),
            com,
        );
        total_verify_times.0 += timer.elapsed();

        let timer = Instant::now();
        verifier.verify(&proof_1, &evaluations[0..1], &positions[0..1]).unwrap();
        total_verify_times.1 += timer.elapsed();

        let timer = Instant::now();
        verifier.verify(&proof_16, &evaluations[0..16], &positions[0..16]).unwrap();
        total_verify_times.2 += timer.elapsed();

        let timer = Instant::now();
        verifier.verify(&proof_32, &evaluations, &positions).unwrap();
        total_verify_times.3 += timer.elapsed();
    }

    FridaBenchmarkResult {
        field_type: field_name.to_string(),
        batch_size: 1,
        blowup_factor: options.blowup_factor(),
        folding_factor: options.folding_factor(),
        max_remainder_degree: options.remainder_max_degree(),
        data_size_kb: data_size / 1024,
        num_queries,
        erasure_time_ms: total_erasure_time.as_secs_f64() * 1000.0 / RUNS as f64,
        commitment_time_ms: total_commitment_time.as_secs_f64() * 1000.0 / RUNS as f64,
        proof_time_1_ms: total_proof_times.0.as_secs_f64() * 1000.0 / RUNS as f64,
        proof_time_16_ms: total_proof_times.1.as_secs_f64() * 1000.0 / RUNS as f64,
        proof_time_32_ms: total_proof_times.2.as_secs_f64() * 1000.0 / RUNS as f64,
        verification_setup_ms: total_verify_times.0.as_secs_f64() * 1000.0 / RUNS as f64,
        verification_1_ms: total_verify_times.1.as_secs_f64() * 1000.0 / RUNS as f64,
        verification_16_ms: total_verify_times.2.as_secs_f64() * 1000.0 / RUNS as f64,
        verification_32_ms: total_verify_times.3.as_secs_f64() * 1000.0 / RUNS as f64,
        commitment_size_bytes: total_commitment_size / RUNS,
        proof_size_1_bytes: total_proof_sizes.0 / RUNS,
        proof_size_16_bytes: total_proof_sizes.1 / RUNS,
        proof_size_32_bytes: total_proof_sizes.2 / RUNS,
    }
}

fn benchmark_batched<E, H>(
    options: FriOptions,
    data_size: usize,
    batch_size: usize,
    num_queries: usize,
    field_name: &str,
) -> FridaBenchmarkResult
where
    E: FieldElement,
    H: ElementHasher<BaseField = E::BaseField>,
{
    let mut total_erasure_time = Duration::ZERO;
    let mut total_commitment_time = Duration::ZERO;
    let mut total_proof_times = (Duration::ZERO, Duration::ZERO, Duration::ZERO);
    let mut total_verify_times = (Duration::ZERO, Duration::ZERO, Duration::ZERO, Duration::ZERO);
    let mut total_commitment_size = 0;
    let mut total_proof_sizes = (0, 0, 0);

    for _ in 0..RUNS {
        let mut data_list = vec![];
        for _ in 0..batch_size {
            data_list.push(rand_vector::<u8>(data_size));
        }

        let prover_builder = FridaProverBuilder::<E, H>::new(options.clone());
        let (com, prover) = prover_builder.commit_and_prove_batch(&data_list, num_queries).unwrap();

        unsafe {
            total_erasure_time += ERASURE_TIME.unwrap_or_default();
            total_commitment_time += COMMIT_TIME.unwrap_or_default();
            ERASURE_TIME = None;
            COMMIT_TIME = None;
        }

        total_commitment_size += com.proof.size() + com.roots.len() * 32 + 3;

        let positions = rand_vector::<u64>(32)
            .into_iter()
            .map(|v| (v as usize) % com.domain_size)
            .collect::<Vec<_>>();

        let evaluations = get_evaluations_from_positions(
            &prover.get_first_layer_evalutaions(),
            &positions,
            batch_size,
            com.domain_size,
            options.folding_factor(),
        );

        // Benchmark proof generation
        let timer = Instant::now();
        let proof_1 = prover.open(&positions[0..1]);
        total_proof_sizes.0 += proof_1.size();
        total_proof_times.0 += timer.elapsed();

        let timer = Instant::now();
        let proof_16 = prover.open(&positions[0..16]);
        total_proof_sizes.1 += proof_16.size();
        total_proof_times.1 += timer.elapsed();

        let timer = Instant::now();
        let proof_32 = prover.open(&positions);
        total_proof_sizes.2 += proof_32.size();
        total_proof_times.2 += timer.elapsed();

        // Benchmark verification
        let timer = Instant::now();
        let verifier = prepare_verifier::<E, H>(
            options.blowup_factor(),
            options.folding_factor(),
            options.remainder_max_degree(),
            com,
        );
        total_verify_times.0 += timer.elapsed();

        let timer = Instant::now();
        verifier.verify(&proof_1, &evaluations[0..batch_size], &positions[0..1]).unwrap();
        total_verify_times.1 += timer.elapsed();

        let timer = Instant::now();
        verifier.verify(&proof_16, &evaluations[0..batch_size * 16], &positions[0..16]).unwrap();
        total_verify_times.2 += timer.elapsed();

        let timer = Instant::now();
        verifier.verify(&proof_32, &evaluations, &positions).unwrap();
        total_verify_times.3 += timer.elapsed();
    }

    FridaBenchmarkResult {
        field_type: field_name.to_string(),
        batch_size,
        blowup_factor: options.blowup_factor(),
        folding_factor: options.folding_factor(),
        max_remainder_degree: options.remainder_max_degree(),
        data_size_kb: data_size / 1024,
        num_queries,
        erasure_time_ms: total_erasure_time.as_secs_f64() * 1000.0 / RUNS as f64,
        commitment_time_ms: total_commitment_time.as_secs_f64() * 1000.0 / RUNS as f64,
        proof_time_1_ms: total_proof_times.0.as_secs_f64() * 1000.0 / RUNS as f64,
        proof_time_16_ms: total_proof_times.1.as_secs_f64() * 1000.0 / RUNS as f64,
        proof_time_32_ms: total_proof_times.2.as_secs_f64() * 1000.0 / RUNS as f64,
        verification_setup_ms: total_verify_times.0.as_secs_f64() * 1000.0 / RUNS as f64,
        verification_1_ms: total_verify_times.1.as_secs_f64() * 1000.0 / RUNS as f64,
        verification_16_ms: total_verify_times.2.as_secs_f64() * 1000.0 / RUNS as f64,
        verification_32_ms: total_verify_times.3.as_secs_f64() * 1000.0 / RUNS as f64,
        commitment_size_bytes: total_commitment_size / RUNS,
        proof_size_1_bytes: total_proof_sizes.0 / RUNS,
        proof_size_16_bytes: total_proof_sizes.1 / RUNS,
        proof_size_32_bytes: total_proof_sizes.2 / RUNS,
    }
}

pub fn run_full_benchmark(output_path: &str) {
    let fri_options = get_standard_fri_options();
    let data_sizes_f64 = get_standard_data_sizes::<F64Element>();
    let data_sizes_f128 = get_standard_data_sizes::<F128Element>();
    let num_queries_list = get_standard_num_queries();
    let batch_sizes = get_standard_batch_sizes();

    let mut results = Vec::new();

    println!("Running full Frida benchmark suite...");
    println!("Configurations: {} FRI options × {} data sizes × {} queries × {} batch sizes × 2 field types",
        fri_options.len(), data_sizes_f64.len(), num_queries_list.len(), batch_sizes.len());

    for &(blowup_factor, folding_factor, max_remainder_degree) in &fri_options {
        let options = FriOptions::new(blowup_factor, folding_factor, max_remainder_degree);

        for (&data_size_f64, &data_size_f128) in data_sizes_f64.iter().zip(data_sizes_f128.iter()) {
            for &num_queries in &num_queries_list {
                // Non-batched (batch_size = 1)
                if let Ok(result) = std::panic::catch_unwind(|| {
                    benchmark_non_batched::<F64Element, Blake3_F64>(
                        options.clone(), data_size_f64, num_queries, field_names::F64
                    )
                }) {
                    results.push(result);
                }

                if let Ok(result) = std::panic::catch_unwind(|| {
                    benchmark_non_batched::<F128Element, Blake3_F128>(
                        options.clone(), data_size_f128, num_queries, field_names::F128
                    )
                }) {
                    results.push(result);
                }

                // Batched
                for &batch_size in &batch_sizes {
                    if let Ok(result) = std::panic::catch_unwind(|| {
                        benchmark_batched::<F64Element, Blake3_F64>(
                            options.clone(), data_size_f64, batch_size, num_queries, field_names::F64
                        )
                    }) {
                        results.push(result);
                    }

                    if let Ok(result) = std::panic::catch_unwind(|| {
                        benchmark_batched::<F128Element, Blake3_F128>(
                            options.clone(), data_size_f128, batch_size, num_queries, field_names::F128
                        )
                    }) {
                        results.push(result);
                    }
                }
            }
        }
    }

    common::save_results_with_header(&results, output_path, &FridaBenchmarkResult::csv_header(), |r| r.to_csv())
        .expect("Failed to save results");
    println!("Frida benchmark completed with {} successful results", results.len());
}

pub fn run_custom_benchmark(
    blowup_factor: usize,
    folding_factor: usize,
    max_remainder_degree: usize,
    data_size: usize,
    batch_size: usize,
    num_queries: usize,
    output_path: &str,
) {
    let options = FriOptions::new(blowup_factor, folding_factor, max_remainder_degree);
    let mut results = Vec::new();

    println!("Running custom Frida benchmark...");
    println!("Parameters: blowup={}, folding={}, remainder={}, data={}KB, batch={}, queries={}",
        blowup_factor, folding_factor, max_remainder_degree, data_size / 1024, batch_size, num_queries);

    if batch_size > 1 {
        let result_f64 = benchmark_batched::<F64Element, Blake3_F64>(
            options.clone(), data_size, batch_size, num_queries, field_names::F64
        );
        results.push(result_f64);

        let result_f128 = benchmark_batched::<F128Element, Blake3_F128>(
            options.clone(), data_size, batch_size, num_queries, field_names::F128
        );
        results.push(result_f128);
    } else {
        let result_f64 = benchmark_non_batched::<F64Element, Blake3_F64>(
            options.clone(), data_size, num_queries, field_names::F64
        );
        results.push(result_f64);

        let result_f128 = benchmark_non_batched::<F128Element, Blake3_F128>(
            options.clone(), data_size, num_queries, field_names::F128
        );
        results.push(result_f128);
    }

    common::save_results_with_header(&results, output_path, &FridaBenchmarkResult::csv_header(), |r| r.to_csv())
        .expect("Failed to save results");
    println!("Custom Frida benchmark completed successfully");
}