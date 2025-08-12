use std::time::{Duration, Instant};
use winter_crypto::ElementHasher;
use winter_fri::FriOptions;
use winter_math::FieldElement;
use winter_rand_utils::{rand_value, rand_vector};

use frida_poc::{
    core::data::{build_evaluations_from_data, encoded_data_element_count},
    frida_prover::{batch_data_to_evaluations, get_evaluations_from_positions, FridaProverBuilder},
    frida_verifier::das::FridaDasVerifier,
    frida_const,
};

use crate::common::{
    self, field_names, get_standard_data_sizes, get_standard_fri_options,
    get_standard_validator_counts, Blake3_F128, Blake3_F64, F128Element, F64Element, RUNS
};

#[derive(Debug)]
struct DefridaBenchmarkResult {
    field_type: String,
    batch_size: usize,
    blowup_factor: usize,
    folding_factor: usize,
    max_remainder_degree: usize,
    data_size_kb: usize,
    num_validators: usize,
    num_queries: usize,
    commitment_time_ms: f64,
    commitment_size_bytes: usize,
    avg_proof_time_ms: f64,
    avg_proof_size_bytes: usize,
    verification_setup_time_ms: f64,
    avg_verification_time_ms: f64,
}

impl DefridaBenchmarkResult {
    fn csv_header() -> String {
        "field_type,batch_size,blowup_factor,folding_factor,max_remainder_degree,data_size_kb,num_validators,num_queries,commitment_time_ms,commitment_size_bytes,avg_proof_time_ms,avg_proof_size_bytes,verification_setup_time_ms,avg_verification_time_ms".to_string()
    }

    fn to_csv(&self) -> String {
        format!(
            "{},{},{},{},{},{},{},{},{:.3},{},{:.3},{},{:.3},{:.3}",
            self.field_type,
            self.batch_size,
            self.blowup_factor,
            self.folding_factor,
            self.max_remainder_degree,
            self.data_size_kb,
            self.num_validators,
            self.num_queries,
            self.commitment_time_ms,
            self.commitment_size_bytes,
            self.avg_proof_time_ms,
            self.avg_proof_size_bytes,
            self.verification_setup_time_ms,
            self.avg_verification_time_ms
        )
    }
}

fn compute_position_assignments(
    n_validators: usize,
    query_positions: &[usize],
    h: usize,
) -> Vec<Vec<usize>> {
    let s = query_positions.len();
    let n = n_validators;
    if n == 0 {
        return vec![];
    }
    if n <= s {
        let span_length = s.saturating_sub(h) + 1;
        (1..=n)
            .map(|i| {
                let offset = (i - 1) % s;
                (0..span_length)
                    .map(|j| query_positions[(offset + j) % s])
                    .collect()
            })
            .collect()
    } else {
        let n_prime = (n / s) * s;
        if n_prime == 0 {
            return vec![Vec::new(); n];
        }
        let replication_factor = n_prime / s;
        let h_prime =
            (h.saturating_sub(n - n_prime) + replication_factor - 1) / replication_factor;
        let base_subsets = compute_position_assignments(s, query_positions, h_prime);
        (1..=n)
            .map(|i| {
                if i <= n_prime {
                    base_subsets[(i - 1) % s].clone()
                } else {
                    Vec::new()
                }
            })
            .collect()
    }
}

fn benchmark_non_batched<E, H>(
    options: FriOptions,
    data_size: usize,
    num_validators: usize,
    num_queries: usize,
    field_name: &str,
) -> DefridaBenchmarkResult
where
    E: FieldElement,
    H: ElementHasher<BaseField = E::BaseField>,
{
    let mut total_commitment_time = Duration::ZERO;
    let mut total_commitment_size = 0;
    let mut total_proof_times = Duration::ZERO;
    let mut total_proof_sizes = 0;
    let mut total_verification_setup_time = Duration::ZERO;
    let mut total_verification_time = Duration::ZERO;
    let mut total_proofs_generated = 0;

    for _ in 0..RUNS {
        let data = rand_vector::<u8>(data_size);
        let prover_builder = FridaProverBuilder::<E, H>::new(options.clone());

        let start = Instant::now();
        let (prover_commitment, prover, base_positions) = prover_builder
            .calculate_commitment(&data, num_queries)
            .expect("Commitment generation failed");
        total_commitment_time += start.elapsed();

        let commitment_size = prover_commitment.roots.len() * 32 + 16;
        total_commitment_size += commitment_size;

        let f = (num_validators - 1) / 3;
        let h = f + 1;
        let validator_positions = compute_position_assignments(num_validators, &base_positions, h);

        for positions in &validator_positions {
            if !positions.is_empty() {
                let start = Instant::now();
                let proof = prover.open(positions);
                total_proof_times += start.elapsed();
                total_proof_sizes += proof.size();
                total_proofs_generated += 1;
            }
        }

        let all_evaluations = build_evaluations_from_data::<E>(
            &data,
            prover_commitment.domain_size,
            options.blowup_factor(),
        )
        .unwrap();

        let setup_start = Instant::now();
        let verifier = FridaDasVerifier::<E, H, H>::from_commitment(
            &prover_commitment,
            options.clone(),
        )
        .expect("Verifier initialization failed");
        total_verification_setup_time += setup_start.elapsed();

        if let Some(positions) = validator_positions.iter().find(|p| !p.is_empty()) {
            let evaluations: Vec<E> = positions.iter().map(|&p| all_evaluations[p]).collect();
            let proof = prover.open(positions);

            let verify_start = Instant::now();
            verifier.verify(&proof, &evaluations, positions).unwrap();
            total_verification_time += verify_start.elapsed();
        }
    }

    DefridaBenchmarkResult {
        field_type: field_name.to_string(),
        batch_size: 1,
        blowup_factor: options.blowup_factor(),
        folding_factor: options.folding_factor(),
        max_remainder_degree: options.remainder_max_degree(),
        data_size_kb: data_size / 1024,
        num_validators,
        num_queries,
        commitment_time_ms: total_commitment_time.as_secs_f64() * 1000.0 / RUNS as f64,
        commitment_size_bytes: total_commitment_size / RUNS,
        avg_proof_time_ms: if total_proofs_generated > 0 {
            total_proof_times.as_secs_f64() * 1000.0 / total_proofs_generated as f64
        } else {
            0.0
        },
        avg_proof_size_bytes: if total_proofs_generated > 0 {
            total_proof_sizes / total_proofs_generated
        } else {
            0
        },
        verification_setup_time_ms: total_verification_setup_time.as_secs_f64() * 1000.0 / RUNS as f64,
        avg_verification_time_ms: total_verification_time.as_secs_f64() * 1000.0 / RUNS as f64,
    }
}

fn benchmark_batched<E, H>(
    options: FriOptions,
    data_size: usize,
    batch_size: usize,
    num_validators: usize,
    num_queries: usize,
    field_name: &str,
) -> DefridaBenchmarkResult
where
    E: FieldElement,
    H: ElementHasher<BaseField = E::BaseField>,
{
    let mut total_commitment_time = Duration::ZERO;
    let mut total_commitment_size = 0;
    let mut total_proof_times = Duration::ZERO;
    let mut total_proof_sizes = 0;
    let mut total_verification_setup_time = Duration::ZERO;
    let mut total_verification_time = Duration::ZERO;
    let mut total_proofs_generated = 0;

    for _ in 0..RUNS {
        let mut data_list = vec![];
        for _ in 0..batch_size {
            data_list.push(rand_vector::<u8>(data_size));
        }

        let prover_builder = FridaProverBuilder::<E, H>::new(options.clone());

        let start = Instant::now();
        let (prover_commitment, prover, base_positions) = prover_builder
            .calculate_commitment_batch(&data_list, num_queries)
            .expect("Batch commitment generation failed");
        total_commitment_time += start.elapsed();

        let commitment_size = prover_commitment.roots.len() * 32 + 16;
        total_commitment_size += commitment_size;

        let f = (num_validators - 1) / 3;
        let h = f + 1;
        let validator_positions = compute_position_assignments(num_validators, &base_positions, h);

        for positions in &validator_positions {
            if !positions.is_empty() {
                let start = Instant::now();
                let proof = prover.open(positions);
                total_proof_times += start.elapsed();
                total_proof_sizes += proof.size();
                total_proofs_generated += 1;
            }
        }

        let blowup_factor = options.blowup_factor();
        let max_data_len = encoded_data_element_count::<E>(
            data_list.iter().map(|data| data.len()).max().unwrap_or_default(),
        );
        let domain_size = usize::max(
            (max_data_len * blowup_factor).next_power_of_two(),
            frida_const::MIN_DOMAIN_SIZE,
        );

        let all_evaluations = batch_data_to_evaluations::<E>(
            &data_list,
            batch_size,
            domain_size,
            blowup_factor,
            options.folding_factor(),
        )
        .unwrap();

        let setup_start = Instant::now();
        let verifier = FridaDasVerifier::<E, H, H>::from_commitment(
            &prover_commitment,
            options.clone(),
        )
        .expect("Verifier initialization failed");
        total_verification_setup_time += setup_start.elapsed();

        if let Some(positions) = validator_positions.iter().find(|p| !p.is_empty()) {
            let evaluations = get_evaluations_from_positions(
                &all_evaluations,
                positions,
                batch_size,
                domain_size,
                options.folding_factor(),
            );
            let proof = prover.open(positions);

            let verify_start = Instant::now();
            verifier.verify(&proof, &evaluations, positions).unwrap();
            total_verification_time += verify_start.elapsed();
        }
    }

    DefridaBenchmarkResult {
        field_type: field_name.to_string(),
        batch_size,
        blowup_factor: options.blowup_factor(),
        folding_factor: options.folding_factor(),
        max_remainder_degree: options.remainder_max_degree(),
        data_size_kb: data_size / 1024,
        num_validators,
        num_queries,
        commitment_time_ms: total_commitment_time.as_secs_f64() * 1000.0 / RUNS as f64,
        commitment_size_bytes: total_commitment_size / RUNS,
        avg_proof_time_ms: if total_proofs_generated > 0 {
            total_proof_times.as_secs_f64() * 1000.0 / total_proofs_generated as f64
        } else {
            0.0
        },
        avg_proof_size_bytes: if total_proofs_generated > 0 {
            total_proof_sizes / total_proofs_generated
        } else {
            0
        },
        verification_setup_time_ms: total_verification_setup_time.as_secs_f64() * 1000.0 / RUNS as f64,
        avg_verification_time_ms: total_verification_time.as_secs_f64() * 1000.0 / RUNS as f64,
    }
}

pub fn run_full_benchmark(output_path: &str) {
    let fri_options = get_standard_fri_options();
    let data_sizes_f64 = get_standard_data_sizes::<F64Element>();
    let data_sizes_f128 = get_standard_data_sizes::<F128Element>();
    let validator_counts = get_standard_validator_counts();
    let batch_sizes = vec![1, 2, 4, 8, 16];
    let query_range = vec![32, 64, 128];

    let mut results = Vec::new();

    println!("Running full deFRIDA benchmark suite...");
    println!("Total configurations: {}", 
        fri_options.len() * data_sizes_f64.len() * validator_counts.len() * batch_sizes.len() * query_range.len() * 2);

    for &(blowup_factor, folding_factor, max_remainder_degree) in &fri_options {
        let options = FriOptions::new(blowup_factor, folding_factor, max_remainder_degree);
        
        for (&data_size_f64, &data_size_f128) in data_sizes_f64.iter().zip(data_sizes_f128.iter()) {
            for &num_validators in &validator_counts {
                for &num_queries in &query_range {
                    for &batch_size in &batch_sizes {
                        if batch_size == 1 {
                            if let Ok(result) = std::panic::catch_unwind(|| {
                                benchmark_non_batched::<F64Element, Blake3_F64>(
                                    options.clone(),
                                    data_size_f64,
                                    num_validators,
                                    num_queries,
                                    field_names::F64,
                                )
                            }) {
                                results.push(result);
                            }

                            if let Ok(result) = std::panic::catch_unwind(|| {
                                benchmark_non_batched::<F128Element, Blake3_F128>(
                                    options.clone(),
                                    data_size_f128,
                                    num_validators,
                                    num_queries,
                                    field_names::F128,
                                )
                            }) {
                                results.push(result);
                            }
                        } else {
                            if let Ok(result) = std::panic::catch_unwind(|| {
                                benchmark_batched::<F64Element, Blake3_F64>(
                                    options.clone(),
                                    data_size_f64,
                                    batch_size,
                                    num_validators,
                                    num_queries,
                                    field_names::F64,
                                )
                            }) {
                                results.push(result);
                            }

                            if let Ok(result) = std::panic::catch_unwind(|| {
                                benchmark_batched::<F128Element, Blake3_F128>(
                                    options.clone(),
                                    data_size_f128,
                                    batch_size,
                                    num_validators,
                                    num_queries,
                                    field_names::F128,
                                )
                            }) {
                                results.push(result);
                            }
                        }
                    }
                }
            }
        }
    }

    common::save_results_with_header(&results, output_path, &DefridaBenchmarkResult::csv_header(), |r| r.to_csv())
        .expect("Failed to save results");
    println!("deFRIDA benchmark completed with {} successful results", results.len());
}

pub fn run_custom_benchmark(
    blowup_factor: usize,
    folding_factor: usize,
    max_remainder_degree: usize,
    data_size: usize,
    num_validators: usize,
    num_queries: usize,
    batch_size: usize,
    output_path: &str,
) {
    let options = FriOptions::new(blowup_factor, folding_factor, max_remainder_degree);
    let mut results = Vec::new();

    println!("Running custom deFRIDA benchmark...");
    println!("Parameters: blowup={}, folding={}, remainder={}, data={}KB, validators={}, queries={}, batch_size={}",
        blowup_factor, folding_factor, max_remainder_degree, data_size / 1024, num_validators, num_queries, batch_size);

    if batch_size > 1 {
        let result_f64 = benchmark_batched::<F64Element, Blake3_F64>(
            options.clone(),
            data_size,
            batch_size,
            num_validators,
            num_queries,
            field_names::F64,
        );
        results.push(result_f64);

        let result_f128 = benchmark_batched::<F128Element, Blake3_F128>(
            options.clone(),
            data_size,
            batch_size,
            num_validators,
            num_queries,
            field_names::F128,
        );
        results.push(result_f128);
    } else {
        let result_f64 = benchmark_non_batched::<F64Element, Blake3_F64>(
            options.clone(),
            data_size,
            num_validators,
            num_queries,
            field_names::F64,
        );
        results.push(result_f64);

        let result_f128 = benchmark_non_batched::<F128Element, Blake3_F128>(
            options.clone(),
            data_size,
            num_validators,
            num_queries,
            field_names::F128,
        );
        results.push(result_f128);
    }

    common::save_results_with_header(&results, output_path, &DefridaBenchmarkResult::csv_header(), |r| r.to_csv())
        .expect("Failed to save results");
    println!("Custom deFRIDA benchmark completed successfully");
}