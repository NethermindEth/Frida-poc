use std::time::{Duration, Instant};
use winter_crypto::ElementHasher;
use winter_fri::FriOptions;
use winter_math::FieldElement;
use winter_rand_utils::rand_vector;

use crate::runner::{Benchmark, BenchmarkParams};
use frida_poc::{
    constants, core::data::encoded_data_element_count, prover::builder::FridaProverBuilder,
};

use crate::common::{field_names, Blake3F128, Blake3F64, F128Element, F64Element, RUNS};

#[derive(Debug)]
pub struct SingleFridaBenchmarkResult {
    field_type: String,
    batch_size: u32,
    blowup_factor: u32,
    folding_factor: u32,
    max_remainder_degree: u32,
    data_size_kb: u64,
    domain_size: usize,
    single_proof_time_ms: f64,
    single_proof_size_bytes: u64,
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
    data_size: u64,
    field_name: &str,
) -> SingleFridaBenchmarkResult
where
    E: FieldElement,
    H: ElementHasher<BaseField = E::BaseField>,
{
    let mut total_proof_time = Duration::ZERO;
    let mut total_proof_size = 0;

    let encoded_element_count = encoded_data_element_count::<E>(data_size as usize);
    let domain_size = usize::max(
        encoded_element_count.next_power_of_two() * options.blowup_factor(),
        constants::MIN_DOMAIN_SIZE,
    );

    for _ in 0..RUNS {
        let data = rand_vector::<u8>(data_size as usize);
        let prover_builder = FridaProverBuilder::<E, H>::new(options.clone());

        let (_, prover, base_positions) = prover_builder
            .commitment(&data, 1)
            .expect("Commitment calculation failed");

        let drawn_position = vec![base_positions[0]];

        let start = Instant::now();
        let proof = prover.open(&drawn_position);
        total_proof_time += start.elapsed();
        total_proof_size += proof.size() as u64;
    }

    let avg_proof_time_ms = total_proof_time.as_secs_f64() * 1000.0 / RUNS as f64;
    let avg_proof_size_bytes = total_proof_size / RUNS as u64;
    let total_proof_size_estimate_mb =
        (domain_size as u64 * avg_proof_size_bytes) as f64 / (1024.0 * 1024.0);

    SingleFridaBenchmarkResult {
        field_type: field_name.to_string(),
        batch_size: 1,
        blowup_factor: options.blowup_factor() as u32,
        folding_factor: options.folding_factor() as u32,
        max_remainder_degree: options.remainder_max_degree() as u32,
        data_size_kb: data_size / 1024,
        domain_size,
        single_proof_time_ms: avg_proof_time_ms,
        single_proof_size_bytes: avg_proof_size_bytes,
        total_proof_size_estimate_mb,
    }
}

fn benchmark_batched<E, H>(
    options: FriOptions,
    data_size: u64,
    batch_size: u32,
    field_name: &str,
) -> SingleFridaBenchmarkResult
where
    E: FieldElement,
    H: ElementHasher<BaseField = E::BaseField>,
{
    let mut total_proof_time = Duration::ZERO;
    let mut total_proof_size = 0;

    let max_data_len = encoded_data_element_count::<E>(data_size as usize);
    let domain_size = usize::max(
        (max_data_len * options.blowup_factor()).next_power_of_two(),
        constants::MIN_DOMAIN_SIZE,
    );

    for _ in 0..RUNS {
        let mut data_list = vec![];
        for _ in 0..batch_size {
            data_list.push(rand_vector::<u8>(data_size as usize));
        }

        let prover_builder = FridaProverBuilder::<E, H>::new(options.clone());

        let (_, prover, base_positions) = prover_builder
            .commitment_batch(&data_list, 1)
            .expect("Batch commitment calculation failed");

        let drawn_position = vec![base_positions[0]];

        let start = Instant::now();
        let proof = prover.open(&drawn_position);
        total_proof_time += start.elapsed();
        total_proof_size += proof.size() as u64;
    }

    let avg_proof_time_ms = total_proof_time.as_secs_f64() * 1000.0 / RUNS as f64;
    let avg_proof_size_bytes = total_proof_size / RUNS as u64;
    let total_proof_size_estimate_mb =
        (domain_size as u64 * avg_proof_size_bytes) as f64 / (1024.0 * 1024.0);

    SingleFridaBenchmarkResult {
        field_type: field_name.to_string(),
        batch_size,
        blowup_factor: options.blowup_factor() as u32,
        folding_factor: options.folding_factor() as u32,
        max_remainder_degree: options.remainder_max_degree() as u32,
        data_size_kb: data_size / 1024,
        domain_size,
        single_proof_time_ms: avg_proof_time_ms,
        single_proof_size_bytes: avg_proof_size_bytes,
        total_proof_size_estimate_mb,
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SingleFridaBenchmark;

impl Benchmark for SingleFridaBenchmark {
    type BenchmarkResult = SingleFridaBenchmarkResult;

    fn csv_header() -> String {
        SingleFridaBenchmarkResult::csv_header()
    }

    fn to_csv(result: &Self::BenchmarkResult) -> String {
        result.to_csv()
    }

    fn run_f64_non_batched(
        &self,
        options: FriOptions,
        params: &BenchmarkParams,
    ) -> Self::BenchmarkResult {
        benchmark_non_batched::<F64Element, Blake3F64>(options, params.data_size, field_names::F64)
    }

    fn run_f128_non_batched(
        &self,
        options: FriOptions,
        params: &BenchmarkParams,
    ) -> Self::BenchmarkResult {
        benchmark_non_batched::<F128Element, Blake3F128>(
            options,
            params.data_size,
            field_names::F128,
        )
    }

    fn run_f64_batched(
        &self,
        options: FriOptions,
        params: &BenchmarkParams,
    ) -> Self::BenchmarkResult {
        benchmark_batched::<F64Element, Blake3F64>(
            options,
            params.data_size,
            params.batch_size,
            field_names::F64,
        )
    }

    fn run_f128_batched(
        &self,
        options: FriOptions,
        params: &BenchmarkParams,
    ) -> Self::BenchmarkResult {
        benchmark_batched::<F128Element, Blake3F128>(
            options,
            params.data_size,
            params.batch_size,
            field_names::F128,
        )
    }
}
