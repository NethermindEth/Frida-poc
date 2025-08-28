use crate::common::{self, FieldType};
use frida_poc::winterfell::FriOptions;
use itertools::iproduct;
use std::fmt::Debug;

pub trait Benchmark: Debug + Sized {
    type BenchmarkResult: Debug + Send + 'static;

    fn csv_header() -> String;
    fn to_csv(result: &Self::BenchmarkResult) -> String;

    fn run_f64_non_batched(
        &self,
        options: FriOptions,
        params: &BenchmarkParams,
    ) -> Self::BenchmarkResult;
    fn run_f128_non_batched(
        &self,
        options: FriOptions,
        params: &BenchmarkParams,
    ) -> Self::BenchmarkResult;
    fn run_f64_batched(
        &self,
        options: FriOptions,
        params: &BenchmarkParams,
    ) -> Self::BenchmarkResult;
    fn run_f128_batched(
        &self,
        options: FriOptions,
        params: &BenchmarkParams,
    ) -> Self::BenchmarkResult;
}

#[derive(Debug, Clone)]
pub struct BenchmarkConfig {
    pub fri_options: Vec<(usize, usize, usize)>,
    pub data_sizes: Vec<usize>,
    pub batch_sizes: Vec<usize>,
    pub field_type: FieldType,
    pub output_path: String,
    // Optional parameters
    pub num_queries: Option<Vec<usize>>,
    pub num_validators: Option<Vec<usize>>,
}

#[derive(Debug, Clone, Copy)]
pub struct BenchmarkParams {
    pub data_size: usize,
    pub batch_size: usize,
    pub num_queries: usize,
    pub num_validators: usize,
}

pub fn run_benchmark<B: Benchmark>(benchmark: B, config: BenchmarkConfig) {
    let mut results = Vec::new();
    println!("...Running benchmark...");

    let num_queries_iter = config.num_queries.clone().unwrap_or_else(|| vec![0]);
    let num_validators_iter = config.num_validators.clone().unwrap_or_else(|| vec![0]);

    for (fri_option, &data_size, &batch_size, &num_queries, &num_validators) in iproduct!(
        config.fri_options.iter(),
        config.data_sizes.iter(),
        config.batch_sizes.iter(),
        num_queries_iter.iter(),
        num_validators_iter.iter()
    ) {
        let &(blowup_factor, folding_factor, max_remainder_degree) = fri_option;
        let options = FriOptions::new(blowup_factor, folding_factor, max_remainder_degree);

        let params = BenchmarkParams {
            data_size,
            batch_size,
            num_queries,
            num_validators,
        };

        let mut run_for_field =
            |run_non_batched: &dyn Fn() -> B::BenchmarkResult,
             run_batched: &dyn Fn() -> B::BenchmarkResult| {
                if params.batch_size == 1 {
                    results.push(run_non_batched());
                } else {
                    results.push(run_batched());
                }
            };

        match config.field_type {
            FieldType::F64 => run_for_field(
                &|| benchmark.run_f64_non_batched(options.clone(), &params),
                &|| benchmark.run_f64_batched(options.clone(), &params),
            ),
            FieldType::F128 => run_for_field(
                &|| benchmark.run_f128_non_batched(options.clone(), &params),
                &|| benchmark.run_f128_batched(options.clone(), &params),
            ),
            FieldType::Both => {
                run_for_field(
                    &|| benchmark.run_f64_non_batched(options.clone(), &params),
                    &|| benchmark.run_f64_batched(options.clone(), &params),
                );
                run_for_field(
                    &|| benchmark.run_f128_non_batched(options.clone(), &params),
                    &|| benchmark.run_f128_batched(options.clone(), &params),
                );
            }
        }
    }

    common::save_results_with_header(&results, &config.output_path, &B::csv_header(), B::to_csv)
        .expect("Failed to save results");

    println!("Benchmark completed successfully");
}
