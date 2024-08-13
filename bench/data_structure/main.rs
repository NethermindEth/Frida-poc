#![cfg(feature = "bench")]
use std::{
    println,
    time::{Duration, Instant},
};

use frida_poc::{
    frida_prover::{
        bench::{COMMIT_TIME, ERASURE_TIME},
        Commitment, FridaProverBuilder,
    },
    frida_verifier::das::FridaDasVerifier,
};
use winter_crypto::{hashers::Blake3_256, ElementHasher};
use winter_fri::FriOptions;
use winter_math::{FieldElement, fields::{f64, f128}};
use winter_rand_utils::rand_vector;

use rayon::prelude::*;
use std::sync::Mutex;

mod data_structure;


const RUNS: u32 = 10;

fn prepare_prover_builder<E: FieldElement, H: ElementHasher<BaseField = E::BaseField>>(
    blowup_factor: usize,
    folding_factor: usize,
    remainder_max_degree: usize,
) -> FridaProverBuilder<E, H> {
    let options = FriOptions::new(blowup_factor, folding_factor, remainder_max_degree);
    FridaProverBuilder::new(options)
}

fn prepare_verifier<E: FieldElement, H: ElementHasher<BaseField = E::BaseField>>(
    blowup_factor: usize,
    folding_factor: usize,
    remainder_max_degree: usize,
    com: Commitment<H>,
) -> FridaDasVerifier<E, H, H> {
    let options = FriOptions::new(blowup_factor, folding_factor, remainder_max_degree);
    FridaDasVerifier::new(com, options.clone()).unwrap().0
}

/// the function handles formatting duration to denote the time units in front
fn format_duration(d: Duration) -> String {
    let total_micros = d.as_micros();
    let millis = total_micros / 1_000;

    if millis > 0 {
        format!("ms {}.{:03}", millis, total_micros % 1_000)
    } else {
        format!("µs {}", total_micros)
    }
}

fn run_approach_1<E: FieldElement, H: ElementHasher<BaseField = E::BaseField>>(k_amount: usize) {
    let k_amount_sqrt: usize = (k_amount as f64).sqrt().ceil() as usize; // k^1/2

    let data_struct = data_structure::DataDesign{chunk_amount: k_amount};
    let data = data_struct.create_data::<E>();

    println!("\nk^1/2 = {}, data size = {} (bits, each batch)\n", k_amount_sqrt, data[0].len());

    let num_queries = vec![8, 16, 32];

    let prover_options = vec![
        (2, 2, 0),
        (2, 4, 2),
        (2, 8, 4),
        (2, 16, 8),
        (2, 16, 16),
    ];

    println!("FriOptions, Queries, Data Size (Batched {}), Erasure Coding, Commitment, Proofs (1, 16, 32), Verification (Com, 1, 16, 32), Commitment Size, Proof Size (1, 16, 32)", k_amount_sqrt);

    let mut results = vec![];

    for opt in prover_options {
        let prover_builder = prepare_prover_builder::<E, H>(opt.0, opt.1, opt.2);

        for num_query in num_queries.iter() {
            let mut prove_time = (
                Duration::default(),
                Duration::default(),
                Duration::default(),
            );
            let mut verify_time = (
                Duration::default(),
                Duration::default(),
                Duration::default(),
                Duration::default(),
            );

            let mut commit_size = 0;
            let mut proof_size = (0, 0, 0);

            for _ in 0..RUNS {
                let (com, prover) =
                    prover_builder.commit_batch(&data, *num_query).unwrap();

                // +1 roots len, +1 k_amount_sqrt, +1 num_query = +3 at the end
                commit_size += com.proof.size() + com.roots.len() * 32 + 3;

                let positions = rand_vector::<u64>(32)
                    .into_iter()
                    .map(|v| (v as usize) % com.domain_size)
                    .collect::<Vec<_>>();

                let mut evaluations = vec![];
                for position in positions.iter() {
                    let bucket = position % (com.domain_size / opt.1);
                    let start_index = bucket * (k_amount_sqrt * opt.1)
                        + (position / (com.domain_size / opt.1)) * k_amount_sqrt;
                    prover.get_first_layer_evalutaions()[start_index..start_index + k_amount_sqrt]
                        .iter()
                        .for_each(|e| {
                            evaluations.push(*e);
                        });
                }

                let mut timer = Instant::now();
                let proof_0 = prover.open(&positions[0..1]);
                proof_size.0 += proof_0.size();
                prove_time.0 += timer.elapsed();

                timer = Instant::now();
                let proof_1 = prover.open(&positions[0..16]);
                proof_size.1 += proof_1.size();
                prove_time.1 += timer.elapsed();

                timer = Instant::now();
                let proof_2 = prover.open(&positions);
                proof_size.2 += proof_2.size();
                prove_time.2 += timer.elapsed();

                timer = Instant::now();
                let verifier = prepare_verifier::<E, H>(opt.0, opt.1, opt.2, com);
                verify_time.0 += timer.elapsed();

                timer = Instant::now();
                verifier
                    .verify(&proof_0, &evaluations[0..k_amount_sqrt], &positions[0..1])
                    .unwrap();
                verify_time.1 += timer.elapsed();

                timer = Instant::now();
                verifier
                    .verify(&proof_1, &evaluations[0..k_amount_sqrt * 16], &positions[0..16])
                    .unwrap();
                verify_time.2 += timer.elapsed();

                timer = Instant::now();
                verifier.verify(&proof_2, &evaluations, &positions).unwrap();
                verify_time.3 += timer.elapsed();
            }
            
            results.push(format!(
                "{:?}, {}, Kb {:.2}, {}, {}, ({}, {}, {}), ({}, {}, {}, {}), {}, ({}, {}, {})",
                opt,
                num_query,
                data[0].len() as f64 / 1024.0 * k_amount_sqrt as f64,
                format_duration(unsafe { ERASURE_TIME.unwrap() / RUNS }),
                format_duration(unsafe { COMMIT_TIME.unwrap() / RUNS }),
                format_duration(prove_time.0 / RUNS),
                format_duration(prove_time.1 / RUNS),
                format_duration(prove_time.2 / RUNS),
                format_duration(verify_time.0 / RUNS),
                format_duration(verify_time.1 / RUNS),
                format_duration(verify_time.2 / RUNS),
                format_duration(verify_time.3 / RUNS),
                commit_size / RUNS as usize,
                proof_size.0 / RUNS as usize,
                proof_size.1 / RUNS as usize,
                proof_size.2 / RUNS as usize,
            ));

            unsafe {
                ERASURE_TIME = None;
                COMMIT_TIME = None;
            }
        }
    }

    for result in results {
        println!("{}", result);
    }
}

fn run_approach_2<E: FieldElement, H: ElementHasher<BaseField = E::BaseField>>(k_amount: usize)
where
    E: FieldElement,
    // ensuring H is both: Send and Sync, so it could be shared between threads
    H: ElementHasher<BaseField = E::BaseField> + Send + Sync,
{
    let k_amount_cubic: usize = f64::powf(k_amount as f64, 1.0 / 3.0).ceil() as usize; // k^1/3

    let data_struct = data_structure::DataDesign{chunk_amount: k_amount};
    let datas = data_struct.create_subsquare_data::<E>();

    println!("\nk^1/3 = {}, data size = {} (bits, each batch)\n", k_amount_cubic, datas[0][0].len());

    let num_queries = vec![8, 16, 32];

    let prover_options = vec![
        (2, 2, 0),
        (2, 4, 2),
        (2, 8, 4),
        (2, 16, 8),
        (2, 16, 16),
    ];

    println!("FriOptions, Queries, Data Size (Batched {}), Erasure Coding, Commitment, Proofs (1, 16, 32), Verification (Com, 1, 16, 32), Commitment Size, Proof Size (1, 16, 32)", k_amount_cubic);

    let mut results = vec![];

    for opt in &prover_options {
        let prover_builder = prepare_prover_builder::<E, H>(opt.0, opt.1, opt.2);

        for num_query in &num_queries {
            let batch_total_data_size = Mutex::new(0.0);

            let prove_time = Mutex::new((Duration::default(), Duration::default(), Duration::default()));
            let verify_time = Mutex::new((Duration::default(), Duration::default(), Duration::default(), Duration::default()));
            let commit_size = Mutex::new(0);
            let proof_size = Mutex::new((0, 0, 0));

            datas.par_iter().for_each(|data| {
                for _ in 0..RUNS {
                    let (com, prover) = prover_builder.commit_batch(&data, *num_query).unwrap();

                    let mut commit_size_guard = commit_size.lock().unwrap();
                    *commit_size_guard += com.proof.size() + com.roots.len() * 32 + 3;
                    drop(commit_size_guard);

                    let positions: Vec<usize> = rand_vector::<u64>(32)
                        .into_iter()
                        .map(|v| (v as usize) % com.domain_size)
                        .collect();

                    let mut evaluations = vec![];
                    for position in &positions {
                        let bucket = position % (com.domain_size / opt.1);
                        let start_index = bucket * (k_amount_cubic * opt.1)
                            + (position / (com.domain_size / opt.1)) * k_amount_cubic;
                        evaluations.extend_from_slice(&prover.get_first_layer_evalutaions()[start_index..start_index + k_amount_cubic]);
                    }

                    let mut batch_total_data_size_guard = batch_total_data_size.lock().unwrap();
                    *batch_total_data_size_guard += data[0].len() as f64 / 1024.0 * k_amount_cubic as f64;
                    drop(batch_total_data_size_guard);

                    let mut timer = Instant::now();
                    let proof_0 = prover.open(&positions[0..1]);
                    let mut proof_size_guard = proof_size.lock().unwrap();
                    proof_size_guard.0 += proof_0.size();
                    drop(proof_size_guard);
                    let mut prove_time_guard = prove_time.lock().unwrap();
                    prove_time_guard.0 += timer.elapsed();
                    drop(prove_time_guard);

                    timer = Instant::now();
                    let proof_1 = prover.open(&positions[0..16]);
                    let mut proof_size_guard = proof_size.lock().unwrap();
                    proof_size_guard.1 += proof_1.size();
                    drop(proof_size_guard);
                    let mut prove_time_guard = prove_time.lock().unwrap();
                    prove_time_guard.1 += timer.elapsed();
                    drop(prove_time_guard);

                    timer = Instant::now();
                    let proof_2 = prover.open(&positions);
                    let mut proof_size_guard = proof_size.lock().unwrap();
                    proof_size_guard.2 += proof_2.size();
                    drop(proof_size_guard);
                    let mut prove_time_guard = prove_time.lock().unwrap();
                    prove_time_guard.2 += timer.elapsed();
                    drop(prove_time_guard);

                    timer = Instant::now();
                    let verifier = prepare_verifier::<E, H>(opt.0, opt.1, opt.2, com);
                    let mut verify_time_guard = verify_time.lock().unwrap();
                    verify_time_guard.0 += timer.elapsed();
                    drop(verify_time_guard);

                    timer = Instant::now();
                    verifier.verify(&proof_0, &evaluations[0..k_amount_cubic], &positions[0..1]).unwrap();
                    let mut verify_time_guard = verify_time.lock().unwrap();
                    verify_time_guard.1 += timer.elapsed();
                    drop(verify_time_guard);

                    timer = Instant::now();
                    verifier.verify(&proof_1, &evaluations[0..k_amount_cubic * 16], &positions[0..16]).unwrap();
                    let mut verify_time_guard = verify_time.lock().unwrap();
                    verify_time_guard.2 += timer.elapsed();
                    drop(verify_time_guard);

                    timer = Instant::now();
                    verifier.verify(&proof_2, &evaluations, &positions).unwrap();
                    let mut verify_time_guard = verify_time.lock().unwrap();
                    verify_time_guard.3 += timer.elapsed();
                    drop(verify_time_guard);
                }
            });

            let batch_total_data_size = *batch_total_data_size.lock().unwrap() / RUNS as f64;
            let prove_time = *prove_time.lock().unwrap();
            let verify_time = *verify_time.lock().unwrap();
            let commit_size = *commit_size.lock().unwrap() / RUNS as usize;
            let proof_size = *proof_size.lock().unwrap();
            
            results.push(format!(
                "{:?}, {}, Kb {:.2}, {}, {}, ({}, {}, {}), ({}, {}, {}, {}), {}, ({}, {}, {})",
                opt,
                num_query,
                batch_total_data_size,
                format_duration(unsafe { ERASURE_TIME.unwrap() / RUNS }),
                format_duration(unsafe { COMMIT_TIME.unwrap() / RUNS }),
                format_duration(prove_time.0 / RUNS),
                format_duration(prove_time.1 / RUNS),
                format_duration(prove_time.2 / RUNS),
                format_duration(verify_time.0 / RUNS),
                format_duration(verify_time.1 / RUNS),
                format_duration(verify_time.2 / RUNS),
                format_duration(verify_time.3 / RUNS),
                commit_size,
                proof_size.0 / RUNS as usize,
                proof_size.1 / RUNS as usize,
                proof_size.2 / RUNS as usize,
            ));
        
            unsafe {
                ERASURE_TIME = None;
                COMMIT_TIME = None;
            }
        }
    }

    for result in results {
        println!("{}", result);
    }
}

fn main() {
    println!("\nBatched FRI\n");

    let k_values = data_structure::DataDesign::generate_sixth_powers(730, 300_000);
    println!("k values used: {:?}", k_values);

    println!("\n\nApproach 1:\n");
    println!("64bit...");
    for &k in &k_values {
        run_approach_1::<f64::BaseElement, Blake3_256<f64::BaseElement>>(k);
    }
    
    println!("\n128bit...");
    for &k in &k_values {
        run_approach_1::<f128::BaseElement, Blake3_256<f128::BaseElement>>(k);
    }

    println!("\n\nApproach 2:\n");
    println!("64bit...");
    for &k in &k_values {
        run_approach_2::<f64::BaseElement, Blake3_256<f64::BaseElement>>(k);
    }

    println!("\n128bit...");
    for &k in &k_values {
        run_approach_2::<f128::BaseElement, Blake3_256<f128::BaseElement>>(k);
    }
}
