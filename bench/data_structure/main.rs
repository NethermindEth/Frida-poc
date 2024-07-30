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

fn run_approach_1<E: FieldElement, H: ElementHasher<BaseField = E::BaseField>>(k_amount: usize) {
    let k_amount_sqrt: usize = (k_amount as f64).sqrt().ceil() as usize; // k^1/2

    let data_struct = data_structure::DataDesign{chunk_amount: k_amount};
    let data = data_struct.create_data::<E>();

    println!("\nk^1/2 = {}, data size = {} (bits, each batch)\n", k_amount_sqrt, data[0].len());

    let num_queries = vec![8, 16, 32];

    // when remainder max degree is larger than 16,
    // it's impossible to form enough evauluation points ("NotEnoughDataPoints" error)
    // 
    // BUT if k >= 117649,
    // any remainder max degree works
    let prover_options = vec![
        (2, 2, 0),
        // (2, 2, 256),
        (2, 4, 2),
        // (2, 4, 256),
        (2, 8, 4),
        // (2, 8, 256),
        (2, 16, 8),
        // (2, 16, 256),
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
                "{:?}, {}, {:.2}Kb, {:?}, {:?}, ({:?}, {:?}, {:?}), ({:?}, {:?}, {:?}, {:?}), {}, ({}, {}, {})",
                opt,
                num_query,
                data[0].len() as f64 / 1024.0 * k_amount_sqrt as f64,
                unsafe { ERASURE_TIME.unwrap() / RUNS },
                unsafe { COMMIT_TIME.unwrap() / RUNS },
                prove_time.0 / RUNS,
                prove_time.1 / RUNS,
                prove_time.2 / RUNS,
                verify_time.0 / RUNS,
                verify_time.1 / RUNS,
                verify_time.2 / RUNS,
                verify_time.3 / RUNS,
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

fn run_approach_2<E: FieldElement, H: ElementHasher<BaseField = E::BaseField>>(k_amount: usize) {
    let k_amount_cubic: usize = f64::powf(k_amount as f64, 1.0 / 3.0).ceil() as usize; // k^1/3

    let data_struct = data_structure::DataDesign{chunk_amount: k_amount};
    let datas = data_struct.create_subsquare_data::<E>();

    println!("\nk^1/3 = {}, data size = {} (bits, each batch)\n", k_amount_cubic, datas[0][0].len());
    
    let num_queries = vec![8, 16, 32];

    // in order to use the max remainder degree that's more 16,
    // the k value should be over 1 000 000. 
    // the exact k value that works for the larger remainder degrees will be determined soon.
    let prover_options = vec![
        (2, 2, 0),
        // (2, 2, 256),
        (2, 4, 2),
        // (2, 4, 256),
        (2, 8, 4),
        // (2, 8, 256),
        (2, 16, 8),
        // (2, 16, 256),
        (2, 16, 16),
    ];

    println!("FriOptions, Queries, Data Size (Batched {}), Erasure Coding, Commitment, Proofs (1, 16, 32), Verification (Com, 1, 16, 32), Commitment Size, Proof Size (1, 16, 32)", k_amount_cubic);

    let mut results = vec![];

    for opt in &prover_options {
        let prover_builder = prepare_prover_builder::<E, H>(opt.0, opt.1, opt.2);

        for num_query in num_queries.iter() {
            let mut batch_total_data_size = 0.0;

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

            for data in datas.iter() {
                for _ in 0..RUNS {
                    let (com, prover) =
                        prover_builder.commit_batch(&data, *num_query).unwrap();

                    // +1 roots len, +1 k_amount_cubic, +1 num_query = +3 at the end
                    commit_size += com.proof.size() + com.roots.len() * 32 + 3;

                    let positions = rand_vector::<u64>(32)
                        .into_iter()
                        .map(|v| (v as usize) % com.domain_size)
                        .collect::<Vec<_>>();

                    let mut evaluations = vec![];
                    for position in positions.iter() {
                        let bucket = position % (com.domain_size / opt.1);
                        let start_index = bucket * (k_amount_cubic * opt.1)
                            + (position / (com.domain_size / opt.1)) * k_amount_cubic;
                        prover.get_first_layer_evalutaions()[start_index..start_index + k_amount_cubic]
                            .iter()
                            .for_each(|e| {
                                evaluations.push(*e);
                            });
                    }

                    batch_total_data_size += data[0].len() as f64 / 1024.0 * k_amount_cubic as f64;

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
                        .verify(&proof_0, &evaluations[0..k_amount_cubic], &positions[0..1])
                        .unwrap();
                    verify_time.1 += timer.elapsed();

                    timer = Instant::now();
                    verifier
                        .verify(&proof_1, &evaluations[0..k_amount_cubic * 16], &positions[0..16])
                        .unwrap();
                    verify_time.2 += timer.elapsed();

                    timer = Instant::now();
                    verifier.verify(&proof_2, &evaluations, &positions).unwrap();
                    verify_time.3 += timer.elapsed();
                }
            }
            results.push(format!(
                "{:?}, {}, {:.2}Kb, {:?}, {:?}, ({:?}, {:?}, {:?}), ({:?}, {:?}, {:?}, {:?}), {}, ({}, {}, {})",
                opt,
                num_query,
                batch_total_data_size / RUNS as f64,
                unsafe { ERASURE_TIME.unwrap() / RUNS },
                unsafe { COMMIT_TIME.unwrap() / RUNS },
                prove_time.0 / RUNS,
                prove_time.1 / RUNS,
                prove_time.2 / RUNS,
                verify_time.0 / RUNS,
                verify_time.1 / RUNS,
                verify_time.2 / RUNS,
                verify_time.3 / RUNS,
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

fn main() {
    println!("\nBatched FRI\n");

    // when k <= 64, domain size becomes smaller than the number of queries
    // which results in the 'BadNumQueries' error
    // 
    // Old k values:
    // k = [16, 64, 256, 1024, 4096, 16384, 65536]
    // 
    // Now, for k values we are using numbers that that can be both square-rooted and cube-rooted
    // these numbers are the same as the perfect sixth powers
    let k_values = data_structure::DataDesign::generate_sixth_powers(730, 4096);
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
