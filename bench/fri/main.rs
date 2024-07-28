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
    frida_random::{FridaRandom, FridaRandomCoin},
    frida_verifier::{das::FridaDasVerifier, traits::BaseFridaVerifier},
};
use winter_crypto::{hashers::Blake3_256, ElementHasher};
use winter_fri::FriOptions;
use winter_math::{FieldElement, fields::{f64, f128}};
use winter_rand_utils::rand_vector;

mod data_structure;

const RUNS: u32 = 10;

fn data_sizes<E: FieldElement>() -> Vec<usize> {
    // for now using more than 1 size at once results in the index out of range error, will fix it asap
    vec![
        (128 * 1024) / E::ELEMENT_BYTES * (E::ELEMENT_BYTES - 1) - 8,
        // (256 * 1024) / E::ELEMENT_BYTES * (E::ELEMENT_BYTES - 1) - 8,
        // (512 * 1024) / E::ELEMENT_BYTES * (E::ELEMENT_BYTES - 1) - 8,
        // (1024 * 1024) / E::ELEMENT_BYTES * (E::ELEMENT_BYTES - 1) - 8,
        // (2048 * 1024) / E::ELEMENT_BYTES * (E::ELEMENT_BYTES - 1) - 8,
    ]
}

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
) -> FridaDasVerifier<E, H, H, FridaRandom<H, H, E>> {
    let options = FriOptions::new(blowup_factor, folding_factor, remainder_max_degree);
    let mut coin = FridaRandom::<H, H, E>::new(&[123]);
    FridaDasVerifier::new(com, &mut coin, options.clone()).unwrap()
}

fn run<E: FieldElement, H: ElementHasher<BaseField = E::BaseField>>() {
    let datas = data_sizes::<E>()
        .into_iter()
        .map(|size| rand_vector::<u8>(size))
        .collect::<Vec<_>>();
    let num_queries = vec![8, 16, 32];

    let prover_options = vec![
        (2, 2, 0),
        (2, 2, 256),
        (2, 4, 2),
        (2, 4, 256),
        (2, 8, 4),
        (2, 8, 256),
        (2, 16, 8),
        (2, 16, 256),
    ];

    println!("FriOptions, Queries, Data Size, Erasure Coding, Commitment, Proofs (1, 16, 32), Verification (Com, 1, 16, 32), Commitment Size, Proof Size (1, 16, 32)");

    let mut results = vec![];

    for opt in prover_options {
        let prover_builder = prepare_prover_builder::<E, H>(opt.0, opt.1, opt.2);

        for data in datas.iter() {
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
                        prover_builder.commit(&data, *num_query).unwrap();
                    // +1 roots len, +1 batch_size, +1 num_query = +3 at the end
                    commit_size += com.proof.size() + com.roots.len() * 32 + 3;

                    let positions = rand_vector::<u64>(32)
                        .into_iter()
                        .map(|v| (v as usize) % com.domain_size)
                        .collect::<Vec<_>>();

                    let evaluations = positions
                        .iter()
                        .map(|pos| {
                            prover.get_first_layer_evalutaions()[(pos % (com.domain_size / opt.1))
                                * opt.1
                                + (pos / (com.domain_size / opt.1))]
                        })
                        .collect::<Vec<_>>();

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
                        .verify(proof_0, &evaluations[0..1], &positions[0..1])
                        .unwrap();
                    verify_time.1 += timer.elapsed();

                    timer = Instant::now();
                    verifier
                        .verify(proof_1, &evaluations[0..16], &positions[0..16])
                        .unwrap();
                    verify_time.2 += timer.elapsed();

                    timer = Instant::now();
                    verifier.verify(proof_2, &evaluations, &positions).unwrap();
                    verify_time.3 += timer.elapsed();
                }
                results.push(format!(
                    "{:?}, {}, {}Kb, {:?}, {:?}, ({:?}, {:?}, {:?}), ({:?}, {:?}, {:?}, {:?}), {}, ({}, {}, {})",
                    opt,
                    num_query,
                    data.len() / 1024,
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
    }

    for result in results {
        println!("{}", result);
    }
}

fn run_batched<E: FieldElement, H: ElementHasher<BaseField = E::BaseField>>() {
    let mut batch_size: usize = 0;

    let datas = data_sizes::<E>()
        .into_iter()
        .map(|size| {
            let data_struct = data_structure::DataDesign::new(size);
            let data = data_struct.create_square_data();

            batch_size = data.len();
            println!("Batch size: {}, data size: {}", batch_size, size);
            data
        })
        .collect::<Vec<_>>();
    let num_queries = vec![8, 16, 32];

    // when using remainder_max_degree (option 3) that's more than 16, the program results in "NotEnoughDataPoints" error.
    // so, i have just commented out the ones that are more than 16 for testing purposes
    let prover_options = vec![
        (2, 2, 0),
        // (2, 2, 256),
        (2, 4, 2),
        // (2, 4, 256),
        (2, 8, 4),
        // (2, 8, 256),
        (2, 16, 8),
        // (2, 16, 256),
    ];

    println!("FriOptions, Queries, Data Size (Batched {}), Erasure Coding, Commitment, Proofs (1, 16, 32), Verification (Com, 1, 16, 32), Commitment Size, Proof Size (1, 16, 32)", batch_size);

    let mut results = vec![];

    for opt in prover_options {
        let prover_builder = prepare_prover_builder::<E, H>(opt.0, opt.1, opt.2);

        for data in datas.iter() {
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

                    // +1 roots len, +1 batch_size, +1 num_query = +3 at the end
                    commit_size += com.proof.size() + com.roots.len() * 32 + 3;

                    let positions = rand_vector::<u64>(32)
                        .into_iter()
                        .map(|v| (v as usize) % com.domain_size)
                        .collect::<Vec<_>>();

                    let mut evaluations = vec![];
                    for position in positions.iter() {
                        let bucket = position % (com.domain_size / opt.1);
                        let start_index = bucket * (batch_size * opt.1)
                            + (position / (com.domain_size / opt.1)) * batch_size;
                        prover.get_first_layer_evalutaions()[start_index..start_index + batch_size]
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
                        .verify(proof_0, &evaluations[0..batch_size], &positions[0..1])
                        .unwrap();
                    verify_time.1 += timer.elapsed();

                    timer = Instant::now();
                    verifier
                        .verify(proof_1, &evaluations[0..batch_size * 16], &positions[0..16])
                        .unwrap();
                    verify_time.2 += timer.elapsed();

                    timer = Instant::now();
                    verifier.verify(proof_2, &evaluations, &positions).unwrap();
                    verify_time.3 += timer.elapsed();
                }
                results.push(format!(
                    "{:?}, {}, {}Kb, {:?}, {:?}, ({:?}, {:?}, {:?}), ({:?}, {:?}, {:?}, {:?}), {}, ({}, {}, {})",
                    opt,
                    num_query,
                    data[0].len() / 1024 * batch_size,
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
    }

    for result in results {
        println!("{}", result);
    }
}

fn main() {
    // println!("FRI...\n\n");
    // println!("64bit...");
    // run::<f64::BaseElement, Blake3_256<f64::BaseElement>>();

    // println!("\n128bit...");
    // run::<f128::BaseElement, Blake3_256<f128::BaseElement>>();

    println!("\nBatched FRI...\n\n");
    println!("64bit...");
    run_batched::<f64::BaseElement, Blake3_256<f64::BaseElement>>();
    // for i in [2, 4, 8, 16] {
    //     run_batched::<f64::BaseElement, Blake3_256<f64::BaseElement>>(i);
    // }

    println!("\n128bit...");
    run_batched::<f128::BaseElement, Blake3_256<f128::BaseElement>>();
    // for i in [2, 4, 8, 16] {
    //     run_batched::<f128::BaseElement, Blake3_256<f128::BaseElement>>(i);
    // }
}