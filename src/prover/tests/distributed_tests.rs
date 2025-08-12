use super::*;
use crate::{
    core::data::{
        build_evaluations_from_data, encoded_data_element_count,
    },
    prover::{builder::FridaProverBuilder, Commitment, ProverCommitment, batch_data_to_evaluations, get_evaluations_from_positions},
    verifier::das::FridaDasVerifier,
    winterfell::{f128::BaseElement, Blake3_256, FriOptions},
    *,
};
use winter_rand_utils::{rand_value, rand_vector};

type Blake3 = Blake3_256<BaseElement>;

mod distributed_tests {
    use super::*;
    use crate::{
        core::data::build_evaluations_from_data,
        verifier::das::FridaDasVerifier,
        winterfell::{f128::BaseElement, Blake3_256, FriOptions},
    };
    use winter_rand_utils::{rand_value, rand_vector};

    type Blake3 = Blake3_256<BaseElement>;

    // This helper function would live in your application logic, not the library.
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

    #[test]
    fn test_distributed_proof_workflow() {
        // 1. SETUP: A block producer sets up the prover.
        let data = rand_vector::<u8>(512);
        let options = FriOptions::new(8, 4, 31);
        let n_validators = 10;
        let total_queries = 32;
        let prover_builder = FridaProverBuilder::<BaseElement, Blake3>::new(options.clone());

        // 2. COMMIT: The producer creates the commitment and the stateful prover.
        let (prover_commitment, prover, base_positions) = prover_builder
            .commitment(&data, total_queries)
            .expect("Commitment generation failed");

        // 3. DISTRIBUTE: The producer (or anyone) determines the query sets for each validator.
        let f = (n_validators - 1) / 3;
        let h = f + 1;
        let validator_positions = compute_position_assignments(n_validators, &base_positions, h);

        // 4. PROVE: The producer generates a specific, small proof for each validator.
        let validator_proofs: Vec<_> = validator_positions
            .iter()
            .map(|positions| {
                if positions.is_empty() {
                    None
                } else {
                    Some(prover.open(positions))
                }
            })
            .collect();

        // 5. VERIFY: Each validator independently verifies their assigned proof.
        let all_evaluations = build_evaluations_from_data::<BaseElement>(
            &data,
            prover_commitment.domain_size,
            options.blowup_factor(),
        )
        .unwrap();

        for i in 0..n_validators {
            if let Some(proof) = &validator_proofs[i] {
                let positions = &validator_positions[i];
                let evaluations: Vec<BaseElement> =
                    positions.iter().map(|&p| all_evaluations[p]).collect();

                // A. Validator initializes a verifier from the public commitment.
                let verifier = FridaDasVerifier::<BaseElement, Blake3, Blake3>::from_commitment(
                    &prover_commitment,
                    options.clone(),
                )
                .expect("Verifier initialization failed");

                // B. Validator verifies their specific proof against the global context.
                let verification_result = verifier.verify(proof, &evaluations, positions);

                assert!(
                    verification_result.is_ok(),
                    "Verification failed for validator {} with error: {:?}",
                    i,
                    verification_result.err()
                );
            }
        }
    }

    #[test]
    fn test_distributed_proof_workflow_batch() {
        let poly_count = 10;
        let mut data_list = vec![];
        for _ in 0..poly_count {
            data_list.push(rand_vector::<u8>(usize::min(
                rand_value::<u64>() as usize,
                128,
            )));
        }

        let options = FriOptions::new(2, 2, 1);
        let n_validators = 10;
        let total_queries = 30;
        let prover_builder = FridaProverBuilder::<BaseElement, Blake3>::new(options.clone());

        // 2. COMMIT: The producer creates the commitment and the stateful prover.
        let (prover_commitment, prover, base_positions) = prover_builder
            .commitment_batch(&data_list, total_queries)
            .expect("Commitment generation failed");

        // 3. DISTRIBUTE: The producer (or anyone) determines the query sets for each validator.
        let f = (n_validators - 1) / 3;
        let h = f + 1;
        let validator_positions = compute_position_assignments(n_validators, &base_positions, h);

        // 4. PROVE: The producer generates a specific, small proof for each validator.
        let validator_proofs: Vec<_> = validator_positions
            .iter()
            .map(|positions| {
                if positions.is_empty() {
                    None
                } else {
                    Some(prover.open(positions))
                }
            })
            .collect();

        // 5. VERIFY: Each validator independently verifies their assigned proof.
        let blowup_factor = options.blowup_factor();

        let max_data_len = encoded_data_element_count::<BaseElement>(
            data_list
                .iter()
                .map(|data| data.len())
                .max()
                .unwrap_or_default(),
        );

        let domain_size = usize::max(
            (max_data_len * blowup_factor).next_power_of_two(),
            constants::MIN_DOMAIN_SIZE,
        );

        let all_evaluations = batch_data_to_evaluations::<BaseElement>(
            &data_list,
            poly_count,
            domain_size,
            blowup_factor,
            options.folding_factor(),
        )
        .unwrap();

        for i in 0..n_validators {
            if let Some(proof) = &validator_proofs[i] {
                let positions = &validator_positions[i];

                let evaluations = get_evaluations_from_positions(
                    &all_evaluations,
                    positions,
                    poly_count,
                    domain_size,
                    options.folding_factor(),
                );

                // A. Validator initializes a verifier from the public commitment.
                let verifier = FridaDasVerifier::<BaseElement, Blake3, Blake3>::from_commitment(
                    &prover_commitment,
                    options.clone(),
                )
                .expect("Verifier initialization failed");

                // B. Validator verifies their specific proof against the global context.
                let verification_result = verifier.verify(proof, &evaluations, positions);

                assert!(
                    verification_result.is_ok(),
                    "Verification failed for validator {} with error: {:?}",
                    i,
                    verification_result.err()
                );
            }
        }
    }
}
