pub mod frida_const;
pub mod frida_data;
pub mod frida_error;
pub mod frida_prover;
pub mod frida_random;
pub mod frida_verifier;
pub mod utils;

#[cfg(test)]
mod tests {
    use winter_crypto::Hasher;
    use winter_fri::FriOptions;
    use winter_math::fields::f128;
    use winter_rand_utils::rand_array;

    use crate::{
        frida_error::FridaError,
        frida_prover::{proof::FridaProof, Commitment, FridaProverBuilder},
        utils::test_utils::*,
    };

    #[test]
    fn test_verify() {
        pub fn verify_proof(
            opening_proof: FridaProof,
            proof: FridaProof,
            roots: Vec<<Blake3 as Hasher>::Digest>,
            evaluations: &[f128::BaseElement],
            domain_size: usize,
            positions: &[usize],
            options: &FriOptions,
        ) -> Result<(), FridaError> {
            // verify the proof
            let (verifier, _) = TestFridaDasVerifier::new(
                Commitment {
                    roots,
                    proof,
                    domain_size,
                    num_queries: 32,
                    poly_count: 1,
                },
                options.clone(),
            )?;

            let queried_evaluations = positions
                .iter()
                .map(|&p| evaluations[p])
                .collect::<Vec<_>>();
            verifier.verify(&opening_proof, &queried_evaluations, positions)
        }

        fn fri_prove_verify(
            trace_length_e: usize,
            lde_blowup_e: usize,
            folding_factor_e: usize,
            max_remainder_degree: usize,
        ) {
            let trace_length = 1 << trace_length_e;
            let lde_blowup = 1 << lde_blowup_e;
            let folding_factor = 1 << folding_factor_e;

            let options = FriOptions::new(lde_blowup, folding_factor, max_remainder_degree);
            let mut channel = test_build_prover_channel(trace_length, &options);
            let evaluations = test_build_evaluations(trace_length, lde_blowup);

            // instantiate the prover and generate the proof
            let prover_builder = FridaProverBuilder::new(options.clone());
            let prover = prover_builder.test_build_layers(&mut channel, evaluations.clone());

            let positions = channel.draw_query_positions();
            let proof = prover.open(&positions);

            let positions = rand_array::<u64, 5>()
                .iter()
                .map(|v| usize::min(*v as usize, lde_blowup * trace_length - 1))
                .collect::<Vec<_>>();
            let opening_proof = prover.open(&positions);

            // make sure the proof can be verified
            let commitments = channel.commitments.clone();
            let domain_size = trace_length * lde_blowup;
            let result = verify_proof(
                opening_proof.clone(),
                proof.clone(),
                commitments.clone(),
                &evaluations,
                domain_size,
                &positions,
                &options,
            );
            assert!(result.is_ok(), "{:?}", result.err().unwrap());

            // make sure proof fails for invalid domain size
            let result = verify_proof(
                opening_proof,
                proof,
                commitments,
                &evaluations,
                domain_size / 2,
                &positions,
                &options,
            );
            assert!(result.is_err());
        }

        let trace_length_e = 12;
        let lde_blowup_e = 3;
        let folding_factor_e = 1;
        let max_remainder_degree = 7;
        fri_prove_verify(
            trace_length_e,
            lde_blowup_e,
            folding_factor_e,
            max_remainder_degree,
        )
    }
}
