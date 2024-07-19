#[cfg(test)]
mod test {
    use crate::frida_prover::proof::FridaProof;
    use crate::frida_prover::{Commitment, FridaProverBuilder};
    use crate::frida_prover_channel::{
        BaseProverChannel, BaseProverChannelTest,
    };
    use crate::frida_random::{FridaRandom, FridaRandomCoin};
    use crate::frida_verifier::das::FridaDasVerifier;
    use crate::frida_verifier::traits::BaseFridaVerifier;
    use crate::utils::{test_build_evaluations, test_build_prover_channel};
    use winter_crypto::hashers::Blake3_256;
    use winter_fri::folding::fold_positions;
    use winter_fri::{FriOptions, ProverChannel};
    use winter_math::fields::f128::BaseElement;
    use winter_rand_utils::{rand_value, rand_vector};

    type Blake3 = Blake3_256<BaseElement>;
    type FriRandom = FridaRandom<Blake3, Blake3, BaseElement>;
    type FriProverBuilder = FridaProverBuilder<BaseElement, Blake3>;

    #[test]
    fn test_drawn_alpha() {
        let trace_length_e = 12;
        let lde_blowup_e = 3;
        let folding_factor_e = 1;
        let max_remainder_degree = 7;

        let trace_length = 1 << trace_length_e;
        let lde_blowup = 1 << lde_blowup_e;
        let folding_factor = 1 << folding_factor_e;
        let domain_size = trace_length * lde_blowup;

        let options = FriOptions::new(lde_blowup, folding_factor, max_remainder_degree);
        let mut channel = test_build_prover_channel(trace_length, &options);
        let evaluations: Vec<_> = test_build_evaluations(trace_length, lde_blowup);

        // instantiate the prover and generate the proof
        let prover_builder = FriProverBuilder::new(options.clone());
        let prover = prover_builder.test_build_layers(&mut channel, evaluations);
        let prover_drawn_alpha = channel.drawn_alphas();
        let roots = channel.layer_commitments().to_vec();

        let positions = channel.draw_query_positions();
        let proof = prover.open(&positions);

        let mut coin = FriRandom::new(&[123]);
        let verifier = FridaDasVerifier::new(
            Commitment {
                proof,
                roots,
                domain_size,
                num_queries: 32,
                poly_count: 1,
            },
            &mut coin,
            options.clone(),
        )
        .unwrap();

        let layer_alpha = verifier.layer_alphas();
        assert_eq!(prover_drawn_alpha, layer_alpha[..layer_alpha.len() - 1]);

        let poly_count = 10;
        let mut data = vec![];
        for _ in 0..poly_count {
            data.push(rand_vector::<u8>(usize::min(
                rand_value::<u64>() as usize,
                128,
            )));
        }
        let (commitment, prover) = prover_builder.commit_batch(&data, 32).unwrap();
        let mut channel = test_build_prover_channel(commitment.domain_size, &options);
        for layer_root in commitment.roots.iter() {
            channel.commit_fri_layer(*layer_root);
            channel.draw_fri_alpha();
        }
        let prover_drawn_alpha = channel.drawn_alphas();
        let roots = channel.layer_commitments().to_vec();
        let positions = channel.draw_query_positions();
        let proof = prover.open(&positions);

        let mut coin = FriRandom::new(&[123]);
        let verifier = FridaDasVerifier::new(
            Commitment {
                proof,
                roots,
                domain_size: commitment.domain_size,
                num_queries: 32,
                poly_count: 10,
            },
            &mut coin,
            options.clone(),
        )
        .unwrap();
        let layer_alpha = verifier.layer_alphas();
        assert_eq!(
            prover_drawn_alpha[..prover_drawn_alpha.len() - 1],
            layer_alpha[..layer_alpha.len() - 1]
        )
    }

    #[test]
    fn test_drawn_alpha_batch() {
        let lde_blowup_e = 3;
        let folding_factor_e = 1;
        let max_remainder_degree = 7;
        let lde_blowup = 1 << lde_blowup_e;
        let folding_factor = 1 << folding_factor_e;
        let options = FriOptions::new(lde_blowup, folding_factor, max_remainder_degree);

        // instantiate the prover and generate the proof
        let prover_builder = FriProverBuilder::new(options.clone());
        let poly_count = 10;
        let mut data = vec![];
        for _ in 0..poly_count {
            data.push(rand_vector::<u8>(usize::min(
                rand_value::<u64>() as usize,
                128,
            )));
        }
        let (commitment, prover) = prover_builder.commit_batch(&data, 32).unwrap();
        let mut channel = test_build_prover_channel(commitment.domain_size, &options);
        for layer_root in commitment.roots.iter() {
            channel.commit_fri_layer(*layer_root);
            channel.draw_fri_alpha();
        }
        let prover_drawn_alpha = channel.drawn_alphas();
        let roots = channel.layer_commitments().to_vec();
        let positions = channel.draw_query_positions();
        let proof = prover.open(&positions);

        let mut coin = FriRandom::new(&[123]);
        let verifier = FridaDasVerifier::new(
            Commitment {
                proof,
                roots,
                domain_size: commitment.domain_size,
                num_queries: 32,
                poly_count: 10,
            },
            &mut coin,
            options.clone(),
        )
        .unwrap();
        let layer_alpha = verifier.layer_alphas();
        assert_eq!(
            prover_drawn_alpha[..prover_drawn_alpha.len() - 1],
            layer_alpha[..layer_alpha.len() - 1]
        )
    }

    fn verify_batch(
        data_evaluations: &[BaseElement],
        proof: FridaProof,
        commitment: Commitment<Blake3>,
        options: FriOptions,
        domain_size: usize,
    ) {
        let poly_count = commitment.poly_count;
        let folding_factor = options.folding_factor();

        let mut coin = FriRandom::new(&[123]);

        let verifier = FridaDasVerifier::new(commitment, &mut coin, options.clone()).unwrap();

        let mut query_positions = coin.draw_query_positions(4, domain_size).unwrap();
        query_positions.dedup();
        query_positions = fold_positions(&query_positions, domain_size, folding_factor);

        let mut evaluations = vec![];
        for position in query_positions.iter() {
            let bucket = position % (domain_size / folding_factor);
            let start_index = (position / (domain_size / folding_factor)) * poly_count;
            data_evaluations[bucket * poly_count * folding_factor + start_index
                ..bucket * poly_count * folding_factor + start_index + poly_count]
                .iter()
                .for_each(|e| {
                    evaluations.push(*e);
                });
        }

        verifier
            .verify(proof, &evaluations, &query_positions)
            .unwrap();
    }

    #[test]
    fn test_verify_batch() {
        let poly_count = 10;
        let mut data = vec![];
        for _ in 0..poly_count {
            data.push(rand_vector::<u8>(usize::min(
                rand_value::<u64>() as usize,
                128,
            )));
        }

        let blowup_factor = 2;
        let folding_factor = 2;
        let options = FriOptions::new(blowup_factor, folding_factor, 0);
        let prover_builder = FriProverBuilder::new(options.clone());

        let (commitment, prover) = prover_builder.commit_batch(&data, 4).unwrap();
        let proof = commitment.proof.clone();
        let domain_size = commitment.domain_size;

        verify_batch(
            prover.get_first_layer_evalutaions(),
            proof,
            commitment,
            options,
            domain_size,
        );
    }

    #[test]
    fn test_batching_only_batch_layer() {
        let poly_count = 10;
        let mut data = vec![];
        for _ in 0..poly_count {
            data.push(rand_vector::<u8>(1));
        }

        let blowup_factor = 2;
        let folding_factor = 4;
        let options = FriOptions::new(blowup_factor, folding_factor, 0);
        let prover_builder = FriProverBuilder::new(options.clone());

        let (commitment, prover) = prover_builder.commit_batch(&data, 4).unwrap();
        let proof = commitment.proof.clone();
        let domain_size = commitment.domain_size;

        verify_batch(
            prover.get_first_layer_evalutaions(),
            proof,
            commitment,
            options,
            domain_size,
        );
    }
}
