#[cfg(test)]
mod test {
    use crate::frida_prover::{Commitment, FridaProverBuilder};
    use crate::frida_prover_channel::{
        BaseProverChannel, BaseProverChannelTest, FridaProverChannel,
    };
    use crate::frida_random::{FridaRandom, FridaRandomCoin};
    use crate::frida_verifier::das::FridaDasVerifier;
    use crate::frida_verifier::traits::BaseFridaVerifier;
    use crate::utils::{test_build_evaluations, test_build_prover_channel};
    use winter_crypto::hashers::Blake3_256;
    use winter_fri::folding::fold_positions;
    use winter_fri::FriOptions;
    use winter_math::fields::f128::BaseElement;
    use winter_rand_utils::{rand_value, rand_vector};

    type Blake3 = Blake3_256<BaseElement>;

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
        let prover_builder = FridaProverBuilder::new(options.clone());
        let prover = prover_builder.test_build_layers(&mut channel, &evaluations);
        let prover_drawn_alpha = channel.drawn_alphas();
        let roots = channel.layer_commitments().to_vec();

        let positions = channel.draw_query_positions();
        let proof = prover.open(&positions);

        let mut coin = FridaRandom::<Blake3, Blake3, BaseElement>::new(&[123]);
        let verifier = FridaDasVerifier::new(
            Commitment {
                proof,
                roots,
                domain_size,
                num_queries: 32,
                batch_size: 0,
            },
            &mut coin,
            options.clone(),
        )
        .unwrap();

        let layer_alpha = verifier.layer_alphas();
        assert_eq!(prover_drawn_alpha, layer_alpha[..layer_alpha.len() - 1])
    }

    #[test]
    fn test_verify_batch() {
        let batch_size = 10;
        let mut data = vec![];
        for _ in 0..batch_size {
            data.push(rand_vector::<u8>(usize::min(
                rand_value::<u64>() as usize,
                128,
            )));
        }

        let blowup_factor = 2;
        let folding_factor = 2;
        let options = FriOptions::new(blowup_factor, folding_factor, 0);
        let prover_builder: FridaProverBuilder<
            BaseElement,
            BaseElement,
            Blake3_256<BaseElement>,
            FridaProverChannel<
                BaseElement,
                Blake3_256<BaseElement>,
                Blake3_256<BaseElement>,
                FridaRandom<Blake3_256<BaseElement>, Blake3_256<BaseElement>, BaseElement>,
            >,
        > = FridaProverBuilder::new(options.clone());

        let (prover, channel) = prover_builder.build_batched_prover(&data, 4).unwrap();
        let commitment = prover.commit(channel).unwrap();
        let proof = commitment.proof.clone();

        let mut coin =
            FridaRandom::<Blake3_256<BaseElement>, Blake3_256<BaseElement>, BaseElement>::new(&[
                123,
            ]);

        let verifier = FridaDasVerifier::new(
            commitment,
            &mut coin,
            options.clone(),
        )
        .unwrap();

        let mut query_positions = coin.draw_query_positions(4, prover.domain_size()).unwrap();
        query_positions.dedup();
        query_positions = fold_positions(&query_positions, prover.domain_size(), folding_factor);

        let mut evaluations = vec![];
        for position in query_positions.iter() {
            let bucket = position % (prover.domain_size() / folding_factor);
            let start_index = (position / (prover.domain_size() / folding_factor)) * batch_size;
            prover.batch_layer.as_ref().unwrap().evaluations[bucket]
                [start_index..start_index + batch_size]
                .iter()
                .for_each(|e| {
                    evaluations.push(*e);
                });
        }

        verifier
            .verify(proof, &evaluations, &query_positions)
            .unwrap();
    }
}
