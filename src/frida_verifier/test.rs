#[cfg(test)]
mod test {
    use crate::frida_prover_channel::{BaseProverChannel, BaseProverChannelTest};
    use crate::frida_random::{FridaRandom, FridaRandomCoin};
    use crate::frida_verifier::FridaVerifier;
    use crate::utils::{build_evaluations, build_prover_channel};
    use winter_crypto::hashers::Blake3_256;
    use winter_fri::{DefaultVerifierChannel, FriOptions, FriProver};
    use winter_math::fields::f128::BaseElement;

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
        let max_degree = trace_length - 1;

        let options = FriOptions::new(lde_blowup, folding_factor, max_remainder_degree);
        let mut channel = build_prover_channel(trace_length, &options);
        let evaluations: Vec<_> = build_evaluations(trace_length, lde_blowup);

        // instantiate the prover and generate the proof
        let mut prover = FriProver::new(options.clone());
        prover.build_layers(&mut channel, evaluations.clone());
        let prover_drawn_alpha = channel.drawn_alphas();
        let commitments = channel.layer_commitments().to_vec();

        let positions = channel.draw_query_positions();
        let proof = prover.build_proof(&positions);

        let mut channel = DefaultVerifierChannel::<BaseElement, Blake3>::new(
            proof,
            commitments,
            domain_size,
            options.folding_factor(),
        )
        .unwrap();
        let mut coin = FridaRandom::<Blake3, Blake3, BaseElement>::new(&[123]);

        let verifier =
            FridaVerifier::new(&mut channel, &mut coin, options.clone(), max_degree).unwrap();

        let layer_alpha = verifier.layer_alphas();

        assert_eq!(prover_drawn_alpha, layer_alpha[..layer_alpha.len() - 1])
    }
}
