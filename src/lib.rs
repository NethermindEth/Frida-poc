pub mod frida_const;
pub mod frida_data;
pub mod frida_error;
pub mod frida_prover;
pub mod frida_prover_channel;
pub mod frida_random;
pub mod frida_verifier;
pub mod utils;

use frida_prover_channel::{BaseProverChannel, FridaProverChannel};
use frida_random::FridaRandom;
use winter_crypto::hashers::Blake3_256;
use winter_fri::{FriOptions, FriProver};
use winter_math::fft::{self};
use winter_math::fields::f128::BaseElement;
use winter_math::FieldElement;
use winter_rand_utils::rand_vector;

fn build_evaluations(domain_size: usize) -> Vec<BaseElement> {
    let mut p: Vec<BaseElement> = rand_vector(domain_size / BLOWUP_FACTOR);
    p.resize(domain_size, BaseElement::ZERO);
    let twiddles = fft::get_twiddles::<BaseElement>(domain_size);
    fft::evaluate_poly(&mut p, &twiddles);
    p
}

static BLOWUP_FACTOR: usize = 8;
pub fn fri() {
    let options: FriOptions = FriOptions::new(BLOWUP_FACTOR, 4, 255);
    let domain_size = 65536;
    let evaluations = build_evaluations(domain_size);

    let mut prover = FriProver::new(options.clone());
    let mut channel = FridaProverChannel::<
        BaseElement,
        Blake3_256<BaseElement>,
        Blake3_256<BaseElement>,
        FridaRandom<Blake3_256<BaseElement>, Blake3_256<BaseElement>, BaseElement>,
    >::new(domain_size, 32);
    prover.build_layers(&mut channel, evaluations);
}

#[cfg(test)]
mod tests {
    use winter_crypto::{hashers::Blake3_256, Hasher};
    use winter_fri::{DefaultVerifierChannel, FriOptions, FriProof, FriProver, VerifierError};
    use winter_math::fields::f128::BaseElement;
    use winter_utils::{Deserializable, Serializable, SliceReader};

    use crate::{
        fri,
        frida_prover_channel::{BaseProverChannel, BaseProverChannelTest},
        frida_random::{FridaRandom, FridaRandomCoin},
        frida_verifier::FridaVerifier,
        utils::{build_evaluations, build_prover_channel},
    };

    #[test]
    fn test_fri() {
        fri()
    }

    #[test]
    fn test_verify() {
        type Blake3 = Blake3_256<BaseElement>;
        pub fn verify_proof(
            proof: FriProof,
            prover_drawn_alpha: Vec<BaseElement>,
            commitments: Vec<<Blake3 as Hasher>::Digest>,
            evaluations: &[BaseElement],
            max_degree: usize,
            domain_size: usize,
            positions: &[usize],
            options: &FriOptions,
        ) -> Result<(), VerifierError> {
            // test proof serialization / deserialization
            let mut proof_bytes = Vec::new();
            proof.write_into(&mut proof_bytes);

            let mut reader = SliceReader::new(&proof_bytes);
            let proof = FriProof::read_from(&mut reader).unwrap();

            // verify the proof
            let mut channel = DefaultVerifierChannel::<BaseElement, Blake3>::new(
                proof,
                commitments,
                domain_size,
                options.folding_factor(),
            )
            .unwrap();
            // let mut coin = DefaultRandomCoin::<Blake3>::new(&[]);
            let mut coin = FridaRandom::<Blake3, Blake3, BaseElement>::new(&[123]);

            let verifier =
                FridaVerifier::new(&mut channel, &mut coin, options.clone(), max_degree)?;

            let layer_alpha = verifier.layer_alphas();

            println!("prover_drawn_alpha: {:?}", prover_drawn_alpha);
            println!("layer_alpha: {:?}", layer_alpha);

            let queried_evaluations = positions
                .iter()
                .map(|&p| evaluations[p])
                .collect::<Vec<_>>();
            verifier.verify(&mut channel, &queried_evaluations, positions)
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
            let mut channel = build_prover_channel(trace_length, &options);
            let evaluations = build_evaluations(trace_length, lde_blowup);

            // instantiate the prover and generate the proof
            let mut prover = FriProver::new(options.clone());
            prover.build_layers(&mut channel, evaluations.clone());
            let prover_drawn_alpha = channel.drawn_alphas();

            let positions = channel.draw_query_positions();
            let proof = prover.build_proof(&positions);

            // make sure the proof can be verified
            let commitments = channel.layer_commitments().to_vec();
            let max_degree = trace_length - 1;
            let result = verify_proof(
                proof.clone(),
                prover_drawn_alpha.clone(),
                commitments.clone(),
                &evaluations,
                max_degree,
                trace_length * lde_blowup,
                &positions,
                &options,
            );
            assert!(result.is_ok(), "{:}", result.err().unwrap());

            // make sure proof fails for invalid degree
            let result = verify_proof(
                proof,
                prover_drawn_alpha,
                commitments,
                &evaluations,
                max_degree - 8,
                trace_length * lde_blowup,
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
