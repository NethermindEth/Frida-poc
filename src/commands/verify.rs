use crate::{
    commands::open::read_and_deserialize_proof,
    frida_error::FridaError,
    frida_prover::Commitment,
    frida_random::{FridaRandom, FridaRandomCoin},
    frida_verifier::das::FridaDasVerifier,
};
use std::fs;
use winter_crypto::hashers::Blake3_256;
use winter_fri::FriOptions;
use winter_math::fields::f128::BaseElement;
use winter_utils::Deserializable;

pub fn run(
    commitment_path: &str,
    positions_path: &str,
    evaluations_path: &str,
    proof_path: &str,
    encoded_element_count: usize,
    fri_options: FriOptions,
) -> Result<(), FridaError> {
    // Read and deserialize
    let commitment =
        Commitment::<Blake3_256<BaseElement>>::read_from_bytes(&fs::read(commitment_path).unwrap())
            .unwrap();
    let (positions, evaluations, proof) =
        read_and_deserialize_proof(positions_path, evaluations_path, proof_path).unwrap();

    // Instantiate the verifier
    let mut public_coin =
        FridaRandom::<Blake3_256<BaseElement>, Blake3_256<BaseElement>, BaseElement>::new(&[123]);

    let verifier = FridaDasVerifier::new(
        commitment,
        &mut public_coin,
        fri_options.clone(),
        encoded_element_count - 1,
    )
    .unwrap();

    // Verify the proof
    verifier.verify(proof, &evaluations, &positions)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        commands::{commit, generate_data, open},
        frida_data::encoded_data_element_count,
        frida_prover::{traits::BaseFriProver, FridaProver},
        frida_prover_channel::FridaProverChannel,
    };
    use std::fs;
    use winter_fri::FriOptions;

    use winter_crypto::hashers::Blake3_256;
    use winter_math::fields::f128::BaseElement;

    type Blake3 = Blake3_256<BaseElement>;
    type FridaChannel =
        FridaProverChannel<BaseElement, Blake3, Blake3, FridaRandom<Blake3, Blake3, BaseElement>>;
    type FridaProverType = FridaProver<BaseElement, BaseElement, FridaChannel, Blake3>;

    #[test]
    fn test_verify() {
        let data_path = "data/data.bin";
        let commitment_path = "data/commitment.bin";
        let positions_path = "data/positions.bin";
        let evaluations_path = "data/evaluations.bin";
        let proof_path = "data/proof.bin";

        // Generate data
        generate_data::run(200, data_path).unwrap();
        let encoded_element_count =
            encoded_data_element_count::<BaseElement>(fs::read(data_path).unwrap().len())
                .next_power_of_two();

        // Initialize prover
        let mut prover = FridaProverType::new(FriOptions::new(8, 2, 7));

        // Commit the data
        let num_queries = 31;
        commit::run(&mut prover, num_queries, data_path, commitment_path).unwrap();

        // Open the commitment
        let (_, _, _) = open::run(
            &mut prover,
            &[1, 2, 3],
            positions_path,
            evaluations_path,
            proof_path,
        )
        .unwrap();

        // Verify the proof
        let result = run(
            commitment_path,
            positions_path,
            evaluations_path,
            proof_path,
            encoded_element_count,
            prover.options().clone(),
        );
        assert!(result.is_ok(), "{:?}", result.err().unwrap());

        // Clean up
        fs::remove_file(data_path).expect("Failed to remove data file");
        fs::remove_file(commitment_path).expect("Failed to remove commitment file");
        fs::remove_file(positions_path).expect("Failed to remove positions file");
        fs::remove_file(evaluations_path).expect("Failed to remove evaluations file");
        fs::remove_file(proof_path).expect("Failed to remove proof file");
    }
}
