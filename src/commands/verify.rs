use crate::{
    commands::open::read_and_deserialize_proof,
    frida_prover::Commitment,
    frida_random::{FridaRandom, FridaRandomCoin},
    frida_verifier::{das::FridaDasVerifier, traits::BaseFridaVerifier},
};
use std::{error::Error, fs, path::Path};
use winter_crypto::hashers::Blake3_256;
use winter_fri::FriOptions;
use winter_math::fields::f128::BaseElement;
use winter_utils::Deserializable;

pub fn run(
    commitment_path: &Path,
    positions_path: &Path,
    evaluations_path: &Path,
    proof_path: &Path,
    fri_options: FriOptions,
) -> Result<(), Box<dyn Error>> {
    // Read and deserialize
    let commitment_bytes = fs::read(commitment_path)?;
    let commitment = Commitment::<Blake3_256<BaseElement>>::read_from_bytes(&commitment_bytes)
        .map_err(|e| format!("Deserialization error: {}", e))?;

    let (positions, evaluations, proof) =
        read_and_deserialize_proof(positions_path, evaluations_path, proof_path)?;

    // Instantiate the verifier
    let mut public_coin =
        FridaRandom::<Blake3_256<BaseElement>, Blake3_256<BaseElement>, BaseElement>::new(&[123]);

    let verifier = FridaDasVerifier::new(commitment, &mut public_coin, fri_options.clone())
        .map_err(|e| format!("Verifier initialization error: {}", e))?;

    // Verify the proof
    verifier
        .verify(proof, &evaluations, &positions)
        .map_err(|e| format!("Verification error: {}", e))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        commands::{commit, generate_data, open},
        frida_prover::{traits::BaseFriProver, FridaProver},
        frida_prover_channel::FridaProverChannel,
        utils::CleanupFiles,
    };
    use winter_crypto::hashers::Blake3_256;
    use winter_fri::FriOptions;
    use winter_math::fields::f128::BaseElement;

    type Blake3 = Blake3_256<BaseElement>;
    type FridaChannel =
        FridaProverChannel<BaseElement, Blake3, Blake3, FridaRandom<Blake3, Blake3, BaseElement>>;
    type FridaProverType = FridaProver<BaseElement, BaseElement, FridaChannel, Blake3>;

    #[test]
    fn test_verify() {
        let data_path = Path::new("data/data.bin");
        let commitment_path = Path::new("data/commitment.bin");
        let positions_path = Path::new("data/positions.bin");
        let evaluations_path = Path::new("data/evaluations.bin");
        let proof_path = Path::new("data/proof.bin");

        let _cleanup = CleanupFiles::new(vec![
            data_path,
            commitment_path,
            positions_path,
            evaluations_path,
            proof_path,
        ]);

        // Generate data
        generate_data::run(200, data_path).unwrap();

        // Initialize prover
        let mut prover = FridaProverType::new(FriOptions::new(8, 2, 7));

        // Commit the data
        let num_queries = 31;
        commit::run(&mut prover, num_queries, data_path, commitment_path).unwrap();

        // Open the commitment
        open::run(
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
            prover.options().clone(),
        );
        assert!(result.is_ok(), "{:?}", result.err().unwrap());
    }
}
