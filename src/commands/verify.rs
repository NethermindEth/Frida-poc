use crate::{
    commands::open::read_and_deserialize_proof, prover::Commitment,
    frida_verifier::das::FridaDasVerifier,
};
use std::{error::Error, fs, path::Path};
use winter_crypto::hashers::Blake3_256;
use winter_fri::FriOptions;
use winter_math::fields::f128::BaseElement;
use winter_utils::Deserializable;

type Blake3 = Blake3_256<BaseElement>;
type FriVerifierType = FridaDasVerifier<BaseElement, Blake3, Blake3>;

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

    let (verifier, _) = FriVerifierType::new(commitment, fri_options.clone())
        .map_err(|e| format!("Verifier initialization error: {}", e))?;

    // Verify the proof
    verifier
        .verify(&proof, &evaluations, &positions)
        .map_err(|e| format!("Verification error: {}", e))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        commands::{commit, generate_data, open},
        prover::builder::FridaProverBuilder,
        utils::test_utils::CleanupFiles,
    };
    use winter_crypto::hashers::Blake3_256;
    use winter_fri::FriOptions;
    use winter_math::fields::f128::BaseElement;

    type Blake3 = Blake3_256<BaseElement>;
    type FridaProverBuilderType = FridaProverBuilder<BaseElement, Blake3>;

    #[test]
    fn test_verify() {
        let data_path = Path::new("data/data_verify.bin");
        let commitment_path = Path::new("data/commitment_verify.bin");
        let positions_path = Path::new("data/positions_verify.bin");
        let evaluations_path = Path::new("data/evaluations_verify.bin");
        let proof_path = Path::new("data/proof_verify.bin");

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
        let mut prover_builder = FridaProverBuilderType::new(FriOptions::new(8, 2, 7));
        let num_queries = 31;
        commit::run(&mut prover_builder, num_queries, data_path, commitment_path).unwrap();

        // Open the commitment
        open::run(
            &mut prover_builder,
            &[1, 2, 3],
            positions_path,
            evaluations_path,
            data_path,
            proof_path,
        )
        .unwrap();

        // Verify the proof
        let result = run(
            commitment_path,
            positions_path,
            evaluations_path,
            proof_path,
            prover_builder.options.clone(),
        );
        assert!(result.is_ok(), "{:?}", result.err().unwrap());
    }
}
