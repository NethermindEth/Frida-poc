use crate::{
    core::data::{build_evaluations_from_data, encoded_data_element_count},
    prover::{builder::FridaProverBuilder, proof::FridaProof},
    utils::test_utils::{read_file_to_vec, write_to_file},
};
use std::path::Path;
use winter_crypto::hashers::Blake3_256;
use winter_math::fields::f128::BaseElement;
use winter_utils::{Deserializable, Serializable};

type Blake3 = Blake3_256<BaseElement>;
type FridaProverBuilderType = FridaProverBuilder<BaseElement, Blake3>;

type OpenResult = Result<(Vec<usize>, Vec<BaseElement>, FridaProof), Box<dyn std::error::Error>>;

pub fn run(
    prover_builder: &mut FridaProverBuilderType,
    positions: &[usize],
    positions_path: &Path,
    evaluations_path: &Path,
    data_path: &Path,
    proof_path: &Path,
) -> OpenResult {
    // Read data from file
    let data = read_file_to_vec(data_path)?;

    let encoded_element_count =
        encoded_data_element_count::<BaseElement>(data.len()).next_power_of_two();

    // Create proof
    let options = prover_builder.options.clone();
    let (_, prover) = prover_builder.commit_and_prove(&data, 1).unwrap();
    let proof = prover.open(positions);

    let domain_size = (encoded_element_count - 1).next_power_of_two() * options.blowup_factor();
    let evaluations = build_evaluations_from_data(&data, domain_size, options.blowup_factor())
        .map_err(|e| -> Box<dyn std::error::Error> {
            format!("Failed to build evaluations: {e}").into()
        })?;

    let queried_evaluations: Vec<BaseElement> = positions.iter().map(|&p| evaluations[p]).collect();

    // Write positions, evaluations, and proof to files
    write_to_file(positions_path, &positions.to_bytes())?;
    write_to_file(evaluations_path, &queried_evaluations.to_bytes())?;
    write_to_file(proof_path, &proof.to_bytes())?;

    Ok((positions.to_vec(), queried_evaluations, proof))
}

pub fn read_and_deserialize_proof(
    positions_path: &Path,
    evaluations_path: &Path,
    proof_path: &Path,
) -> OpenResult {
    // Read and deserialize positions
    let positions_bytes = read_file_to_vec(positions_path)?;
    let positions = Vec::<usize>::read_from_bytes(&positions_bytes).map_err(
        |e| -> Box<dyn std::error::Error> { format!("Deserialization error: {e}").into() },
    )?;

    // Read and deserialize evaluations
    let queried_evaluations_bytes = read_file_to_vec(evaluations_path)?;
    let queried_evaluations = Vec::<BaseElement>::read_from_bytes(&queried_evaluations_bytes)
        .map_err(|e| -> Box<dyn std::error::Error> {
            format!("Deserialization error: {e}").into()
        })?;

    // Read and deserialize proof
    let proof_bytes = read_file_to_vec(proof_path)?;
    let proof =
        FridaProof::read_from_bytes(&proof_bytes).map_err(|e| -> Box<dyn std::error::Error> {
            format!("Deserialization error: {e}").into()
        })?;

    Ok((positions, queried_evaluations, proof))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{commands::generate_data, utils::test_utils::CleanupFiles};
    use winter_fri::FriOptions;

    #[test]
    fn test_open() {
        let data_path = Path::new("data/data_open.bin");
        let positions_path = Path::new("data/positions_open.bin");
        let evaluations_path = Path::new("data/evaluations_open.bin");
        let proof_path = Path::new("data/proof_open.bin");

        let _cleanup = CleanupFiles::new(vec![
            data_path,
            positions_path,
            evaluations_path,
            proof_path,
        ]);

        if !std::path::Path::new(data_path).exists() {
            generate_data::run(200, data_path).unwrap();
        }

        let mut prover_builder = FridaProverBuilderType::new(FriOptions::new(8, 2, 7));
        let positions = vec![0, 5, 10];

        let result = run(
            &mut prover_builder,
            &positions,
            positions_path,
            evaluations_path,
            data_path,
            proof_path,
        );
        assert!(result.is_ok(), "Failed to generate proof and evaluations.");

        let (positions, queried_evaluations, proof) = result.unwrap();

        let deserialized_result =
            read_and_deserialize_proof(positions_path, evaluations_path, proof_path);
        assert!(
            deserialized_result.is_ok(),
            "Failed to deserialize proof and evaluations."
        );

        let (deserialized_positions, deserialized_evaluations, deserialized_proof) =
            deserialized_result.unwrap();

        assert_eq!(positions, deserialized_positions, "Positions do not match.");
        assert_eq!(
            queried_evaluations, deserialized_evaluations,
            "Queried evaluations do not match."
        );
        assert_eq!(
            proof.to_bytes(),
            deserialized_proof.to_bytes(),
            "Proof does not match."
        );
    }
}
