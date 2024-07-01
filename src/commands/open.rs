use crate::{
    frida_data::{build_evaluations_from_data, encoded_data_element_count},
    frida_prover::{proof::FridaProof, traits::BaseFriProver, FridaProver},
    frida_prover_channel::FridaProverChannel,
    frida_random::FridaRandom,
};
use std::fs;
use std::fs::File;
use std::io::BufWriter;
use std::io::Write;
use std::io::{BufReader, Read};
use winter_crypto::hashers::Blake3_256;
use winter_math::fields::f128::BaseElement;
use winter_utils::Deserializable;
use winter_utils::Serializable;

type Blake3 = Blake3_256<BaseElement>;
type FridaChannel =
    FridaProverChannel<BaseElement, Blake3, Blake3, FridaRandom<Blake3, Blake3, BaseElement>>;
type FridaProverType = FridaProver<BaseElement, BaseElement, FridaChannel, Blake3>;

pub fn run(
    prover: &mut FridaProverType,
    positions: &[usize],
    positions_path: &str,
    evaluations_path: &str,
    proof_path: &str,
) -> Result<(Vec<usize>, Vec<BaseElement>, FridaProof), Box<dyn std::error::Error>> {
    let options = prover.options().clone();
    // Read from files
    let data = fs::read("data/data.bin").unwrap();

    // Calculate encoded element count
    let encoded_element_count =
        encoded_data_element_count::<BaseElement>(data.len()).next_power_of_two();

    let open_position = positions;
    let proof = prover.open(open_position);

    let domain_size = (encoded_element_count - 1).next_power_of_two() * options.blowup_factor();
    let evaluations: Vec<BaseElement> =
        build_evaluations_from_data(&data, domain_size, options.blowup_factor()).unwrap();

    let queried_evaluations = open_position
        .iter()
        .map(|&p| evaluations[p])
        .collect::<Vec<_>>();

    // Save to separate files
    let proof_bytes = proof.to_bytes();
    let queried_evaluations_bytes = queried_evaluations.to_bytes();
    let positions_bytes = positions.to_bytes();

    // Write positions to the file
    let mut file = File::create(positions_path)?;
    let mut writer = BufWriter::new(&mut file);
    writer.write_all(&positions_bytes)?;

    // Write queried evaluations to the file
    let mut file = File::create(evaluations_path)?;
    let mut writer = BufWriter::new(&mut file);
    writer.write_all(&queried_evaluations_bytes)?;

    // Write proof to the file
    let mut file = File::create(proof_path)?;
    let mut writer = BufWriter::new(&mut file);
    writer.write_all(&proof_bytes)?;

    Ok((positions.to_vec(), queried_evaluations, proof))
}

pub fn read_and_deserialize_proof(
    positions_path: &str,
    evaluations_path: &str,
    proof_path: &str,
) -> Result<(Vec<usize>, Vec<BaseElement>, FridaProof), Box<dyn std::error::Error>> {
    // Read positions
    let mut file = File::open(positions_path)?;
    let mut reader = BufReader::new(&mut file);
    let mut positions_bytes = Vec::new();
    reader.read_to_end(&mut positions_bytes)?;
    let positions = Vec::<usize>::read_from_bytes(&positions_bytes).unwrap();

    // Read queried evaluations
    let mut file = File::open(evaluations_path)?;
    let mut reader = BufReader::new(&mut file);
    let mut queried_evaluations_bytes = Vec::new();
    reader.read_to_end(&mut queried_evaluations_bytes)?;
    let queried_evaluations =
        Vec::<BaseElement>::read_from_bytes(&queried_evaluations_bytes).unwrap();

    // Read proof
    let mut file = File::open(proof_path)?;
    let mut reader = BufReader::new(&mut file);
    let mut proof_bytes = Vec::new();
    reader.read_to_end(&mut proof_bytes)?;
    let proof = FridaProof::read_from_bytes(&proof_bytes).unwrap();

    Ok((positions, queried_evaluations, proof))
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::generate_data;
    use std::fs;
    use winter_fri::FriOptions;

    #[test]
    fn test_open() {
        // Paths
        let data_path = "data/data.bin";
        let positions_path = "data/positions.bin";
        let evaluations_path = "data/evaluations.bin";
        let proof_path = "data/proof.bin";

        // Prepare data
        if !std::path::Path::new(data_path).exists() {
            generate_data::run(200, data_path).unwrap();
        }
        let data = fs::read(data_path).unwrap();
        let num_queries = 31;

        // Initialize prover
        let mut prover = FridaProverType::new(FriOptions::new(8, 2, 7));

        // Generate the commitment
        prover.commit(data, num_queries).unwrap();

        // Specify positions to open
        let positions = vec![0, 5, 10];

        // Run the opening process
        let result = run(
            &mut prover,
            &positions,
            positions_path,
            evaluations_path,
            proof_path,
        );
        assert!(result.is_ok(), "Failed to generate proof and evaluations.");

        let (positions, queried_evaluations, proof) = result.unwrap();

        // Verify the contents are written to file
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

        // Cleanup
        fs::remove_file(data_path).unwrap();
        fs::remove_file(proof_path).unwrap();
        fs::remove_file(positions_path).unwrap();
        fs::remove_file(evaluations_path).unwrap();
    }
}
