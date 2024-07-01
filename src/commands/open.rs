use std::fs;
use std::fs::File;
use std::io::BufWriter;
use std::io::Write;

use crate::{
    frida_data::{build_evaluations_from_data, encoded_data_element_count},
    frida_prover::{proof::FridaProof, traits::BaseFriProver, FridaProver},
    frida_prover_channel::FridaProverChannel,
    frida_random::FridaRandom,
};
use winter_crypto::hashers::Blake3_256;
use winter_math::fields::f128::BaseElement;
use winter_utils::Serializable;

type Blake3 = Blake3_256<BaseElement>;
type FridaChannel =
    FridaProverChannel<BaseElement, Blake3, Blake3, FridaRandom<Blake3, Blake3, BaseElement>>;
type FridaProverType = FridaProver<BaseElement, BaseElement, FridaChannel, Blake3>;

pub fn run(
    prover: &mut FridaProverType,
    proof_path: &str,
    positions: &[usize],
) -> Result<(FridaProof, Vec<BaseElement>), Box<dyn std::error::Error>> {
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

    // TODO: Save to the file
    let proof_bytes = proof.to_bytes();
    let queried_evaluations_bytes = queried_evaluations.to_bytes();

    // Write to the file
    let mut file = File::create(proof_path)?;
    let mut writer = BufWriter::new(&mut file);
    writer.write_all(&proof_bytes)?;
    writer.write_all(&queried_evaluations_bytes)?;

    Ok((proof, queried_evaluations))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::generate_data;
    use std::fs;
    use std::io::Read;
    use winter_fri::FriOptions;

    #[test]
    fn test_open() {
        // Paths
        let data_path = "data/data.bin";
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
        let result = run(&mut prover, proof_path, &positions);
        assert!(result.is_ok(), "Failed to generate proof and evaluations.");

        let (proof, queried_evaluations) = result.unwrap();

        // Verify the contents are written to file
        let mut file_contents = Vec::new();
        let mut file = fs::File::open(proof_path).unwrap();
        file.read_to_end(&mut file_contents).unwrap();

        // Serialize proof and queried evaluations
        let mut proof_bytes = proof.to_bytes();
        let queried_evaluations_bytes = queried_evaluations.to_bytes();
        proof_bytes.extend(queried_evaluations_bytes);

        assert_eq!(
            file_contents, proof_bytes,
            "File contents do not match expected serialized output."
        );

        // Optionally, validate proof with external verification logic here, if available

        // Cleanup
        fs::remove_file(data_path).unwrap();
        fs::remove_file(proof_path).unwrap();
    }
}
