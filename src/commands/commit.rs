use crate::{
    frida_prover::{Commitment, FridaProver},
    frida_prover_channel::FridaProverChannel,
    frida_random::FridaRandom,
    utils::{read_file_to_vec, write_to_file},
};
use winter_crypto::hashers::Blake3_256;
use winter_math::fields::f128::BaseElement;
use winter_utils::{Deserializable, Serializable};

type Blake3 = Blake3_256<BaseElement>;
type FridaChannel =
    FridaProverChannel<BaseElement, Blake3, Blake3, FridaRandom<Blake3, Blake3, BaseElement>>;
type FridaProverType = FridaProver<BaseElement, BaseElement, FridaChannel, Blake3>;

/// Runs the commitment process, saving the commitment to a file.
pub fn run(
    prover: &mut FridaProverType,
    num_queries: usize,
    data_path: &str,
    commitment_path: &str,
) -> Result<Commitment<Blake3>, Box<dyn std::error::Error>> {
    // Read data from file
    let data = read_file_to_vec(data_path)?;

    // Create commitment from data
    let (commitment, _) =
        prover
            .commit(data, num_queries)
            .map_err(|e| -> Box<dyn std::error::Error> {
                format!("Prover commit error: {}", e).into()
            })?;

    // Write commitment to file
    let commitment_bytes = commitment.to_bytes();
    write_to_file(commitment_path, &commitment_bytes)?;

    println!("Commitment created and saved to {}", commitment_path);
    Ok(commitment)
}

/// Reads the commitment from a file.
pub fn read_commitment_from_file(
    file_path: &str,
) -> Result<Commitment<Blake3>, Box<dyn std::error::Error>> {
    let commitment_bytes = read_file_to_vec(file_path)?;
    let commitment = Commitment::<Blake3>::read_from_bytes(&commitment_bytes).map_err(
        |e| -> Box<dyn std::error::Error> { format!("Deserialization error: {}", e).into() },
    )?;
    Ok(commitment)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::generate_data;
    use crate::frida_prover::traits::BaseFriProver;
    use std::fs;
    use winter_fri::FriOptions;

    #[test]
    fn test_commit() {
        let data_path = "data/data.bin";
        let commitment_path = "data/commitment.bin";

        if !std::path::Path::new(data_path).exists() {
            generate_data::run(200, data_path).unwrap();
        }

        let mut prover = FridaProverType::new(FriOptions::new(8, 2, 7));

        // Run the commitment process
        let commitment = run(&mut prover, 31, data_path, commitment_path).unwrap();

        // Read the commitment from the file
        let commitment_file = read_commitment_from_file(commitment_path).unwrap();

        // Verify the commitment
        assert_eq!(commitment, commitment_file, "Commitment does not match.");

        // Cleanup
        fs::remove_file(data_path).unwrap();
        fs::remove_file(commitment_path).unwrap();
    }
}
