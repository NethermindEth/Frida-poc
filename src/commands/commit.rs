use std::fs;
use std::fs::File;
use std::io::BufWriter;
use std::io::Write;

use crate::{
    frida_data::encoded_data_element_count,
    frida_prover::{traits::BaseFriProver, Commitment, FridaProver},
    frida_prover_channel::FridaProverChannel,
    frida_random::FridaRandom,
};
use winter_crypto::hashers::Blake3_256;
use winter_fri::FriOptions;
use winter_math::fields::f128::BaseElement;
use winter_utils::Serializable;

type Blake3 = Blake3_256<BaseElement>;
type FridaChannel =
    FridaProverChannel<BaseElement, Blake3, Blake3, FridaRandom<Blake3, Blake3, BaseElement>>;
type FridaProverType = FridaProver<BaseElement, BaseElement, FridaChannel, Blake3>;

/// Runs the commitment process, saving the commitment to a file.
pub fn run(
    data_path: &str,
    commitment_path: &str,
    num_queries: usize,
    options: FriOptions,
) -> Result<(usize, Commitment<Blake3>), Box<dyn std::error::Error>> {
    // Create commitment from the data file
    let (encoded_element_count, commitment) =
        create_commitment_from_file(data_path, num_queries, options)?;

    // Write the commitment to the specified file
    write_commitment_to_file(encoded_element_count, &commitment, commitment_path)?;

    // Print success message with detail
    println!("Commitment created and saved to {}", commitment_path);

    Ok((encoded_element_count, commitment))
}

/// Creates a commitment from the data file.
fn create_commitment_from_file(
    data_path: &str,
    num_queries: usize,
    options: FriOptions,
) -> Result<(usize, Commitment<Blake3>), Box<dyn std::error::Error>> {
    // Read data from the file
    let data = fs::read(data_path)?;
    let mut prover: FridaProverType = FridaProver::new(options.clone());

    // Calculate the encoded element count
    let encoded_element_count =
        encoded_data_element_count::<BaseElement>(data.len()).next_power_of_two();

    // Generate the commitment
    let (commitment, _) = prover.commit(data, num_queries).unwrap();

    Ok((encoded_element_count, commitment))
}

/// Writes the commitment and encoded element count to a file.
fn write_commitment_to_file(
    encoded_element_count: usize,
    commitment: &Commitment<Blake3>,
    file_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Serialize the commitment and encoded element count
    let commitment_bytes = commitment.to_bytes();
    let encoded_element_count_bytes = encoded_element_count.to_le_bytes();

    // Write to the file
    let mut file = File::create(file_path)?;
    let mut writer = BufWriter::new(&mut file);
    writer.write_all(&encoded_element_count_bytes)?;
    writer.write_all(&commitment_bytes)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{commands::generate_data, utils::load_fri_options};
    use std::io::BufReader;
    use std::io::Read;
    use winter_utils::Deserializable;

    #[test]
    fn test_commit() {
        let data_path = "data/data.bin";
        let commitment_path = "data/commitment.bin";

        if !std::path::Path::new(data_path).exists() {
            generate_data::run(200, data_path).unwrap();
        }

        let options = load_fri_options(None);

        // Run the commitment process
        let (encoded_element_count, commitment) =
            run(data_path, commitment_path, 31, options).unwrap();

        // Read the commitment from the file
        let (encoded_element_count_file, commitment_file) =
            read_commitment_from_file(commitment_path).unwrap();

        // Verify the encoded element count
        assert_eq!(
            encoded_element_count, encoded_element_count_file,
            "Encoded element count does not match."
        );

        // Verify the commitment
        assert_eq!(commitment, commitment_file, "Commitment does not match.");

        // Cleanup
        fs::remove_file(data_path).unwrap();
        fs::remove_file(commitment_path).unwrap();
    }

    /// Reads the commitment and encoded element count from a file.
    fn read_commitment_from_file(
        file_path: &str,
    ) -> Result<(usize, Commitment<Blake3>), Box<dyn std::error::Error>> {
        // Open the file and create a buffered reader
        let file = File::open(file_path)?;
        let mut reader = BufReader::new(file);

        // Read the encoded element count
        let mut encoded_element_count_bytes = [0u8; 8];
        reader.read_exact(&mut encoded_element_count_bytes)?;
        let encoded_element_count = usize::from_le_bytes(encoded_element_count_bytes);

        // Read the commitment bytes
        let mut commitment_bytes = Vec::new();
        reader.read_to_end(&mut commitment_bytes)?;

        // Deserialize the commitment
        let commitment = Commitment::<Blake3>::read_from_bytes(&commitment_bytes).unwrap();

        Ok((encoded_element_count, commitment))
    }
}
