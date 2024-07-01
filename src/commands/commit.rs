use crate::{
    frida_prover::{Commitment, FridaProver},
    frida_prover_channel::FridaProverChannel,
    frida_random::FridaRandom,
};
use std::fs;
use std::fs::File;
use std::io::BufReader;
use std::io::BufWriter;
use std::io::Read;
use std::io::Write;
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
    // Create commitment from the data file
    let commitment = create_commitment_from_file(prover, num_queries, data_path)?;

    // Write the commitment to the specified file
    write_commitment_to_file(&commitment, commitment_path)?;

    // Print success message with detail
    println!("Commitment created and saved to {}", commitment_path);

    Ok(commitment)
}

/// Creates a commitment from the data file.
fn create_commitment_from_file(
    prover: &mut FridaProverType,
    num_queries: usize,
    data_path: &str,
) -> Result<Commitment<Blake3>, Box<dyn std::error::Error>> {
    // Read data from the file
    let data = fs::read(data_path)?;

    // Generate the commitment
    let (commitment, _) = prover.commit(data, num_queries).unwrap();

    Ok(commitment)
}

/// Writes the commitment to a file.
fn write_commitment_to_file(
    commitment: &Commitment<Blake3>,
    file_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Serialize the commitment
    let commitment_bytes = commitment.to_bytes();

    // Write to the file
    let mut file = File::create(file_path)?;
    let mut writer = BufWriter::new(&mut file);
    writer.write_all(&commitment_bytes)?;

    Ok(())
}

/// Reads the commitment from a file.
pub fn read_commitment_from_file(
    file_path: &str,
) -> Result<Commitment<Blake3>, Box<dyn std::error::Error>> {
    // Open the file and create a buffered reader
    let file = File::open(file_path)?;
    let mut reader = BufReader::new(file);

    // Read the commitment bytes
    let mut commitment_bytes = Vec::new();
    reader.read_to_end(&mut commitment_bytes)?;

    // Deserialize the commitment
    let commitment = Commitment::<Blake3>::read_from_bytes(&commitment_bytes).unwrap();

    Ok(commitment)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::generate_data;
    use crate::frida_prover::traits::BaseFriProver;
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
