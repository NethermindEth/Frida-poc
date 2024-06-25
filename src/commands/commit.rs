use serde_json;
use std::fs;

use frida_poc::{
    frida_data::encoded_data_element_count,
    frida_prover::{traits::BaseFriProver, FridaProver},
    frida_prover_channel::FridaProverChannel,
    frida_random::FridaRandom,
};
use winter_crypto::hashers::Blake3_256;
use winter_fri::FriOptions;
use winter_math::fields::f128::BaseElement;

type Blake3 = Blake3_256<BaseElement>;
type FridaChannel =
    FridaProverChannel<BaseElement, Blake3, Blake3, FridaRandom<Blake3, Blake3, BaseElement>>;
type FridaProverType = FridaProver<BaseElement, BaseElement, FridaChannel, Blake3>;

pub fn run(
    data_path: &str,
    num_queries: usize,
    options: FriOptions,
) -> Result<(), Box<dyn std::error::Error>> {
    let data = fs::read(data_path)?;
    let mut prover: FridaProverType = FridaProver::new(options.clone());

    let encoded_element_count =
        encoded_data_element_count::<BaseElement>(data.len()).next_power_of_two();

    let (commitment, _) = prover.commit(data.clone(), num_queries).unwrap();

    let commitment_json = serde_json::to_string(&commitment).unwrap();
    fs::write("data/commitment.json", commitment_json)?;

    println!("Commitment saved to data/commitment.json");

    fs::write("data/count.txt", encoded_element_count.to_string())?;

    println!("Encoded element count saved to data/count.txt");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commit() {
        let data_path = "data/data.bin";
        assert!(
            std::path::Path::new(data_path).exists(),
            "Test data file does not exist"
        );

        let options = FriOptions::new(8, 2, 7);
        run(data_path, 31, options).expect("Failed to commit data");

        // TODO: Check if the commitment file is correct
    }
}
