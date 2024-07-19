use frida_poc::{
    frida_data::encoded_data_element_count,
    frida_prover::FridaProverBuilder,
    frida_prover_channel::FridaProverChannel,
    frida_random::FridaRandom,
};
use winter_crypto::hashers::Blake3_256;
use winter_fri::FriOptions;
use winter_math::fields::f128::BaseElement;

type Blake3 = Blake3_256<BaseElement>;
type FridaChannel =
    FridaProverChannel<BaseElement, Blake3, Blake3, FridaRandom<Blake3, Blake3, BaseElement>>;
type FridaProverBuilderType = FridaProverBuilder<BaseElement, BaseElement, Blake3, FridaChannel>;

pub fn run(data_path: &str, num_queries: usize, options: FriOptions) {
    let data = std::fs::read(data_path).expect("Unable to read data file");
    let prover_builder = FridaProverBuilderType::new(options.clone());

    let encoded_element_count =
        encoded_data_element_count::<BaseElement>(data.len()).next_power_of_two();

    let (commitment, _prover) =
        prover_builder.commit(&data, num_queries).unwrap();
    // TODO: Save commitment to file

    println!(
        "Data committed with commitment: {:?} and encoded element count: {}",
        commitment, encoded_element_count
    );
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
        run(data_path, 31, options);

        // TODO: Check if the commitment file is correct
    }
}
