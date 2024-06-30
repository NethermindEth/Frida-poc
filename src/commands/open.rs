use std::fs;
use std::fs::File;
use std::io::BufWriter;
use std::io::Write;

use crate::{
    commands::commit::read_commitment_from_file,
    frida_data::{build_evaluations_from_data, encoded_data_element_count},
    frida_prover::{traits::BaseFriProver, Commitment, FridaProver},
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

pub fn run(proof_path: &str, positions: &[usize], options: FriOptions) {
    let data = fs::read("data/data.bin").unwrap();
    let encoded_element_count =
        encoded_data_element_count::<BaseElement>(data.len()).next_power_of_two();
    let (_, commitment) = read_commitment_from_file("d").expect("Cannot read commitment file");

    let mut prover: FridaProverType = FridaProver::new(options.clone());
    let open_position = [1];
    let proof = prover.open(&open_position);

    let domain_size = (encoded_element_count - 1).next_power_of_two() * options.blowup_factor();
    let evaluations: Vec<BaseElement> =
        build_evaluations_from_data(&data, domain_size, options.blowup_factor()).unwrap();

    let queried_evaluations = open_position
        .iter()
        .map(|&p| evaluations[p])
        .collect::<Vec<_>>();

    // TODO: Save to the file
}
