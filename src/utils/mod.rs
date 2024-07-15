use serde::Deserialize;
use std::fs;
use std::fs::File;
use std::io::{self, BufWriter, Read, Write};

use winter_crypto::hashers::Blake3_256;
use winter_fri::FriOptions;
use winter_math::{fft, fields::f128::BaseElement, FieldElement};

use crate::{
    frida_prover_channel::{BaseProverChannel, FridaProverChannel},
    frida_random::FridaRandom,
};

type Blake3 = Blake3_256<BaseElement>;

pub fn build_prover_channel(
    trace_length: usize,
    options: &FriOptions,
) -> FridaProverChannel<BaseElement, Blake3, Blake3, FridaRandom<Blake3, Blake3, BaseElement>> {
    FridaProverChannel::<BaseElement, Blake3, Blake3, FridaRandom<Blake3, Blake3, BaseElement>>::new(
        trace_length * options.blowup_factor(),
        32,
    )
}

pub fn build_evaluations(trace_length: usize, lde_blowup: usize) -> Vec<BaseElement> {
    let mut p = (0..trace_length as u128)
        .map(BaseElement::new)
        .collect::<Vec<_>>();
    let domain_size = trace_length * lde_blowup;
    p.resize(domain_size, BaseElement::ZERO);

    let twiddles = fft::get_twiddles::<BaseElement>(domain_size);

    fft::evaluate_poly(&mut p, &twiddles);
    p
}

#[derive(Deserialize)]
pub struct FriOptionsConfig {
    blowup_factor: usize,
    folding_factor: usize,
    max_remainder_degree: usize,
}

pub fn load_fri_options(file_path: Option<&String>) -> FriOptions {
    if let Some(path) = file_path {
        let file_content = fs::read_to_string(path).expect("Unable to read FriOptions file");
        let config: FriOptionsConfig =
            serde_json::from_str(&file_content).expect("Invalid FriOptions file format");
        FriOptions::new(
            config.blowup_factor,
            config.folding_factor,
            config.max_remainder_degree,
        )
    } else {
        FriOptions::new(8, 2, 7)
    }
}

pub fn read_file_to_vec(file_path: &str) -> Result<Vec<u8>, io::Error> {
    let mut file = File::open(file_path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    Ok(data)
}

pub fn write_to_file(file_path: &str, data: &[u8]) -> Result<(), io::Error> {
    let mut file = File::create(file_path)?;
    let mut writer = BufWriter::new(&mut file);
    writer.write_all(data)?;
    Ok(())
}
