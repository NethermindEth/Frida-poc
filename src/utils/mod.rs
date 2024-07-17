use serde::Deserialize;
use std::{
    fs::{self, File},
    io::{self, BufWriter, Read, Write},
    path::Path,
};
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
#[serde(remote = "FriOptions")]
pub struct FriOptionsDef {
    #[serde(getter = "FriOptions::folding_factor")]
    folding_factor: usize,
    #[serde(getter = "FriOptions::remainder_max_degree")]
    remainder_max_degree: usize,
    #[serde(getter = "FriOptions::blowup_factor")]
    blowup_factor: usize,
}

impl From<FriOptionsDef> for FriOptions {
    fn from(def: FriOptionsDef) -> FriOptions {
        FriOptions::new(
            def.blowup_factor,
            def.folding_factor,
            def.remainder_max_degree,
        )
    }
}

pub fn load_fri_options(file_path: &Path) -> Result<FriOptions, Box<dyn std::error::Error>> {
    let file_content = fs::read_to_string(file_path)?;
    let mut de = serde_json::Deserializer::from_str(&file_content);
    let fri_options = FriOptionsDef::deserialize(&mut de)?;
    Ok(fri_options)
}

pub fn read_file_to_vec(file_path: &Path) -> Result<Vec<u8>, io::Error> {
    let mut file = File::open(file_path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    Ok(data)
}

pub fn write_to_file(file_path: &Path, data: &[u8]) -> Result<(), io::Error> {
    let mut file = File::create(file_path)?;
    let mut writer = BufWriter::new(&mut file);
    writer.write_all(data)?;
    Ok(())
}

pub struct CleanupFiles<'a> {
    pub paths: Vec<&'a Path>,
}

impl<'a> CleanupFiles<'a> {
    pub fn new(paths: Vec<&'a Path>) -> Self {
        CleanupFiles { paths }
    }
}

impl Drop for CleanupFiles<'_> {
    fn drop(&mut self) {
        for path in &self.paths {
            if path.exists() {
                fs::remove_file(path).unwrap_or_else(|err| {
                    eprintln!("Failed to remove file {}: {}", path.display(), err);
                });
            }
        }
    }
}
