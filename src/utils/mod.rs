use winter_crypto::hashers::Blake3_256;
use winter_fri::FriOptions;
use winter_math::{fft, fields::f128::BaseElement, FieldElement};

use crate::{
    frida_prover_channel::{BaseProverChannel, FridaProverChannel},
    frida_random::FridaRandom,
};

type Blake3 = Blake3_256<BaseElement>;

pub fn test_build_prover_channel(
    trace_length: usize,
    options: &FriOptions,
) -> FridaProverChannel<BaseElement, Blake3, Blake3, FridaRandom<Blake3, Blake3, BaseElement>> {
    FridaProverChannel::<BaseElement, Blake3, Blake3, FridaRandom<Blake3, Blake3, BaseElement>>::new(
        trace_length * options.blowup_factor(),
        32,
    )
}

pub fn test_build_evaluations(trace_length: usize, lde_blowup: usize) -> Vec<BaseElement> {
    let mut p = (0..trace_length as u128)
        .map(BaseElement::new)
        .collect::<Vec<_>>();
    let domain_size = trace_length * lde_blowup;
    p.resize(domain_size, BaseElement::ZERO);

    let twiddles = fft::get_twiddles::<BaseElement>(domain_size);

    fft::evaluate_poly(&mut p, &twiddles);
    p
}
