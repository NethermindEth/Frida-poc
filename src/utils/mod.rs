use winter_crypto::hashers::Blake3_256;
use winter_fri::FriOptions;
use winter_math::{fft, fields::f128, FieldElement};

use crate::{
    frida_random::FridaRandom,
};

#[cfg(test)]
use crate::frida_prover::channel::FridaProverChannel;

type Blake3 = Blake3_256<f128::BaseElement>;

#[cfg(test)]
pub fn test_build_prover_channel(
    trace_length: usize,
    options: &FriOptions,
) -> FridaProverChannel<f128::BaseElement, Blake3, Blake3, FridaRandom<Blake3, Blake3, f128::BaseElement>> {
    FridaProverChannel::<f128::BaseElement, Blake3, Blake3, FridaRandom<Blake3, Blake3, f128::BaseElement>>::new(
        trace_length * options.blowup_factor(),
        32,
    )
}

#[cfg(test)]
pub fn test_build_evaluations(trace_length: usize, lde_blowup: usize) -> Vec<f128::BaseElement> {
    let mut p = (0..trace_length as u128)
        .map(f128::BaseElement::new)
        .collect::<Vec<_>>();
    let domain_size = trace_length * lde_blowup;
    p.resize(domain_size, f128::BaseElement::ZERO);

    let twiddles = fft::get_twiddles::<f128::BaseElement>(domain_size);

    fft::evaluate_poly(&mut p, &twiddles);
    p
}
