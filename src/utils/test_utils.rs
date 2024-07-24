use winter_crypto::hashers::Blake3_256;
use winter_fri::FriOptions;
use winter_math::{fft, FieldElement};
use winter_math::fields::f128;

use crate::frida_prover::channel::FridaProverChannel;
use crate::frida_prover::FridaProverBuilder;
use crate::frida_verifier::das::FridaDasVerifier;

pub type Blake3 = Blake3_256<f128::BaseElement>;
pub type TestFridaProverBuilder = FridaProverBuilder<f128::BaseElement, Blake3>;
pub type TestFridaProverChannel = FridaProverChannel<f128::BaseElement, Blake3, Blake3>;
pub type TestFridaDasVerifier = FridaDasVerifier<f128::BaseElement, Blake3, Blake3>;

pub fn test_build_prover_channel(
    trace_length: usize,
    options: &FriOptions,
) -> TestFridaProverChannel {
    TestFridaProverChannel::new(
        trace_length * options.blowup_factor(),
        32,
    )
}

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
