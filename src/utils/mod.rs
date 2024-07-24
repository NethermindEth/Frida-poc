use winter_crypto::ElementHasher;
use winter_crypto::hashers::Blake3_256;
use winter_fri::FriOptions;
use winter_math::{fft, fields::f128, FieldElement};

#[cfg(test)]
use crate::frida_prover::channel::FridaProverChannel;
use crate::frida_random::{FridaRandom, FridaRandomCoin};

type Blake3 = Blake3_256<f128::BaseElement>;

#[cfg(test)]
pub fn test_build_prover_channel(
    trace_length: usize,
    options: &FriOptions,
) -> FridaProverChannel<f128::BaseElement, Blake3, Blake3> {
    FridaProverChannel::<f128::BaseElement, Blake3, Blake3>::new(
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

pub struct FreshPublicCoin<E, HashHst, HashRandom>
where
    E: FieldElement,
    HashHst: ElementHasher<BaseField = E::BaseField>,
    HashRandom: ElementHasher<BaseField = E::BaseField>,
{
    coin: FridaRandom<E, HashHst, HashRandom>,
}

impl<E, HashHst, HashRandom> FreshPublicCoin<E, HashHst, HashRandom>
where
    E: FieldElement,
    HashHst: ElementHasher<BaseField = E::BaseField>,
    HashRandom: ElementHasher<BaseField = E::BaseField>,
{

    /// Create a new fresh public coin with a predefined seed.
    pub fn new() -> Self {
        Self { coin: FridaRandom::<E, HashHst, HashRandom>::new(&[123]) }
    }

    /// Consume self, returning the contained coin.
    pub fn inner(self) -> FridaRandom<E, HashHst, HashRandom> {
        self.coin
    }
}
