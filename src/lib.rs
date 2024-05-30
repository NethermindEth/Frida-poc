pub mod frida_commit;
pub mod frida_const;
pub mod frida_data;
pub mod frida_error;
pub mod frida_prover;
pub mod frida_prover_channel;
pub mod frida_random;

use frida_prover_channel::{BaseProverChannel, FridaProverChannel};
use frida_random::FridaRandom;
use winter_crypto::hashers::Blake3_256;
use winter_fri::{FriOptions, FriProver};
use winter_math::fft::{self};
use winter_math::fields::f128::BaseElement;
use winter_math::FieldElement;
use winter_rand_utils::rand_vector;

fn build_evaluations(domain_size: usize) -> Vec<BaseElement> {
    let mut p: Vec<BaseElement> = rand_vector(domain_size / BLOWUP_FACTOR);
    p.resize(domain_size, BaseElement::ZERO);
    let twiddles = fft::get_twiddles::<BaseElement>(domain_size);
    fft::evaluate_poly(&mut p, &twiddles);
    p
}

static BLOWUP_FACTOR: usize = 8;
pub fn fri() {
    let options: FriOptions = FriOptions::new(BLOWUP_FACTOR, 4, 255);
    let domain_size = 65536;
    let evaluations = build_evaluations(domain_size);

    let mut prover = FriProver::new(options.clone());
    let mut channel = FridaProverChannel::<
        BaseElement,
        Blake3_256<BaseElement>,
        Blake3_256<BaseElement>,
        FridaRandom<Blake3_256<BaseElement>, Blake3_256<BaseElement>>,
    >::new(domain_size, 32);
    prover.build_layers(&mut channel, evaluations);
}

#[cfg(test)]
mod tests {
    use crate::fri;

    #[test]
    fn test_fri() {
        fri()
    }
}
