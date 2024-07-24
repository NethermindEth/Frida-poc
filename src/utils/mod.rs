use winter_crypto::ElementHasher;
use winter_math::FieldElement;

use crate::frida_random::{FridaRandom, FridaRandomCoin};

#[cfg(test)]
pub mod test_utils;

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
