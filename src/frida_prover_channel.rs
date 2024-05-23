use std::marker::PhantomData;

use winter_crypto::{Digest, ElementHasher};
use winter_fri::ProverChannel;
use winter_math::FieldElement;

use crate::frida_random::FridaRandomCoin;

pub struct FridaProverChannel<E, HHst, HRandom, R>
where
    E: FieldElement,
    HHst: ElementHasher<BaseField = E::BaseField>,
    HRandom: ElementHasher<BaseField = E::BaseField>,
    R: FridaRandomCoin<BaseField = E::BaseField, HashHst = HHst, HashRandom = HRandom>,
{
    commitments: Vec<HRandom::Digest>,
    public_coin: R,
    _hash_function_hst: PhantomData<HHst>,
    _hash_function_random: PhantomData<HRandom>,
    _field_element: PhantomData<E>,
}

impl<E, HHst, HRandom, R> FridaProverChannel<E, HHst, HRandom, R>
where
    E: FieldElement,
    HHst: ElementHasher<BaseField = E::BaseField>,
    HRandom: ElementHasher<BaseField = E::BaseField>,
    R: FridaRandomCoin<BaseField = E::BaseField, HashHst = HHst, HashRandom = HRandom>,
{
    /// Returns a new prover channel instantiated from the specified parameters.
    ///
    /// # Panics
    /// Panics if:
    /// * `domain_size` is smaller than 8 or is not a power of two.
    /// * `num_queries` is zero.
    pub fn new(domain_size: usize, num_queries: usize) -> Self {
        assert!(
            domain_size >= 8,
            "domain size must be at least 8, but was {domain_size}"
        );
        assert!(
            domain_size.is_power_of_two(),
            "domain size must be a power of two, but was {domain_size}"
        );
        assert!(
            num_queries > 0,
            "number of queries must be greater than zero"
        );
        Self {
            public_coin: FridaRandomCoin::new(&[123]),
            commitments: Vec::new(),
            _hash_function_hst: PhantomData,
            _hash_function_random: PhantomData,
            _field_element: PhantomData,
        }
    }
}

impl<E, HHst, HRandom, R> ProverChannel<E> for FridaProverChannel<E, HHst, HRandom, R>
where
    E: FieldElement,
    HHst: ElementHasher<BaseField = E::BaseField>,
    HRandom: ElementHasher<BaseField = E::BaseField>,
    R: FridaRandomCoin<BaseField = E::BaseField, HashHst = HHst, HashRandom = HRandom>,
{
    // assuming merkle tree hash function uses the hash function
    // that will generate the randomness in our Fiat-shamir
    type Hasher = HRandom;

    fn commit_fri_layer(
        &mut self,
        layer_root: <<Self as ProverChannel<E>>::Hasher as winter_crypto::Hasher>::Digest,
    ) {
        self.commitments.push(layer_root);
        self.public_coin.update(&layer_root.as_bytes());
    }

    fn draw_fri_alpha(&mut self) -> E {
        self.public_coin.draw().expect("failed to draw FRI alpha")
    }
}
