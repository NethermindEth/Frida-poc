use winter_crypto::{Digest, ElementHasher};
use winter_fri::ProverChannel;
use winter_math::FieldElement;

use crate::{constants, error::FridaError};
use crate::core::random::FridaRandom;

#[derive(Debug)]
pub struct FridaProverChannel<E, HHst, HRandom>
where
    E: FieldElement,
    HHst: ElementHasher<BaseField = E::BaseField>,
    HRandom: ElementHasher<BaseField = E::BaseField>,
{
    pub commitments: Vec<HRandom::Digest>,
    pub public_coin: FridaRandom<E, HHst, HRandom>,
    pub domain_size: usize,
    pub num_queries: usize,
}

impl<E, HHst, HRandom> FridaProverChannel<E, HHst, HRandom>
where
    E: FieldElement,
    HHst: ElementHasher<BaseField = E::BaseField>,
    HRandom: ElementHasher<BaseField = E::BaseField>,
{
    /// Returns a new prover channel instantiated from the specified parameters.
    ///
    /// # Panics
    /// Panics if:
    /// * `domain_size` is smaller than 8 or is not a power of two.
    /// * `num_queries` is zero.
    pub fn new(domain_size: usize, num_queries: usize) -> Self {
        assert!(
            domain_size >= constants::MIN_DOMAIN_SIZE,
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
            domain_size,
            num_queries,
            public_coin: FridaRandom::new(),
            commitments: Vec::new(),
        }
    }

    /// Draws the set of positions at which the polynomial evaluations committed at the first FRI
    /// layer should be queried.
    ///
    /// # Panics
    /// Panics if it fails while drawing a position.
    pub fn draw_query_positions(&mut self) -> Vec<usize> {
        let mut positions = self
            .public_coin
            .draw_query_positions(self.num_queries, self.domain_size)
            .expect("failed to draw query position");

        // TODO: Decide if dedup is ok or if we want to strictly hit the num_queries goal. Winterfell uses dedup.
        positions.dedup();
        positions
    }

    pub fn draw_xi(&mut self, count: usize) -> Result<Vec<E>, FridaError> {
        self.public_coin.draw_xi(count)
    }
}

impl<E, HHst, HRandom> ProverChannel<E> for FridaProverChannel<E, HHst, HRandom>
where
    E: FieldElement,
    HHst: ElementHasher<BaseField = E::BaseField>,
    HRandom: ElementHasher<BaseField = E::BaseField>,
{
    // assuming merkle tree hash function uses the hash function
    // that will generate the randomness in our Fiat-shamir
    type Hasher = HRandom;

    fn commit_fri_layer(
        &mut self,
        layer_root: <<Self as ProverChannel<E>>::Hasher as winter_crypto::Hasher>::Digest,
    ) {
        self.commitments.push(layer_root);
        self.public_coin.reseed(&layer_root.as_bytes());
    }

    fn draw_fri_alpha(&mut self) -> E {
        let alpha = self.public_coin.draw().expect("failed to draw FRI alpha");
        alpha
    }
}
