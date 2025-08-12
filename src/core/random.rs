use core::marker::PhantomData;

use crate::{constants, error::FridaError};
use winter_crypto::{Digest, ElementHasher};
use winter_math::FieldElement;

#[derive(Debug)]
pub struct FridaRandom<E: FieldElement, HashHst: ElementHasher, HashRandom: ElementHasher> {
    counter: u64,
    hst: Vec<u8>,
    #[cfg(test)]
    drawn_alphas: Vec<E>,
    _field_element: PhantomData<E>,
    _hash_digest_hst: PhantomData<HashHst::Digest>,
    _hash_digest2_random: PhantomData<HashRandom::Digest>,
}

impl<
        E: FieldElement,
        HashHst: ElementHasher<BaseField = E::BaseField>,
        HashRandom: ElementHasher<BaseField = E::BaseField>,
    > FridaRandom<E, HashHst, HashRandom>
{
    /// Create a fresh public coin with a predefined seed.
    pub fn new() -> Self {
        Self::from_hst(&[123])
    }

    fn from_hst(hst_neg_1: &[u8]) -> Self {
        Self {
            hst: hst_neg_1.to_vec(),
            counter: 0,
            #[cfg(test)]
            drawn_alphas: vec![],
            _field_element: PhantomData,
            _hash_digest_hst: PhantomData,
            _hash_digest2_random: PhantomData,
        }
    }

    pub fn draw(&mut self) -> Result<E, FridaError> {
        let random_value = HashRandom::hash(&self.hst[..E::ELEMENT_BYTES]);

        let bytes = &random_value.as_bytes()[..E::ELEMENT_BYTES];
        if let Some(element) = E::from_random_bytes(bytes) {
            #[cfg(test)]
            self.drawn_alphas.push(element);

            return Ok(element);
        }

        Err(FridaError::DrawError())
    }

    pub fn draw_query_positions(
        &self,
        num_queries: usize,
        domain_size: usize,
    ) -> Result<Vec<usize>, FridaError> {
        assert!(
            domain_size >= constants::MIN_DOMAIN_SIZE,
            "domain size must be at least 8, but was {domain_size}"
        );
        assert!(
            domain_size.is_power_of_two(),
            "domain size must be a power of two"
        );
        assert!(
            num_queries < domain_size,
            "number of query points must be smaller than domain size"
        );

        let mut values = Vec::with_capacity(num_queries);
        let mask = (domain_size - 1) as u64;
        for i in 0..num_queries {
            let to_be_hashed = [&self.hst[..], &i.to_be_bytes()].concat();
            let random_value = HashRandom::hash(&to_be_hashed);
            let bytes: [u8; 8] = random_value.as_bytes()[..8].try_into().unwrap();
            let result = (u64::from_be_bytes(bytes) & mask) as usize;

            values.push(result);
        }

        if values.len() < num_queries {
            return Err(FridaError::FailedToDrawEnoughQueryPoints(
                num_queries,
                domain_size,
            ));
        }

        Ok(values)
    }

    pub fn draw_xi(&self, count: usize) -> Result<Vec<E>, FridaError> {
        let mut values = Vec::with_capacity(count);
        for i in 0..count {
            let to_be_hashed = [&self.hst[..], &i.to_be_bytes()].concat();
            let random_value = HashRandom::hash(&to_be_hashed);
            let bytes = &random_value.as_bytes()[..E::ELEMENT_BYTES];
            if let Some(element) = E::from_random_bytes(bytes) {
                values.push(element);
            } else {
                return Err(FridaError::DrawError());
            }
        }

        if values.len() < count {
            return Err(FridaError::FailedToDrawEnoughXi(count, count));
        }

        Ok(values)
    }

    pub fn reseed(&mut self, new_root: &[u8]) {
        let prev_hst = &self.hst;
        let merged = [new_root, prev_hst, &self.counter.to_be_bytes()].concat();
        let new_hst = HashHst::hash(&merged);

        self.hst = new_hst.as_bytes().to_vec();
        self.counter += 1;
    }

    #[cfg(test)]
    pub fn test_drawn_alphas(&self) -> Vec<E> {
        self.drawn_alphas.clone()
    }
}
