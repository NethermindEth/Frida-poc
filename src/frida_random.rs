use core::marker::PhantomData;

use crate::{frida_const, frida_error::FridaError};
use winter_crypto::{Digest, ElementHasher};
use winter_math::{FieldElement, StarkField};

pub struct FridaRandom<HashHst: ElementHasher, HashRandom: ElementHasher, E: FieldElement> {
    counter: u64,
    hst: Vec<u8>,
    drawn_alphas: Vec<E>, // how can we only introduce this during test
    _hash_digest_hst: PhantomData<HashHst::Digest>,
    _hash_digest2_random: PhantomData<HashRandom::Digest>,
}

pub trait FridaRandomCoin: Sync {
    type BaseField: StarkField;
    type FieldElement: FieldElement;
    type HashHst: ElementHasher<BaseField = Self::BaseField>;
    type HashRandom: ElementHasher<BaseField = Self::BaseField>;

    fn new(hst_neg_1: &[u8]) -> Self;
    fn draw(&mut self) -> Result<Self::FieldElement, FridaError>;
    fn draw_query_positions(
        &self,
        num_queries: usize,
        domain_size: usize,
    ) -> Result<Vec<usize>, FridaError>;
    fn reseed(&mut self, new_root: &[u8]);
    fn drawn_alphas(&self) -> Vec<Self::FieldElement>;
}

impl<
        B: StarkField,
        HashHst: ElementHasher<BaseField = B>,
        HashRandom: ElementHasher<BaseField = B>,
        E: FieldElement<BaseField = B>,
    > FridaRandomCoin for FridaRandom<HashHst, HashRandom, E>
{
    type BaseField = B;
    type FieldElement = E;
    type HashHst = HashHst;
    type HashRandom = HashRandom;

    fn new(hst_neg_1: &[u8]) -> Self {
        Self {
            hst: hst_neg_1.to_vec(),
            counter: 0,
            drawn_alphas: vec![],
            _hash_digest_hst: PhantomData,
            _hash_digest2_random: PhantomData,
        }
    }

    fn draw(&mut self) -> Result<E, FridaError> {
        let random_value = HashRandom::hash(&self.hst[..E::ELEMENT_BYTES]);

        let bytes = &random_value.as_bytes()[..E::ELEMENT_BYTES];
        if let Some(element) = E::from_random_bytes(bytes) {
            self.drawn_alphas.push(element);

            return Ok(element);
        }

        Err(FridaError::DrawError())
    }

    fn draw_query_positions(
        &self,
        num_queries: usize,
        domain_size: usize,
    ) -> Result<Vec<usize>, FridaError> {
        assert!(
            domain_size >= frida_const::MIN_DOMAIN_SIZE,
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

    fn reseed(&mut self, new_root: &[u8]) {
        let prev_hst = &self.hst;
        let merged = [new_root, prev_hst, &self.counter.to_be_bytes()].concat();
        let new_hst = HashHst::hash(&merged);

        self.hst = new_hst.as_bytes().to_vec();
        self.counter += 1;
    }

    fn drawn_alphas(&self) -> Vec<E> {
        self.drawn_alphas.clone()
    }
}

// new (hst_-1) -> Self
// counter = 0

// draw()
// return hash_random(hst)

// reseed(root_new)
// new_hst = hash_hst(root_new, old_hst, counter)
// counter += 1
