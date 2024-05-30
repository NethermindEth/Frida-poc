use std::marker::PhantomData;

use winter_crypto::{Digest, ElementHasher};
use winter_math::{FieldElement, StarkField};

pub struct FridaRandom<HashHst: ElementHasher, HashRandom: ElementHasher, E: FieldElement> {
    counter: u64,
    hst: Vec<u8>,
    drawn_alphas: Vec<E>,
    _hash_digest_hst: PhantomData<HashHst::Digest>,
    _hash_digest2_random: PhantomData<HashRandom::Digest>,
}

pub trait FridaRandomCoin: Sync {
    type BaseField: StarkField;
    type FieldElement: FieldElement;
    type HashHst: ElementHasher<BaseField = Self::BaseField>;
    type HashRandom: ElementHasher<BaseField = Self::BaseField>;

    fn new(hst_neg_1: &[u8]) -> Self;
    // fn draw<E: FieldElement<BaseField = Self::BaseField>>(&self) -> Result<E, &str>;
    fn draw(&mut self) -> Result<Self::FieldElement, &str>;
    fn reseed(&mut self, new_root: &[u8]);
    fn drawn_alphas(&self) -> Vec<Self::FieldElement>;
}

// impl<
//         B: StarkField,
//         HashHst: ElementHasher<BaseField = B>,
//         HashRandom: ElementHasher<BaseField = B>,
//         E: FieldElement<BaseField = B>,
//     > FridaRandom<HashHst, HashRandom, E>
// {
//     fn drawn_alphas(&self) -> Option<Vec<E>> {
//         match &self.drawn_alphas {
//             None => None,
//             Some(v) => Some(v.to_vec()),
//         }
//     }
// }

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

    fn draw(&mut self) -> Result<E, &str> {
        let random_value = HashRandom::hash(&self.hst[..E::ELEMENT_BYTES]);

        let bytes = &random_value.as_bytes()[..E::ELEMENT_BYTES];
        if let Some(element) = E::from_random_bytes(bytes) {
            self.drawn_alphas.push(element);

            return Ok(element);
        }
        Err("Error in draw")
    }

    fn reseed(&mut self, new_root: &[u8]) {
        let prev_hst = &self.hst;
        let merged = [new_root, prev_hst, &self.counter.to_ne_bytes()].concat();
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
