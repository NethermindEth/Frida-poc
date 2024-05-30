use core::marker::PhantomData;

use traits::BaseFriProver;
use winter_crypto::{ElementHasher, Hasher, MerkleTree};
use winter_math::{FieldElement, StarkField};

use winter_fri::FriOptions;

pub mod proof;
pub mod traits;
use proof::FridaProof;

use crate::{
    frida_const,
    frida_data::{build_evaluations_from_data, encoded_data_element_count},
    frida_error::FridaError,
    frida_prover_channel::BaseProverChannel,
};

pub struct FridaProver<B, E, C, H>
where
    B: StarkField,
    E: FieldElement<BaseField = B>,
    C: BaseProverChannel<E, H>,
    H: ElementHasher<BaseField = B>,
{
    options: FriOptions,
    layers: Vec<FridaLayer<B, E, H>>,
    remainder_poly: FridaRemainder<E>,
    channel: Option<C>,
}

pub struct FridaLayer<B: StarkField, E: FieldElement<BaseField = B>, H: Hasher> {
    tree: MerkleTree<H>,
    evaluations: Vec<E>,
    _base_field: PhantomData<B>,
}

pub struct FridaRemainder<E: FieldElement>(Vec<E>);

// PROVER IMPLEMENTATION
// ================================================================================================

impl<B, E, C, H> BaseFriProver<B, E, C, H> for FridaProver<B, E, C, H>
where
    B: StarkField,
    E: FieldElement<BaseField = B>,
    C: BaseProverChannel<E, H>,
    H: ElementHasher<BaseField = B>,
{
    fn new(options: FriOptions) -> Self {
        FridaProver {
            options,
            layers: Vec::new(),
            remainder_poly: FridaRemainder(vec![]),
            channel: None,
        }
    }

    fn options(&self) -> &FriOptions {
        &self.options
    }

    fn folding_factor(&self) -> usize {
        self.options.folding_factor()
    }

    fn domain_size(&self) -> usize {
        self.layers[0].evaluations.len()
    }

    fn domain_offset(&self) -> B {
        self.options.domain_offset()
    }

    fn remainder_poly(&self) -> &FridaRemainder<E> {
        &self.remainder_poly
    }

    fn num_layers(&self) -> usize {
        self.layers.len()
    }

    fn reset(&mut self) {
        self.layers.clear();
        self.remainder_poly.0.clear();
        self.channel = None;
    }

    fn store_layer(&mut self, layer: FridaLayer<B, E, H>) {
        self.layers.push(layer);
    }

    fn get_layer(&self, index: usize) -> &FridaLayer<B, E, H> {
        &self.layers[index]
    }

    fn set_remainer_poly(&mut self, remainder: FridaRemainder<E>) {
        self.remainder_poly = remainder;
    }
}

#[cfg(test)]
mod base_tests;
