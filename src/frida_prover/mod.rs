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

#[derive(Debug, PartialEq)]
pub struct Commitment<HRoot: ElementHasher> {
    pub roots: Vec<HRoot::Digest>,
    pub proof: FridaProof,
}

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

impl<B, E, C, H> FridaProver<B, E, C, H>
where
    B: StarkField,
    E: FieldElement<BaseField = B>,
    C: BaseProverChannel<E, H>,
    H: ElementHasher<BaseField = B>,
{
    fn build_layers_from_data(
        &mut self,
        data: &[u8],
        num_queries: usize,
    ) -> Result<(), FridaError> {
        // TODO: Decide if we want to dynamically set domain_size like here
        let blowup_factor = self.options.blowup_factor();
        let encoded_element_count = encoded_data_element_count::<E>(data.len());

        let domain_size = usize::max(
            (encoded_element_count * blowup_factor).next_power_of_two(),
            frida_const::MIN_DOMAIN_SIZE,
        );

        if domain_size > frida_const::MAX_DOMAIN_SIZE {
            return Err(FridaError::DomainSizeTooBig(domain_size));
        }
        if num_queries >= domain_size {
            return Err(FridaError::BadNumQueries(num_queries));
        }

        let evaluations = build_evaluations_from_data(&data, domain_size, blowup_factor)?;

        if num_queries == 0 {
            let mut channel = C::new(domain_size, 1);
            self.build_layers(&mut channel, evaluations);
        } else {
            let mut channel = C::new(domain_size, num_queries);
            self.build_layers(&mut channel, evaluations);
            self.channel = Some(channel);
        }

        Ok(())
    }

    // COMMIT STAGE
    // --------------------------------------------------------------------------------------------
    pub fn commit(
        &mut self,
        data: Vec<u8>,
        num_queries: usize,
    ) -> Result<(Commitment<H>, Vec<u8>), FridaError> {
        if num_queries == 0 {
            return Err(FridaError::BadNumQueries(num_queries));
        }
        self.build_layers_from_data(&data, num_queries)?;
        let proof = self.query();
        let channel = self.channel.take().unwrap();

        let commitment = Commitment {
            roots: channel.take_layer_commitments(),
            proof,
        };

        Ok((commitment, data))
    }

    fn query(&mut self) -> FridaProof {
        if let Some(channel) = &mut self.channel {
            let query_positions = channel.draw_query_positions();
            self.build_proof(&query_positions)
        } else {
            panic!("Channel does not exist")
        }
    }

    // OPEN STAGE
    // --------------------------------------------------------------------------------------------
    pub fn parse_state(&mut self, state: &[u8]) -> Result<(), FridaError> {
        self.build_layers_from_data(state, 0)
    }

    pub fn open(&mut self, positions: &[usize]) -> FridaProof {
        self.build_proof(positions)
    }
}

#[cfg(test)]
mod base_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{frida_prover_channel::FridaProverChannel, frida_random::FridaRandom};
    use winter_crypto::hashers::Blake3_256;
    use winter_fri::{FriOptions, ProverChannel};
    use winter_math::fields::f128::BaseElement;
    use winter_rand_utils::rand_vector;

    #[test]
    fn test_commit() {
        let options = FriOptions::new(2, 2, 0);
        let mut prover: FridaProver<
            BaseElement,
            BaseElement,
            FridaProverChannel<
                BaseElement,
                Blake3_256<BaseElement>,
                Blake3_256<BaseElement>,
                FridaRandom<Blake3_256<BaseElement>, Blake3_256<BaseElement>>,
            >,
            Blake3_256<BaseElement>,
        > = FridaProver::new(options.clone());

        let domain_error = prover
            .commit(vec![0; frida_const::MAX_DOMAIN_SIZE * 15 / 2 + 1], 1)
            .unwrap_err();
        assert_eq!(
            FridaError::DomainSizeTooBig(frida_const::MAX_DOMAIN_SIZE * 2),
            domain_error
        );
        prover.reset();

        let num_qeuries_error_zero = prover.commit(rand_vector::<u8>(10), 0).unwrap_err();
        assert_eq!(FridaError::BadNumQueries(0), num_qeuries_error_zero);
        prover.reset();

        let num_qeuries_error_bigger_than_domain =
            prover.commit(rand_vector::<u8>(200), 32).unwrap_err();
        assert_eq!(
            FridaError::BadNumQueries(32),
            num_qeuries_error_bigger_than_domain
        );
        prover.reset();

        // Make sure minimum domain size is correctly enforced
        let (commitment, _) = prover.commit(rand_vector::<u8>(1), 1).unwrap();
        assert_eq!(
            frida_const::MIN_DOMAIN_SIZE.ilog2() as usize,
            commitment.roots.len()
        );
        prover.reset();

        let data = rand_vector::<u8>(200);
        let (commitment, state) = prover.commit(data.clone(), 31).unwrap();

        let evaluations = build_evaluations_from_data(&data, 32, 2).unwrap();
        let mut prover = FridaProver::new(options.clone());
        let mut channel = FridaProverChannel::<
            BaseElement,
            Blake3_256<BaseElement>,
            Blake3_256<BaseElement>,
            FridaRandom<Blake3_256<BaseElement>, Blake3_256<BaseElement>>,
        >::new(32, 31);
        prover.build_layers(&mut channel, evaluations.clone());
        let positions = channel.draw_query_positions();
        let proof = prover.build_proof(&positions);

        assert_eq!(
            commitment,
            Commitment {
                roots: channel.layer_commitments().to_vec(),
                proof: proof
            }
        );
        assert_eq!(state, data);
    }

    #[test]
    fn test_open() {
        let options = FriOptions::new(2, 2, 0);
        let mut prover: FridaProver<
            BaseElement,
            BaseElement,
            FridaProverChannel<
                BaseElement,
                Blake3_256<BaseElement>,
                Blake3_256<BaseElement>,
                FridaRandom<Blake3_256<BaseElement>, Blake3_256<BaseElement>>,
            >,
            Blake3_256<BaseElement>,
        > = FridaProver::new(options.clone());

        let data = rand_vector::<u8>(200);
        let (commitment, state) = prover.commit(data.clone(), 31).unwrap();

        let mut opening_prover: FridaProver<
            BaseElement,
            BaseElement,
            FridaProverChannel<
                BaseElement,
                Blake3_256<BaseElement>,
                Blake3_256<BaseElement>,
                FridaRandom<Blake3_256<BaseElement>, Blake3_256<BaseElement>>,
            >,
            Blake3_256<BaseElement>,
        > = FridaProver::new(options.clone());
        opening_prover.parse_state(&state).unwrap();

        // Replicating query positions just to make sure open is generating proper proofs since we can just compare it with the query phase proofs
        let mut channel = FridaProverChannel::<
            BaseElement,
            Blake3_256<BaseElement>,
            Blake3_256<BaseElement>,
            FridaRandom<Blake3_256<BaseElement>, Blake3_256<BaseElement>>,
        >::new(32, 31);
        for layer_root in commitment.roots {
            channel.commit_fri_layer(layer_root);
        }
        let query_positions = channel.draw_query_positions();

        let opening_prover_query_proof = opening_prover.open(&query_positions);
        assert_eq!(commitment.proof, opening_prover_query_proof);

        // Make sure prover that has ran commit can also just use open for creating more proofs
        let prover_proof = prover.open(&[1, 0, 3]);
        let opening_prover_proof = opening_prover.open(&[1, 0, 3]);
        assert_eq!(prover_proof, opening_prover_proof);
    }
}
