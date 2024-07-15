use core::marker::PhantomData;

#[cfg(feature = "bench")]
use std::time::Instant;

use traits::BaseFriProver;
use winter_crypto::{ElementHasher, Hasher, MerkleTree};
use winter_math::{FieldElement, StarkField};

use winter_fri::FriOptions;

pub mod proof;
pub mod traits;
use proof::FridaProof;
use winter_utils::uninit_vector;

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
    poly_count: usize,
    remainder_poly: FridaRemainder<E>,
    channel: Option<C>,
}

pub struct FridaLayer<B: StarkField, E: FieldElement<BaseField = B>, H: Hasher> {
    tree: MerkleTree<H>,
    pub evaluations: Vec<E>,
    _base_field: PhantomData<B>,
}

pub struct FridaRemainder<E: FieldElement>(Vec<E>);

#[derive(Debug, PartialEq)]
pub struct Commitment<HRoot: ElementHasher> {
    pub roots: Vec<HRoot::Digest>,
    pub proof: FridaProof,
    // In a real protocol, domain size will likely be predefined and won't be part of a block.
    pub domain_size: usize,
    pub num_queries: usize,
    pub poly_count: usize,
}

#[cfg(feature = "bench")]
pub mod bench {
    use std::time::{Duration, Instant};
    pub static mut TIMER: Option<Instant> = None;
    pub static mut ERASURE_TIME: Option<Duration> = None;
    pub static mut COMMIT_TIME: Option<Duration> = None;
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
            poly_count: 1,
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
        self.layers[0].evaluations.len() / self.poly_count
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
        self.poly_count = 1;
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

    fn is_batch(&self) -> bool {
        self.poly_count > 1
    }

    fn poly_count(&self) -> usize {
        self.poly_count
    }
}

impl<B, E, C, H> FridaProver<B, E, C, H>
where
    B: StarkField,
    E: FieldElement<BaseField = B>,
    C: BaseProverChannel<E, H>,
    H: ElementHasher<BaseField = B>,
{
    fn build_layers_from_batched_data(
        &mut self,
        data_list: &[Vec<u8>],
        num_queries: usize,
    ) -> Result<(), FridaError> {
        #[cfg(feature = "bench")]
        unsafe {
            bench::TIMER = Some(Instant::now());
        }

        let poly_count = data_list.len();
        if poly_count <= 1 {
            return Err(FridaError::SinglePolyBatch);
        }

        let blowup_factor = self.options.blowup_factor();

        let max_data_len = encoded_data_element_count::<E>(
            data_list.iter().map(|data| data.len()).max().unwrap_or_default()    
        );

        let domain_size = usize::max(
            (max_data_len * blowup_factor).next_power_of_two(),
            frida_const::MIN_DOMAIN_SIZE,
        );

        let folding_factor = self.folding_factor();
        let bucket_count = domain_size / folding_factor;
        let bucket_size = poly_count * folding_factor;

        if domain_size > frida_const::MAX_DOMAIN_SIZE {
            return Err(FridaError::DomainSizeTooBig(domain_size));
        }
        if num_queries >= domain_size {
            return Err(FridaError::BadNumQueries(num_queries));
        }

        let mut evaluations = unsafe { uninit_vector(poly_count * domain_size) };
        for (i, data) in data_list.iter().enumerate() {
            build_evaluations_from_data::<E>(data, domain_size, blowup_factor)?
                .into_iter()
                .enumerate()
                .for_each(|(j, e)| {
                    let bucket = j % bucket_count;
                    let position = i + poly_count * (j / bucket_count);
                    evaluations[bucket * bucket_size + position] = e;
                });
        }

        #[cfg(feature = "bench")]
        unsafe {
            bench::ERASURE_TIME =
                Some(bench::ERASURE_TIME.unwrap_or_default() + bench::TIMER.unwrap().elapsed());
            bench::TIMER = Some(Instant::now());
        }

        if num_queries == 0 {
            let mut channel = C::new(domain_size, 1);
            self.build_layers_batched(&mut channel, evaluations, domain_size)?;
        } else {
            let mut channel = C::new(domain_size, num_queries);
            self.build_layers_batched(&mut channel, evaluations, domain_size)?;
            self.channel = Some(channel);
        }

        self.poly_count = poly_count;
        Ok(())
    }

    fn build_layers_from_data(
        &mut self,
        data: &[u8],
        num_queries: usize,
    ) -> Result<(), FridaError> {
        #[cfg(feature = "bench")]
        unsafe {
            bench::TIMER = Some(Instant::now());
        }

        // TODO: Decide if we want to dynamically set domain_size like here
        let blowup_factor = self.options.blowup_factor();
        let encoded_element_count = encoded_data_element_count::<E>(data.len());

        let domain_size = usize::max(
            encoded_element_count.next_power_of_two() * blowup_factor,
            frida_const::MIN_DOMAIN_SIZE,
        );

        if domain_size > frida_const::MAX_DOMAIN_SIZE {
            return Err(FridaError::DomainSizeTooBig(domain_size));
        }
        if num_queries >= domain_size {
            return Err(FridaError::BadNumQueries(num_queries));
        }

        let evaluations = build_evaluations_from_data(data, domain_size, blowup_factor)?;

        #[cfg(feature = "bench")]
        unsafe {
            bench::ERASURE_TIME =
                Some(bench::ERASURE_TIME.unwrap_or_default() + bench::TIMER.unwrap().elapsed());
            bench::TIMER = Some(Instant::now());
        }

        if num_queries == 0 {
            let mut channel = C::new(domain_size, 1);
            self.build_layers(&mut channel, evaluations, false);
        } else {
            let mut channel = C::new(domain_size, num_queries);
            self.build_layers(&mut channel, evaluations, false);
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

        #[cfg(feature = "bench")]
        unsafe {
            bench::COMMIT_TIME =
                Some(bench::COMMIT_TIME.unwrap_or_default() + bench::TIMER.unwrap().elapsed());
        }

        let channel = self.channel.take().unwrap();

        let commitment = Commitment {
            roots: channel.take_layer_commitments(),
            proof,
            domain_size: self.domain_size(),
            num_queries,
            poly_count: 1,
        };

        Ok((commitment, data))
    }

    pub fn commit_batch(
        &mut self,
        data: Vec<Vec<u8>>,
        num_queries: usize,
    ) -> Result<(Commitment<H>, Vec<Vec<u8>>), FridaError> {
        if num_queries == 0 {
            return Err(FridaError::BadNumQueries(num_queries));
        }
        self.build_layers_from_batched_data(&data, num_queries)?;
        let proof = self.query();

        #[cfg(feature = "bench")]
        unsafe {
            bench::COMMIT_TIME =
                Some(bench::COMMIT_TIME.unwrap_or_default() + bench::TIMER.unwrap().elapsed());
        }

        let channel = self.channel.take().unwrap();

        let commitment = Commitment {
            roots: channel.take_layer_commitments(),
            proof,
            domain_size: self.domain_size(),
            num_queries,
            poly_count: data.len(),
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
    pub fn parse_state_batched(&mut self, state: &[Vec<u8>]) -> Result<(), FridaError> {
        self.build_layers_from_batched_data(state, 0)
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
    use winter_fri::{folding::fold_positions, FriOptions, ProverChannel};
    use winter_math::fields::f128::BaseElement;
    use winter_rand_utils::{rand_value, rand_vector};

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
                FridaRandom<Blake3_256<BaseElement>, Blake3_256<BaseElement>, BaseElement>,
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
        let num_queries: usize = 31;
        let domain_size: usize = 32;
        let (commitment, state) = prover.commit(data.clone(), num_queries).unwrap();

        let evaluations = build_evaluations_from_data(&data, 32, 2).unwrap();
        let mut prover = FridaProver::new(options.clone());
        let mut channel = FridaProverChannel::<
            BaseElement,
            Blake3_256<BaseElement>,
            Blake3_256<BaseElement>,
            FridaRandom<Blake3_256<BaseElement>, Blake3_256<BaseElement>, BaseElement>,
        >::new(domain_size, num_queries);
        prover.build_layers(&mut channel, evaluations.clone(), false);
        let positions = channel.draw_query_positions();
        let proof = prover.build_proof(&positions);

        assert_eq!(
            commitment,
            Commitment {
                roots: channel.layer_commitments().to_vec(),
                proof: proof,
                domain_size,
                num_queries,
                poly_count: 1
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
                FridaRandom<Blake3_256<BaseElement>, Blake3_256<BaseElement>, BaseElement>,
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
                FridaRandom<Blake3_256<BaseElement>, Blake3_256<BaseElement>, BaseElement>,
            >,
            Blake3_256<BaseElement>,
        > = FridaProver::new(options.clone());
        opening_prover.parse_state(&state).unwrap();

        // Replicating query positions just to make sure open is generating proper proofs since we can just compare it with the query phase proofs
        let mut channel = FridaProverChannel::<
            BaseElement,
            Blake3_256<BaseElement>,
            Blake3_256<BaseElement>,
            FridaRandom<Blake3_256<BaseElement>, Blake3_256<BaseElement>, BaseElement>,
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

    #[test]
    fn test_batching() {
        let poly_count = 10;
        let mut data = vec![];
        for _ in 0..poly_count {
            data.push(rand_vector::<u8>(usize::min(
                rand_value::<u64>() as usize,
                1024,
            )));
        }

        let blowup_factor = 2;
        let folding_factor = 2;
        let options = FriOptions::new(blowup_factor, folding_factor, 0);
        let mut prover: FridaProver<
            BaseElement,
            BaseElement,
            FridaProverChannel<
                BaseElement,
                Blake3_256<BaseElement>,
                Blake3_256<BaseElement>,
                FridaRandom<Blake3_256<BaseElement>, Blake3_256<BaseElement>, BaseElement>,
            >,
            Blake3_256<BaseElement>,
        > = FridaProver::new(options.clone());
        let (commitment, state) = prover.commit_batch(data, 1).unwrap();

        let mut opening_prover: FridaProver<
            BaseElement,
            BaseElement,
            FridaProverChannel<
                BaseElement,
                Blake3_256<BaseElement>,
                Blake3_256<BaseElement>,
                FridaRandom<Blake3_256<BaseElement>, Blake3_256<BaseElement>, BaseElement>,
            >,
            Blake3_256<BaseElement>,
        > = FridaProver::new(options.clone());
        opening_prover.parse_state_batched(&state).unwrap();

        // Replicating query positions just to make sure open is generating proper proofs since we can just compare it with the query phase proofs
        let mut channel = FridaProverChannel::<
            BaseElement,
            Blake3_256<BaseElement>,
            Blake3_256<BaseElement>,
            FridaRandom<Blake3_256<BaseElement>, Blake3_256<BaseElement>, BaseElement>,
        >::new(prover.domain_size(), 1);
        for layer_root in commitment.roots.iter() {
            channel.commit_fri_layer(*layer_root);
        }
        let query_positions = fold_positions(
            &channel.draw_query_positions(),
            prover.domain_size(),
            folding_factor,
        );
        let mut opening_prover_query_proof = opening_prover.open(&query_positions);
        assert_eq!(commitment.proof, opening_prover_query_proof);

        let (_, merkle_proof) = opening_prover_query_proof
            .parse_batch_layer::<Blake3_256<BaseElement>, BaseElement>(
                prover.domain_size(),
                folding_factor,
                10,
            )
            .unwrap();
        MerkleTree::<Blake3_256<BaseElement>>::verify_batch(
            &commitment.roots[0],
            &query_positions,
            &merkle_proof,
        )
        .unwrap();

        commitment
            .proof
            .parse_layers::<Blake3_256<BaseElement>, BaseElement>(
                prover.domain_size(),
                folding_factor,
            )
            .unwrap();

        prover.reset();
        assert_eq!(
            FridaError::SinglePolyBatch,
            prover.commit_batch(vec![vec![]], 1).unwrap_err()
        );
    }
}
