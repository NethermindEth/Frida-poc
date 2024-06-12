use core::marker::PhantomData;

use traits::BaseFriProver;
use winter_crypto::{ElementHasher, Hasher, MerkleTree};
use winter_math::{FieldElement, StarkField};

use winter_fri::FriOptions;

pub mod proof;
pub mod traits;
use proof::FridaProof;
use winter_utils::{iter_mut, uninit_vector};

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
    batch_layer: Option<BatchFridaLayer<B, E, H>>,
    layers: Vec<FridaLayer<B, E, H>>,
    remainder_poly: FridaRemainder<E>,
    channel: Option<C>,
}

pub struct FridaLayer<B: StarkField, E: FieldElement<BaseField = B>, H: Hasher> {
    tree: MerkleTree<H>,
    evaluations: Vec<E>,
    _base_field: PhantomData<B>,
}

pub struct BatchFridaLayer<B: StarkField, E: FieldElement<BaseField = B>, H: Hasher> {
    tree: MerkleTree<H>,
    pub(crate) evaluations: Vec<Vec<E>>,
    _base_field: PhantomData<B>,
}

pub struct FridaRemainder<E: FieldElement>(Vec<E>);

#[derive(Debug, PartialEq)]
pub struct Commitment<HRoot: ElementHasher> {
    pub roots: Vec<HRoot::Digest>,
    pub proof: FridaProof,
    pub num_queries: usize,
    pub batch_size: usize,
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
            batch_layer: None,
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
    fn get_batch_layer(&self) -> &Option<BatchFridaLayer<B, E, H>> {
        &self.batch_layer
    }

    fn set_remainer_poly(&mut self, remainder: FridaRemainder<E>) {
        self.remainder_poly = remainder;
    }

    fn is_batch(&self) -> bool {
        !self.batch_layer.is_none()
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
        let batch_size = data_list.len();
        let blowup_factor = self.options.blowup_factor();
        let mut max_data_len = 0;
        data_list.iter().for_each(|data| {
            max_data_len = usize::max(encoded_data_element_count::<E>(data.len()), max_data_len);
        });

        let domain_size = usize::max(
            (max_data_len * blowup_factor).next_power_of_two(),
            frida_const::MIN_DOMAIN_SIZE,
        );
        let folding_factor = self.folding_factor();
        let bucket_count = domain_size / folding_factor;

        if domain_size > frida_const::MAX_DOMAIN_SIZE {
            return Err(FridaError::DomainSizeTooBig(domain_size));
        }
        if num_queries >= domain_size {
            return Err(FridaError::BadNumQueries(num_queries));
        }

        let mut evaluations = vec![
            unsafe { uninit_vector(batch_size * folding_factor) };
            domain_size / folding_factor
        ];

        for (i, data) in data_list.iter().enumerate() {
            build_evaluations_from_data::<E>(data, domain_size, blowup_factor)?
                .into_iter()
                .enumerate()
                .for_each(|(j, e)| {
                    evaluations[j % bucket_count][batch_size * (j / bucket_count) + i] = e;
                });
        }

        let mut channel = if num_queries == 0 {
            C::new(domain_size, 1)
        } else {
            C::new(domain_size, num_queries)
        };

        let len = evaluations.len();
        let mut hashed_evaluations: Vec<H::Digest> = unsafe { uninit_vector(len) };
        iter_mut!(hashed_evaluations, 1024)
            .zip(&evaluations)
            .for_each(|(r, v)| {
                *r = H::hash_elements(v);
            });
        let evaluation_tree =
            MerkleTree::<H>::new(hashed_evaluations).expect("failed to construct FRI layer tree");

        channel.commit_fri_layer(*evaluation_tree.root());
        let xi = channel.draw_xi(batch_size)?;
        let mut final_eval = unsafe { uninit_vector(domain_size) };
        iter_mut!(final_eval, 1024).enumerate().for_each(|(i, f)| {
            *f = E::default();
            let start = batch_size * (i / bucket_count);
            evaluations[i % bucket_count][start..start + batch_size]
                .iter()
                .enumerate()
                .for_each(|(j, e)| {
                    *f += *e * xi[j];
                });
        });

        self.batch_layer = Some(BatchFridaLayer {
            tree: evaluation_tree,
            evaluations: evaluations,
            _base_field: PhantomData,
        });
        self.build_layers(&mut channel, final_eval);

        if num_queries != 0 {
            self.channel = Some(channel);
        }
        Ok(())
    }

    fn build_layers_from_data(
        &mut self,
        data: &[u8],
        num_queries: usize,
    ) -> Result<(), FridaError> {
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
            num_queries,
            batch_size: 0,
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
        let channel = self.channel.take().unwrap();

        let commitment = Commitment {
            roots: channel.take_layer_commitments(),
            proof,
            num_queries,
            batch_size: data.len(),
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
        let (commitment, state) = prover.commit(data.clone(), num_queries).unwrap();

        let evaluations = build_evaluations_from_data(&data, 32, 2).unwrap();
        let mut prover = FridaProver::new(options.clone());
        let mut channel = FridaProverChannel::<
            BaseElement,
            Blake3_256<BaseElement>,
            Blake3_256<BaseElement>,
            FridaRandom<Blake3_256<BaseElement>, Blake3_256<BaseElement>, BaseElement>,
        >::new(32, num_queries);
        prover.build_layers(&mut channel, evaluations.clone());
        let positions = channel.draw_query_positions();
        let proof = prover.build_proof(&positions);

        assert_eq!(
            commitment,
            Commitment {
                roots: channel.layer_commitments().to_vec(),
                proof: proof,
                num_queries,
                batch_size: 0
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
        let batch_size = 10;
        let mut data = vec![];
        for _ in 0..batch_size {
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
        channel.commit_fri_layer(commitment.roots[0]);
        let xi = channel.draw_xi(batch_size).unwrap();

        // Sanity checks
        for i in 0..prover.domain_size() {
            assert_eq!(
                opening_prover.layers[0].evaluations[i],
                prover.batch_layer.as_ref().unwrap().evaluations[i / folding_factor]
                    .iter()
                    .skip(i % folding_factor * batch_size)
                    .take(batch_size)
                    .enumerate()
                    .fold(BaseElement::default(), |accum, (j, e)| {
                        accum + xi[j] * *e
                    })
            );
        }

        for layer_root in commitment.roots[1..].iter() {
            channel.commit_fri_layer(*layer_root);
        }
        let query_positions = fold_positions(
            &channel.draw_query_positions(),
            prover.domain_size(),
            folding_factor,
        );
        let mut opening_prover_query_proof = opening_prover.open(&query_positions);
        assert_eq!(commitment.proof, opening_prover_query_proof);

        let (values, merkle_proof) = opening_prover_query_proof
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

        let (layers, _) = commitment
            .proof
            .parse_layers::<Blake3_256<BaseElement>, BaseElement>(
                prover.domain_size(),
                folding_factor,
            )
            .unwrap();

        for (i, value) in layers[0].iter().enumerate() {
            assert_eq!(
                *value,
                values[0]
                    .iter()
                    .skip(i * batch_size)
                    .take(batch_size)
                    .enumerate()
                    .fold(BaseElement::default(), |accumulator, (j, val)| {
                        accumulator + xi[j] * *val
                    })
            )
        }
    }
}
