use core::marker::PhantomData;

#[cfg(feature = "bench")]
use std::time::Instant;

use winter_crypto::{ElementHasher, Hasher, MerkleTree};
use winter_fri::folding::{apply_drp, fold_positions};
use winter_math::{fft, FieldElement, StarkField};

use winter_fri::FriOptions;
use winter_fri::utils::hash_values;

pub mod proof;
use proof::FridaProof;

#[cfg(feature = "concurrent")]
use winter_utils::iterators::*;
use winter_utils::{flatten_vector_elements, group_slice_elements, iter_mut, transpose_slice, uninit_vector};

use crate::{
    frida_const,
    frida_data::{build_evaluations_from_data, encoded_data_element_count},
    frida_error::FridaError,
    frida_prover_channel::BaseProverChannel,
};
use crate::frida_prover::proof::{FridaProofBatchLayer, FridaProofLayer};

pub struct FridaProverBuilder<B, E, H, C>
where
    B: StarkField,
    E: FieldElement<BaseField = B>,
    H: ElementHasher<BaseField = B>,
    C: BaseProverChannel<E, H>,
{
    options: FriOptions,
    _phantom_stark_field: PhantomData<B>,
    _phantom_field_element: PhantomData<E>,
    _phantom_channel: PhantomData<C>,
    _phantom_hasher: PhantomData<H>,
}

/// Prover configured to work with specific data.
#[derive(Debug)]
pub struct FridaProver<B, E, H, C>
where
    B: StarkField,
    E: FieldElement<BaseField = B>,
    H: ElementHasher<BaseField = B>,
    C: BaseProverChannel<E, H>,
{
    pub layers: Vec<FridaLayer<B, E, H>>,
    pub batch_layer: Option<BatchFridaLayer<B, E, H>>,
    pub remainder_poly: FridaRemainder<E>,
    folding_factor: usize,
    phantom_channel: PhantomData<C>,
}

#[derive(Debug)]
pub struct FridaLayer<B: StarkField, E: FieldElement<BaseField = B>, H: Hasher> {
    tree: MerkleTree<H>,
    pub evaluations: Vec<E>,
    _base_field: PhantomData<B>,
}

#[derive(Debug)]
pub struct BatchFridaLayer<B: StarkField, E: FieldElement<BaseField = B>, H: Hasher> {
    tree: MerkleTree<H>,
    pub evaluations: Vec<Vec<E>>,
    batch_size: usize,
    _base_field: PhantomData<B>,
}

#[derive(Debug, Clone)]
pub struct FridaRemainder<E: FieldElement>(Vec<E>);

#[derive(Debug, PartialEq)]
pub struct Commitment<HRoot: ElementHasher> {
    pub roots: Vec<HRoot::Digest>,
    pub proof: FridaProof,
    // In a real protocol, domain size will likely be predefined and won't be part of a block.
    pub domain_size: usize,
    pub num_queries: usize,
    pub batch_size: usize,
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

impl<B, E, H, C> FridaProver<B, E, H, C>
where
    B: StarkField,
    E: FieldElement<BaseField = B>,
    H: ElementHasher<BaseField = B>,
    C: BaseProverChannel<E, H>,
{
    pub fn domain_size(&self) -> usize {
        self.layers[0].evaluations.len()
    }

    /// Commits to the evaluated data, consuming the channel constructed along with this prover.
    pub fn commit(
        &self,
        mut channel: C,
    ) -> Result<Commitment<H>, FridaError> {
        let query_positions = channel.draw_query_positions();
        let proof = self.open(&query_positions);

        #[cfg(feature = "bench")]
        unsafe {
            bench::COMMIT_TIME =
                Some(bench::COMMIT_TIME.unwrap_or_default() + bench::TIMER.unwrap().elapsed());
        }

        let commitment = Commitment {
            roots: channel.layer_commitments().to_vec(),
            proof,
            domain_size: self.domain_size(),
            num_queries: channel.num_queries(),
            batch_size: self.batch_layer.as_ref().map(|bl| bl.batch_size).unwrap_or_default(),
        };

        Ok(commitment)
    }

    /// Opens given position, building a proof for it.
    pub fn open(&self, positions: &[usize]) -> FridaProof {
        let folding_factor = self.folding_factor;
        let domain_size = self.domain_size();
        let layers_len = self.layers.len();
        let mut layers = Vec::with_capacity(layers_len);

        // TODO: Is it possible?
        if layers_len != 0 {
            let mut positions = positions.to_vec();
            let mut domain_size = domain_size;

            // for all FRI layers, except the last one, record tree root, determine a set of query
            // positions, and query the layer at these positions.
            for i in 0..layers_len {
                positions = fold_positions(&positions, domain_size, folding_factor);

                let layer = &self.layers[i];
                // sort of a static dispatch for folding_factor parameter
                let proof_layer = match folding_factor {
                    2 => query_layer::<B, E, H, 2>(layer, &positions),
                    4 => query_layer::<B, E, H, 4>(layer, &positions),
                    8 => query_layer::<B, E, H, 8>(layer, &positions),
                    16 => query_layer::<B, E, H, 16>(layer, &positions),
                    _ => unimplemented!("folding factor {} is not supported", folding_factor),
                };

                layers.push(proof_layer);
                domain_size /= folding_factor;
            }
        }

        // use the remaining polynomial values directly as proof
        let remainder = self.remainder_poly.0.clone();

        let batch_layer = self.batch_layer.as_ref().map(|batch_layer| {
            let positions = fold_positions(&positions, domain_size, folding_factor);
            let proof = batch_layer
                .tree
                .prove_batch(&positions)
                .expect("failed to generate a Merkle proof for FRI layer queries");
            let mut queried_values: Vec<&Vec<E>> = Vec::with_capacity(positions.len());
            for &position in positions.iter() {
                queried_values.push(&batch_layer.evaluations[position]);
            }
            FridaProofBatchLayer::new(queried_values, proof)
        });

        FridaProof::new(batch_layer, layers, remainder, 1)
    }
}

impl<B, E, H, C> FridaProverBuilder<B, E, H, C>
where
    B: StarkField,
    E: FieldElement<BaseField = B>,
    H: ElementHasher<BaseField = B>,
    C: BaseProverChannel<E, H>,
{
    pub fn new(options: FriOptions) -> Self {
        FridaProverBuilder {
            options,
            _phantom_channel: Default::default(),
            _phantom_field_element: Default::default(),
            _phantom_stark_field: Default::default(),
            _phantom_hasher: Default::default(),
        }
    }

    /// Builds a prover for a specific batched data, along with a channel that should be used for commitment.
    pub fn build_batched_prover(
        &self,
        data_list: &[Vec<u8>],
        num_queries: usize,
    ) -> Result<(FridaProver<B, E, H, C>, C), FridaError> {
        #[cfg(feature = "bench")]
        unsafe {
            bench::TIMER = Some(Instant::now());
        }

        if num_queries == 0 {
            return Err(FridaError::BadNumQueries(num_queries));
        }

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
        let folding_factor = self.options.folding_factor();
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

        #[cfg(feature = "bench")]
        unsafe {
            bench::ERASURE_TIME =
                Some(bench::ERASURE_TIME.unwrap_or_default() + bench::TIMER.unwrap().elapsed());
            bench::TIMER = Some(Instant::now());
        }

        let mut channel = C::new(domain_size, num_queries);

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

        let mut prover = self.build_layers(&mut channel, final_eval);
        prover.batch_layer = Some(BatchFridaLayer {
            tree: evaluation_tree,
            evaluations: evaluations,
            batch_size,
            _base_field: PhantomData,
        });

        Ok((prover, channel))
    }

    /// Builds a prover for a specific data, along with a channel that should be used for commitment.
    pub fn build_prover(
        &self,
        data: &[u8],
        num_queries: usize,
    ) -> Result<(FridaProver<B, E, H, C>, C), FridaError> {
        #[cfg(feature = "bench")]
        unsafe {
            bench::TIMER = Some(Instant::now());
        }

        if num_queries == 0 {
            return Err(FridaError::BadNumQueries(num_queries));
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

        let evaluations = build_evaluations_from_data(&data, domain_size, blowup_factor)?;

        #[cfg(feature = "bench")]
        unsafe {
            bench::ERASURE_TIME =
                Some(bench::ERASURE_TIME.unwrap_or_default() + bench::TIMER.unwrap().elapsed());
            bench::TIMER = Some(Instant::now());
        }

        let mut channel = C::new(domain_size, num_queries);
        let prover = self.build_layers(&mut channel, evaluations);

        Ok((prover, channel))
    }

    fn build_layers(&self, channel: &mut C, evaluations: Vec<E>) -> FridaProver<B, E, H, C> {
        // reduce the degree by folding_factor at each iteration until the remaining polynomial
        // has small enough degree
        let mut evaluations = evaluations;
        let domain_size = evaluations.len();
        let num_fri_layers = self.options.num_fri_layers(domain_size);
        let mut layers = Vec::with_capacity(num_fri_layers);
        for _ in 0..num_fri_layers {
            let (new_evaluations, frida_layer) = match self.options.folding_factor() {
                2 => self.build_layer::<2>(channel, &evaluations),
                4 => self.build_layer::<4>(channel, &evaluations),
                8 =>  self.build_layer::<8>(channel, &evaluations),
                16 => self.build_layer::<16>(channel, &evaluations),
                _ => unimplemented!("folding factor {} is not supported", self.options.folding_factor()),
            };
            layers.push(frida_layer);
            evaluations = new_evaluations;
        }

        let remainder_poly = self.build_remainder(channel, &mut evaluations);
        FridaProver {
            layers,
            batch_layer: None,
            remainder_poly,
            folding_factor: self.options.folding_factor(),
            phantom_channel: Default::default(),
        }
    }

    #[cfg(test)]
    pub fn test_build_layers(&self, channel: &mut C, evaluations: Vec<E>) -> FridaProver<B, E, H, C> {
        self.build_layers(channel, evaluations)
    }

    /// Builds a single FRI layer by first committing to the `evaluations`, then drawing a random
    /// alpha from the channel and use it to perform degree-respecting projection.
    fn build_layer<const N: usize>(&self, channel: &mut C, evaluations: &[E]) -> (Vec<E>, FridaLayer<B, E, H>) {
        // commit to the evaluations at the current layer; we do this by first transposing the
        // evaluations into a matrix of N columns, and then building a Merkle tree from the
        // rows of this matrix; we do this so that we could de-commit to N values with a single
        // Merkle authentication path.
        let transposed_evaluations = transpose_slice(evaluations);
        let hashed_evaluations = hash_values::<H, E, N>(&transposed_evaluations);

        let evaluation_tree =
            MerkleTree::<H>::new(hashed_evaluations).expect("failed to construct FRI layer tree");
        channel.commit_fri_layer(*evaluation_tree.root());

        // draw a pseudo-random coefficient from the channel, and use it in degree-respecting
        // projection to reduce the degree of evaluations by N
        let alpha = channel.draw_fri_alpha();
        let evaluations = apply_drp(&transposed_evaluations, self.options.domain_offset(), alpha);
        (evaluations, FridaLayer {
            tree: evaluation_tree,
            evaluations: flatten_vector_elements(transposed_evaluations),
            _base_field: PhantomData,
        })
    }

    /// Creates remainder polynomial in coefficient form from a vector of `evaluations` over a domain.
    fn build_remainder(&self, channel: &mut C, evaluations: &mut [E]) -> FridaRemainder<E> {
        let inv_twiddles = fft::get_inv_twiddles(evaluations.len());
        fft::interpolate_poly_with_offset(
            evaluations,
            &inv_twiddles,
            self.options.domain_offset(),
        );
        let remainder_poly_size = evaluations.len() / self.options.blowup_factor();
        let remainder_poly = evaluations[..remainder_poly_size].to_vec();
        let commitment = <H as ElementHasher>::hash_elements(&remainder_poly);
        channel.commit_fri_layer(commitment);

        FridaRemainder(remainder_poly)
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
        let prover_builder: FridaProverBuilder<
            BaseElement,
            BaseElement,
            Blake3_256<BaseElement>,
            FridaProverChannel<
                BaseElement,
                Blake3_256<BaseElement>,
                Blake3_256<BaseElement>,
                FridaRandom<Blake3_256<BaseElement>, Blake3_256<BaseElement>, BaseElement>,
            >,
        > = FridaProverBuilder::new(options.clone());

        let domain_error = prover_builder
            .build_prover(&[0; frida_const::MAX_DOMAIN_SIZE * 15 / 2 + 1], 1)
            .unwrap_err();
        assert_eq!(
            FridaError::DomainSizeTooBig(frida_const::MAX_DOMAIN_SIZE * 2),
            domain_error
        );

        let num_qeuries_error_zero = prover_builder.build_prover(&rand_vector::<u8>(10), 0).unwrap_err();
        assert_eq!(FridaError::BadNumQueries(0), num_qeuries_error_zero);

        let num_qeuries_error_bigger_than_domain =
            prover_builder.build_prover(&rand_vector::<u8>(200), 32).unwrap_err();
        assert_eq!(
            FridaError::BadNumQueries(32),
            num_qeuries_error_bigger_than_domain
        );

        // Make sure minimum domain size is correctly enforced
        let (prover, channel) =
            prover_builder.build_prover(&rand_vector::<u8>(1), 1).unwrap();
        let commitment = prover.commit(channel).unwrap();
        assert_eq!(
            frida_const::MIN_DOMAIN_SIZE.ilog2() as usize,
            commitment.roots.len()
        );

        let data = rand_vector::<u8>(200);
        let num_queries: usize = 31;
        let domain_size: usize = 32;
        let (prover, channel) =
            prover_builder.build_prover(&data, num_queries).unwrap();
        let commitment = prover.commit(channel).unwrap();

        let evaluations = build_evaluations_from_data(&data, 32, 2).unwrap();
        let prover = FridaProverBuilder::new(options.clone());
        let mut channel = FridaProverChannel::<
            BaseElement,
            Blake3_256<BaseElement>,
            Blake3_256<BaseElement>,
            FridaRandom<Blake3_256<BaseElement>, Blake3_256<BaseElement>, BaseElement>,
        >::new(domain_size, num_queries);
        let prover = prover.build_layers(&mut channel, evaluations);
        let positions = channel.draw_query_positions();
        let proof = prover.open(&positions);

        assert_eq!(
            commitment,
            Commitment {
                roots: channel.layer_commitments().to_vec(),
                proof: proof,
                domain_size,
                num_queries,
                batch_size: 0
            }
        );
    }

    #[test]
    fn test_open() {
        let options = FriOptions::new(2, 2, 0);
        let prover_builder: FridaProverBuilder<
            BaseElement,
            BaseElement,
            Blake3_256<BaseElement>,
            FridaProverChannel<
                BaseElement,
                Blake3_256<BaseElement>,
                Blake3_256<BaseElement>,
                FridaRandom<Blake3_256<BaseElement>, Blake3_256<BaseElement>, BaseElement>,
            >,
        > = FridaProverBuilder::new(options.clone());

        let data = rand_vector::<u8>(200);
        let (prover, channel) = prover_builder.build_prover(&data, 31).unwrap();
        let commitment = prover.commit(channel).unwrap();

        let opening_prover: FridaProverBuilder<
            BaseElement,
            BaseElement,
            Blake3_256<BaseElement>,
            FridaProverChannel<
                BaseElement,
                Blake3_256<BaseElement>,
                Blake3_256<BaseElement>,
                FridaRandom<Blake3_256<BaseElement>, Blake3_256<BaseElement>, BaseElement>,
            >,
        > = FridaProverBuilder::new(options.clone());
        let (prover, _channel) = opening_prover.build_prover(&data, 1).unwrap();

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

        let opening_prover_query_proof = prover.open(&query_positions);
        assert_eq!(commitment.proof, opening_prover_query_proof);

        // Make sure prover that has ran commit can also just use open for creating more proofs
        let prover_proof = prover.open(&[1, 0, 3]);
        let opening_prover_proof = prover.open(&[1, 0, 3]);
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
        let prover_builder: FridaProverBuilder<
            BaseElement,
            BaseElement,
            Blake3_256<BaseElement>,
            FridaProverChannel<
                BaseElement,
                Blake3_256<BaseElement>,
                Blake3_256<BaseElement>,
                FridaRandom<Blake3_256<BaseElement>, Blake3_256<BaseElement>, BaseElement>,
            >,
        > = FridaProverBuilder::new(options.clone());
        let (prover, channel) = prover_builder.build_batched_prover(&data, 1).unwrap();
        let commitment = prover.commit(channel).unwrap();

        let opening_prover: FridaProverBuilder<
            BaseElement,
            BaseElement,
            Blake3_256<BaseElement>,
            FridaProverChannel<
                BaseElement,
                Blake3_256<BaseElement>,
                Blake3_256<BaseElement>,
                FridaRandom<Blake3_256<BaseElement>, Blake3_256<BaseElement>, BaseElement>,
            >,
        > = FridaProverBuilder::new(options.clone());
        let (opening_prover, _channel) = opening_prover.build_batched_prover(&data, 1).unwrap();

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

// HELPER FUNCTIONS
// ================================================================================================

/// Builds a single proof layer by querying the evaluations of the passed in FRI layer at the
/// specified positions.
fn query_layer<B: StarkField, E: FieldElement<BaseField = B>, H: Hasher, const N: usize>(
    layer: &FridaLayer<B, E, H>,
    positions: &[usize],
) -> FridaProofLayer {
    // build Merkle authentication paths for all query positions
    let proof = layer
        .tree
        .prove_batch(positions)
        .expect("failed to generate a Merkle proof for FRI layer queries");

    // build a list of polynomial evaluations at each position; since evaluations in FRI layers
    // are stored in transposed form, a position refers to N evaluations which are committed
    // in a single leaf
    let evaluations: &[[E; N]] = group_slice_elements(&layer.evaluations);
    let mut queried_values: Vec<[E; N]> = Vec::with_capacity(positions.len());
    for &position in positions.iter() {
        queried_values.push(evaluations[position]);
    }

    FridaProofLayer::new(queried_values, proof)
}
