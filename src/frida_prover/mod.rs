use core::marker::PhantomData;
#[cfg(feature = "bench")]
use std::time::Instant;

use winter_crypto::{ElementHasher, Hasher, MerkleTree};
use winter_fri::folding;
use winter_fri::utils::hash_values;
use winter_fri::{FriOptions, ProverChannel};
use winter_math::{fft, FieldElement};
#[cfg(feature = "concurrent")]
use winter_utils::iterators::*;
use winter_utils::{
    flatten_vector_elements, group_slice_elements, iter_mut, transpose_slice, uninit_vector,
    ByteReader, Deserializable, DeserializationError, Serializable,
};

use channel::FridaProverChannel;
use proof::FridaProof;

use crate::{
    frida_const,
    frida_data::{build_evaluations_from_data, encoded_data_element_count},
    frida_error::FridaError,
    frida_prover::proof::{FridaProofBatchLayer, FridaProofLayer},
};

// Channel is only exposed to tests
#[cfg(any(test, feature = "cli"))]
pub mod channel;

#[cfg(not(any(test, feature = "cli")))]
mod channel;

pub mod proof;

pub struct FridaProverBuilder<E, H>
where
    E: FieldElement,
    H: ElementHasher<BaseField = E::BaseField>,
{
    pub options: FriOptions,
    _phantom_field_element: PhantomData<E>,
    _phantom_hasher: PhantomData<H>,
}

/// Prover configured to work with specific data.
#[derive(Debug)]
pub struct FridaProver<E, H>
where
    E: FieldElement,
    H: ElementHasher<BaseField = E::BaseField>,
{
    layers: Vec<FridaLayer<E, H>>,
    poly_count: usize,
    remainder_poly: FridaRemainder<E>,
    domain_size: usize,
    folding_factor: usize,
}

#[derive(Debug)]
pub struct FridaLayer<E, H>
where
    E: FieldElement,
    H: ElementHasher<BaseField = E::BaseField>,
{
    tree: MerkleTree<H>,
    pub evaluations: Vec<E>,
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
    pub poly_count: usize,
}

/// A commitment to the data, containing only the Merkle roots and metadata.
/// It does NOT contain a proof itself.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ProverCommitment<H: Hasher> {
    pub roots: Vec<H::Digest>,
    pub domain_size: usize,
    pub poly_count: usize,
}

impl<H: Hasher> Serializable for ProverCommitment<H>
where
    H::Digest: Serializable,
{
    fn write_into<W: winter_utils::ByteWriter>(&self, target: &mut W) {
        self.roots.write_into(target);
        self.domain_size.write_into(target);
        self.poly_count.write_into(target);
    }
}

impl<H: Hasher> Deserializable for ProverCommitment<H>
where
    H::Digest: Deserializable,
{
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let roots = Vec::<H::Digest>::read_from(source)?;
        let domain_size = usize::read_from(source)?;
        let poly_count = usize::read_from(source)?;

        Ok(ProverCommitment {
            roots,
            domain_size,
            poly_count,
        })
    }
}

impl<HRoot: ElementHasher> Serializable for Commitment<HRoot>
where
    HRoot::Digest: Serializable,
{
    fn write_into<W: winter_utils::ByteWriter>(&self, target: &mut W) {
        self.roots.write_into(target);
        self.proof.write_into(target);
        self.domain_size.write_into(target);
        self.num_queries.write_into(target);
        self.poly_count.write_into(target);
    }

    fn get_size_hint(&self) -> usize {
        // 24 + 104 + 8 + 8 + 8
        152
    }
}

impl<HRoot: ElementHasher> Deserializable for Commitment<HRoot>
where
    HRoot::Digest: Deserializable,
{
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let roots = Vec::<HRoot::Digest>::read_from(source)?;
        let proof = FridaProof::read_from(source)?;
        let domain_size = usize::read_from(source)?;
        let num_queries = usize::read_from(source)?;
        let poly_count = usize::read_from(source)?;

        Ok(Commitment {
            roots,
            proof,
            domain_size,
            num_queries,
            poly_count,
        })
    }
}

#[cfg(feature = "bench")]
pub mod bench {
    use std::time::{Duration, Instant};

    pub static mut TIMER: Option<Instant> = None;
    pub static mut ERASURE_TIME: Option<Duration> = None;
    pub static mut COMMIT_TIME: Option<Duration> = None;
}

type Channel<E, H> = FridaProverChannel<E, H, H>;

// PROVER IMPLEMENTATION
// ================================================================================================

impl<E, H> FridaProver<E, H>
where
    E: FieldElement,
    H: ElementHasher<BaseField = E::BaseField>,
{
    /// Opens given position, building a proof for it.
    pub fn open(&self, positions: &[usize]) -> FridaProof {
        let folding_factor = self.folding_factor;
        let layers_len = self.layers.len();
        let is_batch = self.poly_count > 1;

        let (layers, batch_layer) = {
            let mut positions = positions.to_vec();
            let mut domain_size = self.domain_size;

            let batch_layer = if is_batch {
                positions = folding::fold_positions(&positions, domain_size, folding_factor);
                let proof = self.layers[0]
                    .tree
                    .prove_batch(&positions)
                    .expect("failed to generate a Merkle proof for FRI layer queries");
                let evaluations = &self.layers[0].evaluations;
                let bucket_size = self.poly_count * folding_factor;
                let mut queried_values: Vec<E> = Vec::with_capacity(positions.len() * bucket_size);
                for &position in positions.iter() {
                    evaluations[bucket_size * position..bucket_size * position + bucket_size]
                        .iter()
                        .for_each(|e| {
                            queried_values.push(*e);
                        });
                }
                domain_size /= folding_factor;
                Some(FridaProofBatchLayer::new(queried_values, proof))
            } else {
                None
            };

            // for all FRI layers, except the last one, record tree root, determine a set of query
            // positions, and query the layer at these positions.
            let start = if is_batch { 1 } else { 0 };
            let layers = (start..layers_len)
                .map(|i| {
                    positions = folding::fold_positions(&positions, domain_size, folding_factor);

                    let layer = &self.layers[i];
                    // sort of a static dispatch for folding_factor parameter
                    let proof_layer = match folding_factor {
                        2 => query_layer::<E, H, 2>(layer, &positions),
                        4 => query_layer::<E, H, 4>(layer, &positions),
                        8 => query_layer::<E, H, 8>(layer, &positions),
                        16 => query_layer::<E, H, 16>(layer, &positions),
                        _ => unimplemented!("folding factor {} is not supported", folding_factor),
                    };

                    domain_size /= folding_factor;
                    proof_layer
                })
                .collect::<Vec<_>>();
            (layers, batch_layer)
        };

        // use the remaining polynomial values directly as proof
        let remainder = self.remainder_poly.0.clone();
        FridaProof::new(batch_layer, layers, remainder, 1)
    }

    pub fn get_first_layer_evalutaions(&self) -> &[E] {
        &self.layers[0].evaluations
    }
}

impl<E, H> FridaProverBuilder<E, H>
where
    E: FieldElement,
    H: ElementHasher<BaseField = E::BaseField>,
{
    pub fn new(options: FriOptions) -> Self {
        FridaProverBuilder {
            options,
            _phantom_field_element: PhantomData,
            _phantom_hasher: PhantomData,
        }
    }

    /// Builds a prover for a specific batched data, along with a channel that should be used for commitment.
    pub fn commit_batch(
        &self,
        data_list: &[Vec<u8>],
        num_queries: usize,
    ) -> Result<(Commitment<H>, FridaProver<E, H>), FridaError> {
        let (channel, prover) = self.prepare_prover_state_batch(data_list, num_queries)?;

        let commitment = self.build_commitment(&prover, channel)?;
        Ok((commitment, prover))
    }

    pub fn calculate_commitment_batch(
        &self,
        data_list: &[Vec<u8>],
    ) -> Result<(ProverCommitment<H>, FridaProver<E, H>), FridaError> {
        let (channel, prover) = self.prepare_prover_state_batch(data_list, 1)?;

        let commitment = ProverCommitment {
            roots: channel.commitments,
            domain_size: prover.domain_size,
            poly_count: prover.poly_count,
        };

        Ok((commitment, prover))
    }

    fn prepare_prover_state_batch(
        &self,
        data_list: &[Vec<u8>],
        num_queries: usize,
    ) -> Result<(Channel<E, H>, FridaProver<E, H>), FridaError> {
        #[cfg(feature = "bench")]
        unsafe {
            bench::TIMER = Some(Instant::now());
        }

        if num_queries == 0 {
            return Err(FridaError::BadNumQueries(num_queries));
        }

        let poly_count = data_list.len();
        if poly_count <= 1 {
            return Err(FridaError::SinglePolyBatch);
        }

        let blowup_factor = self.options.blowup_factor();

        let max_data_len = encoded_data_element_count::<E>(
            data_list
                .iter()
                .map(|data| data.len())
                .max()
                .unwrap_or_default(),
        );

        let domain_size = usize::max(
            (max_data_len * blowup_factor).next_power_of_two(),
            frida_const::MIN_DOMAIN_SIZE,
        );

        let folding_factor = self.options.folding_factor();

        if domain_size > frida_const::MAX_DOMAIN_SIZE {
            return Err(FridaError::DomainSizeTooBig(domain_size));
        }
        if num_queries >= domain_size {
            return Err(FridaError::BadNumQueries(num_queries));
        }
        if self.options.num_fri_layers(domain_size) == 0 {
            // Verification currently cannot work without FRI layers
            return Err(FridaError::NotEnoughDataPoints());
        }

        let evaluations = batch_data_to_evaluations::<E>(
            data_list,
            poly_count,
            domain_size,
            blowup_factor,
            folding_factor,
        )?;

        #[cfg(feature = "bench")]
        unsafe {
            bench::ERASURE_TIME =
                Some(bench::ERASURE_TIME.unwrap_or_default() + bench::TIMER.unwrap().elapsed());
            bench::TIMER = Some(Instant::now());
        }

        let mut channel = Channel::<E, H>::new(domain_size, num_queries);
        let prover = self.build_layers_batched(&mut channel, evaluations, domain_size)?;

        Ok((channel, prover))
    }

    /// It calculates the domain size and generates the initial evaluations.
    fn prepare_prover_state(
        &self,
        data: &[u8],
        num_queries: usize,
    ) -> Result<(Channel<E, H>, FridaProver<E, H>), FridaError> {
        if num_queries == 0 {
            return Err(FridaError::BadNumQueries(num_queries));
        }

        let blowup_factor = self.options.blowup_factor();
        let encoded_element_count = encoded_data_element_count::<E>(data.len());

        let domain_size = usize::max(
            encoded_element_count.next_power_of_two() * blowup_factor,
            frida_const::MIN_DOMAIN_SIZE,
        );

        if domain_size > frida_const::MAX_DOMAIN_SIZE {
            return Err(FridaError::DomainSizeTooBig(domain_size));
        }

        let evaluations = build_evaluations_from_data(data, domain_size, blowup_factor)?;

        if num_queries >= domain_size {
            return Err(FridaError::BadNumQueries(num_queries));
        }
        if self.options.num_fri_layers(domain_size) == 0 {
            return Err(FridaError::NotEnoughDataPoints());
        }

        let mut channel = Channel::<E, H>::new(domain_size, num_queries);
        let prover = self.build_layers(&mut channel, evaluations, 1, None);
        Ok((channel, prover))
    }

    /// Builds a prover for a specific data, along with a channel that should be used for commitment.
    pub fn commit(
        &self,
        data: &[u8],
        num_queries: usize,
    ) -> Result<(Commitment<H>, FridaProver<E, H>), FridaError> {
        let (channel, prover) = self.prepare_prover_state(data, num_queries)?;

        let commitment = self.build_commitment(&prover, channel)?;
        Ok((commitment, prover))
    }

    /// Commits to the evaluated data, consuming the channel constructed along with this prover.
    pub fn build_commitment(
        &self,
        prover: &FridaProver<E, H>,
        mut channel: Channel<E, H>,
    ) -> Result<Commitment<H>, FridaError> {
        let query_positions = channel.draw_query_positions();
        let proof = prover.open(&query_positions);

        #[cfg(feature = "bench")]
        unsafe {
            bench::COMMIT_TIME =
                Some(bench::COMMIT_TIME.unwrap_or_default() + bench::TIMER.unwrap().elapsed());
        }

        let num_queries = channel.num_queries;

        let commitment = Commitment {
            roots: channel.commitments,
            proof,
            domain_size: prover.domain_size,
            num_queries,
            poly_count: prover.poly_count,
        };

        Ok(commitment)
    }

    fn build_layers_batched(
        &self,
        channel: &mut Channel<E, H>,
        evaluations: Vec<E>,
        domain_size: usize,
    ) -> Result<FridaProver<E, H>, FridaError> {
        let poly_count = evaluations.len() / domain_size;
        let folding_factor = self.options.folding_factor();
        let bucket_count = domain_size / folding_factor;
        let bucket_size = poly_count * folding_factor;

        let mut hashed_evaluations: Vec<H::Digest> = unsafe { uninit_vector(bucket_count) };
        iter_mut!(hashed_evaluations, 1024)
            .enumerate()
            .for_each(|(i, r)| {
                *r = H::hash_elements(&evaluations[i * bucket_size..i * bucket_size + bucket_size]);
            });
        let evaluation_tree =
            MerkleTree::<H>::new(hashed_evaluations).expect("failed to construct FRI layer tree");
        channel.commit_fri_layer(*evaluation_tree.root());

        let xi = channel.draw_xi(poly_count)?;
        let alpha = channel.draw_fri_alpha();
        let second_layer = match folding_factor {
            2 => apply_drp_batched::<_, 2>(&evaluations, poly_count, &self.options, xi, alpha),
            4 => apply_drp_batched::<_, 4>(&evaluations, poly_count, &self.options, xi, alpha),
            8 => apply_drp_batched::<_, 8>(&evaluations, poly_count, &self.options, xi, alpha),
            16 => apply_drp_batched::<_, 16>(&evaluations, poly_count, &self.options, xi, alpha),
            _ => unimplemented!("folding factor {} is not supported", folding_factor),
        };

        Ok(self.build_layers(
            channel,
            second_layer,
            poly_count,
            Some(FridaLayer {
                tree: evaluation_tree,
                evaluations,
            }),
        ))
    }

    fn build_layers(
        &self,
        channel: &mut Channel<E, H>,
        evaluations: Vec<E>,
        poly_count: usize,
        batch_layer: Option<FridaLayer<E, H>>,
    ) -> FridaProver<E, H> {
        let is_batched = batch_layer.is_some();
        assert!(!is_batched && poly_count == 1 || is_batched && poly_count > 1);

        // reduce the degree by folding_factor at each iteration until the remaining polynomial
        // has small enough degree
        let mut evaluations = evaluations;
        let domain_size = if is_batched {
            evaluations.len() * self.options.folding_factor()
        } else {
            evaluations.len()
        };

        let num_fri_layers = self.options.num_fri_layers(domain_size);
        let mut layers = Vec::with_capacity(num_fri_layers);
        if let Some(batch_layer) = batch_layer {
            layers.push(batch_layer);
        }
        let start = if is_batched { 1 } else { 0 };
        for _ in start..num_fri_layers {
            let (new_evaluations, frida_layer) = match self.options.folding_factor() {
                2 => self.build_layer::<2>(channel, &evaluations),
                4 => self.build_layer::<4>(channel, &evaluations),
                8 => self.build_layer::<8>(channel, &evaluations),
                16 => self.build_layer::<16>(channel, &evaluations),
                _ => unimplemented!(
                    "folding factor {} is not supported",
                    self.options.folding_factor()
                ),
            };
            layers.push(frida_layer);
            evaluations = new_evaluations;
        }

        let remainder_poly = self.build_remainder(channel, &mut evaluations);

        FridaProver {
            layers,
            poly_count,
            remainder_poly,
            domain_size,
            folding_factor: self.options.folding_factor(),
        }
    }

    /// This method returns a commitment containing only the Merkle roots and metadata,
    /// and a stateful `FridaProver` instance which can be used generate many
    /// proofs for different query sets.
    pub fn calculate_commitment(
        &self,
        data: &[u8],
    ) -> Result<(ProverCommitment<H>, FridaProver<E, H>), FridaError> {
        // We use a dummy num_queries here because we are not generating a proof yet.
        let (channel, prover) = self.prepare_prover_state(data, 1)?;

        let commitment = ProverCommitment {
            roots: channel.commitments,
            domain_size: prover.domain_size,
            poly_count: prover.poly_count,
        };

        Ok((commitment, prover))
    }

    #[cfg(test)]
    pub fn test_build_layers(
        &self,
        channel: &mut Channel<E, H>,
        evaluations: Vec<E>,
    ) -> FridaProver<E, H> {
        self.build_layers(channel, evaluations, 1, None)
    }

    /// Builds a single FRI layer by first committing to the `evaluations`, then drawing a random
    /// alpha from the channel and use it to perform degree-respecting projection.
    fn build_layer<const N: usize>(
        &self,
        channel: &mut Channel<E, H>,
        evaluations: &[E],
    ) -> (Vec<E>, FridaLayer<E, H>) {
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
        let evaluations =
            folding::apply_drp(&transposed_evaluations, self.options.domain_offset(), alpha);
        (
            evaluations,
            FridaLayer {
                tree: evaluation_tree,
                evaluations: flatten_vector_elements(transposed_evaluations),
            },
        )
    }

    /// Creates remainder polynomial in coefficient form from a vector of `evaluations` over a domain.
    fn build_remainder(
        &self,
        channel: &mut Channel<E, H>,
        evaluations: &mut [E],
    ) -> FridaRemainder<E> {
        let inv_twiddles = fft::get_inv_twiddles(evaluations.len());
        fft::interpolate_poly_with_offset(evaluations, &inv_twiddles, self.options.domain_offset());
        let remainder_poly_size = evaluations.len() / self.options.blowup_factor();
        let remainder_poly = evaluations[..remainder_poly_size].to_vec();
        let commitment = <H as ElementHasher>::hash_elements(&remainder_poly);
        channel.commit_fri_layer(commitment);

        FridaRemainder(remainder_poly)
    }
}

pub fn batch_data_to_evaluations<E>(
    data_list: &[Vec<u8>],
    poly_count: usize,
    domain_size: usize,
    blowup_factor: usize,
    folding_factor: usize,
) -> Result<Vec<E>, FridaError>
where
    E: FieldElement,
{
    let bucket_count = domain_size / folding_factor;
    let bucket_size = poly_count * folding_factor;

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

    Ok(evaluations)
}

pub fn get_evaluations_from_positions<E: FieldElement>(
    all_evaluations: &[E],
    positions: &[usize],
    poly_count: usize,
    domain_size: usize,
    folding_factor: usize,
) -> Vec<E> {
    let mut evaluations = vec![];
    for position in positions.iter() {
        let bucket = position % (domain_size / folding_factor);
        let start_index = bucket * (poly_count * folding_factor)
            + (position / (domain_size / folding_factor)) * poly_count;
        all_evaluations[start_index..start_index + poly_count]
            .iter()
            .for_each(|e| {
                evaluations.push(*e);
            });
    }
    evaluations
}

#[cfg(test)]
mod base_tests;

#[cfg(test)]
mod tests {
    use winter_crypto::hashers::Blake3_256;
    use winter_fri::{folding::fold_positions, FriOptions, ProverChannel};
    use winter_math::fields::f128::BaseElement;
    use winter_rand_utils::{rand_value, rand_vector};

    use crate::frida_prover::channel::FridaProverChannel;

    use super::*;

    #[test]
    fn test_commit() {
        let options = FriOptions::new(2, 2, 0);
        let prover_builder: FridaProverBuilder<BaseElement, Blake3_256<BaseElement>> =
            FridaProverBuilder::new(options.clone());

        let domain_error = prover_builder
            .commit(&[0; frida_const::MAX_DOMAIN_SIZE * 15 / 2 + 1], 1)
            .unwrap_err();
        assert_eq!(
            FridaError::DomainSizeTooBig(frida_const::MAX_DOMAIN_SIZE * 2),
            domain_error
        );

        let num_qeuries_error_zero = prover_builder
            .commit(&rand_vector::<u8>(10), 0)
            .unwrap_err();
        assert_eq!(FridaError::BadNumQueries(0), num_qeuries_error_zero);

        let num_qeuries_error_bigger_than_domain = prover_builder
            .commit(&rand_vector::<u8>(200), 32)
            .unwrap_err();
        assert_eq!(
            FridaError::BadNumQueries(32),
            num_qeuries_error_bigger_than_domain
        );

        // Make sure minimum domain size is correctly enforced
        let (commitment, _prover) = prover_builder.commit(&rand_vector::<u8>(1), 1).unwrap();
        assert_eq!(
            frida_const::MIN_DOMAIN_SIZE.ilog2() as usize,
            commitment.roots.len()
        );

        let data = rand_vector::<u8>(200);
        let num_queries: usize = 31;
        let domain_size: usize = 32;
        let (commitment, _prover) = prover_builder.commit(&data, num_queries).unwrap();

        let evaluations = build_evaluations_from_data(&data, 32, 2).unwrap();
        let prover = FridaProverBuilder::new(options.clone());
        let mut channel = FridaProverChannel::<
            BaseElement,
            Blake3_256<BaseElement>,
            Blake3_256<BaseElement>,
        >::new(domain_size, num_queries);
        let prover = prover.test_build_layers(&mut channel, evaluations);
        let positions = channel.draw_query_positions();
        let proof = prover.open(&positions);

        assert_eq!(
            commitment,
            Commitment {
                roots: channel.commitments.clone(),
                proof: proof,
                domain_size,
                num_queries,
                poly_count: 1
            }
        );
    }

    #[test]
    fn test_open() {
        let options = FriOptions::new(2, 2, 0);
        let prover_builder: FridaProverBuilder<BaseElement, Blake3_256<BaseElement>> =
            FridaProverBuilder::new(options.clone());

        let data = rand_vector::<u8>(200);
        let (commitment, _prover) = prover_builder.commit(&data, 31).unwrap();

        let opening_prover: FridaProverBuilder<BaseElement, Blake3_256<BaseElement>> =
            FridaProverBuilder::new(options.clone());
        let (_commitment, prover) = opening_prover.commit(&data, 1).unwrap();

        // Replicating query positions just to make sure open is generating proper proofs since we can just compare it with the query phase proofs
        let mut channel = FridaProverChannel::<
            BaseElement,
            Blake3_256<BaseElement>,
            Blake3_256<BaseElement>,
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
        let prover_builder: FridaProverBuilder<BaseElement, Blake3_256<BaseElement>> =
            FridaProverBuilder::new(options.clone());
        let (commitment, prover) = prover_builder.commit_batch(&data, 1).unwrap();

        let opening_prover: FridaProverBuilder<BaseElement, Blake3_256<BaseElement>> =
            FridaProverBuilder::new(options.clone());
        let (_commitment, opening_prover) = opening_prover.commit_batch(&data, 1).unwrap();

        // Replicating query positions just to make sure open is generating proper proofs since we can just compare it with the query phase proofs
        let mut channel = FridaProverChannel::<
            BaseElement,
            Blake3_256<BaseElement>,
            Blake3_256<BaseElement>,
        >::new(prover.domain_size, 1);
        for layer_root in commitment.roots.iter() {
            channel.commit_fri_layer(*layer_root);
        }
        let query_positions = fold_positions(
            &channel.draw_query_positions(),
            prover.domain_size,
            folding_factor,
        );
        let opening_prover_query_proof = opening_prover.open(&query_positions);
        assert_eq!(commitment.proof, opening_prover_query_proof);

        let (_, merkle_proof) = opening_prover_query_proof
            .parse_batch_layer::<Blake3_256<BaseElement>, BaseElement>(
                prover.domain_size,
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
                prover.domain_size,
                folding_factor,
            )
            .unwrap();

        assert_eq!(
            FridaError::SinglePolyBatch,
            prover_builder.commit_batch(&vec![vec![]], 1).unwrap_err()
        );
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Builds a single proof layer by querying the evaluations of the passed in FRI layer at the
/// specified positions.
fn query_layer<E: FieldElement, H: ElementHasher<BaseField = E::BaseField>, const N: usize>(
    layer: &FridaLayer<E, H>,
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
    let queried_values: Vec<[E; N]> = positions.iter().map(|&pos| evaluations[pos]).collect();

    FridaProofLayer::new(queried_values, proof)
}

fn apply_drp_batched<E: FieldElement, const N: usize>(
    evaluations: &[E],
    poly_count: usize,
    options: &FriOptions,
    xi: Vec<E>,
    alpha: E,
) -> Vec<E> {
    let domain_size = evaluations.len() / poly_count;
    let bucket_count = domain_size / options.folding_factor();
    let bucket_size = poly_count * N;

    let mut final_eval: Vec<[E; N]> = vec![[E::default(); N]; bucket_count];
    iter_mut!(final_eval, 1024).enumerate().for_each(|(i, b)| {
        iter_mut!(b, 1024).enumerate().for_each(|(j, f)| {
            let start = i * bucket_size + poly_count * j;
            evaluations[start..start + poly_count]
                .iter()
                .enumerate()
                .for_each(|(j, e)| {
                    *f += *e * xi[j];
                });
        });
    });

    folding::apply_drp(&final_eval, options.domain_offset(), alpha)
}

#[cfg(test)]
mod distributed_api_tests {
    use super::*;
    use crate::{
        frida_data::build_evaluations_from_data,
        frida_verifier::das::FridaDasVerifier,
        winterfell::{f128::BaseElement, Blake3_256, FriOptions},
    };
    use winter_rand_utils::{rand_value, rand_vector};

    type Blake3 = Blake3_256<BaseElement>;

    // This helper function would live in your application logic, not the library.
    fn compute_position_assignments(
        n_validators: usize,
        query_positions: &[usize],
        h: usize,
    ) -> Vec<Vec<usize>> {
        let s = query_positions.len();
        let n = n_validators;
        if n == 0 {
            return vec![];
        }
        if n <= s {
            let span_length = s.saturating_sub(h) + 1;
            (1..=n)
                .map(|i| {
                    let offset = (i - 1) % s;
                    (0..span_length)
                        .map(|j| query_positions[(offset + j) % s])
                        .collect()
                })
                .collect()
        } else {
            let n_prime = (n / s) * s;
            if n_prime == 0 {
                return vec![Vec::new(); n];
            }
            let replication_factor = n_prime / s;
            let h_prime =
                (h.saturating_sub(n - n_prime) + replication_factor - 1) / replication_factor;
            let base_subsets = compute_position_assignments(s, query_positions, h_prime);
            (1..=n)
                .map(|i| {
                    if i <= n_prime {
                        base_subsets[(i - 1) % s].clone()
                    } else {
                        Vec::new()
                    }
                })
                .collect()
        }
    }

    #[test]
    fn test_distributed_proof_workflow() {
        // 1. SETUP: A block producer sets up the prover.
        let data = rand_vector::<u8>(512);
        let options = FriOptions::new(8, 4, 31);
        let n_validators = 10;
        let total_queries = 32;
        let prover_builder = FridaProverBuilder::<BaseElement, Blake3>::new(options.clone());

        // 2. COMMIT: The producer creates the commitment and the stateful prover.
        let (prover_commitment, prover) = prover_builder
            .calculate_commitment(&data)
            .expect("Commitment generation failed");

        // 3. DISTRIBUTE: The producer (or anyone) determines the query sets for each validator.
        let f = (n_validators - 1) / 3;
        let h = f + 1;
        let base_positions: Vec<usize> = (0..total_queries).collect();
        let validator_positions = compute_position_assignments(n_validators, &base_positions, h);

        // 4. PROVE: The producer generates a specific, small proof for each validator.
        let validator_proofs: Vec<_> = validator_positions
            .iter()
            .map(|positions| {
                if positions.is_empty() {
                    None
                } else {
                    Some(prover.open(positions))
                }
            })
            .collect();

        // 5. VERIFY: Each validator independently verifies their assigned proof.
        let all_evaluations = build_evaluations_from_data::<BaseElement>(
            &data,
            prover_commitment.domain_size,
            options.blowup_factor(),
        )
        .unwrap();

        for i in 0..n_validators {
            if let Some(proof) = &validator_proofs[i] {
                let positions = &validator_positions[i];
                let evaluations: Vec<BaseElement> =
                    positions.iter().map(|&p| all_evaluations[p]).collect();

                // A. Validator initializes a verifier from the public commitment.
                let verifier = FridaDasVerifier::<BaseElement, Blake3, Blake3>::from_commitment(
                    &prover_commitment,
                    options.clone(),
                )
                .expect("Verifier initialization failed");

                // B. Validator verifies their specific proof against the global context.
                let verification_result = verifier.verify(proof, &evaluations, positions);

                assert!(
                    verification_result.is_ok(),
                    "Verification failed for validator {} with error: {:?}",
                    i,
                    verification_result.err()
                );
            }
        }
    }

    #[test]
    fn test_distributed_proof_workflow_batch() {
        let poly_count = 10;
        let mut data_list = vec![];
        for _ in 0..poly_count {
            data_list.push(rand_vector::<u8>(usize::min(
                rand_value::<u64>() as usize,
                128,
            )));
        }

        let options = FriOptions::new(2, 2, 1);
        let n_validators = 10;
        let total_queries = 32;
        let prover_builder = FridaProverBuilder::<BaseElement, Blake3>::new(options.clone());

        // 2. COMMIT: The producer creates the commitment and the stateful prover.
        let (prover_commitment, prover) = prover_builder
            .calculate_commitment_batch(&data_list)
            .expect("Commitment generation failed");

        // 3. DISTRIBUTE: The producer (or anyone) determines the query sets for each validator.
        let f = (n_validators - 1) / 3;
        let h = f + 1;
        let base_positions: Vec<usize> = (0..total_queries).collect();
        let validator_positions = compute_position_assignments(n_validators, &base_positions, h);

        // 4. PROVE: The producer generates a specific, small proof for each validator.
        let validator_proofs: Vec<_> = validator_positions
            .iter()
            .map(|positions| {
                if positions.is_empty() {
                    None
                } else {
                    Some(prover.open(positions))
                }
            })
            .collect();

        // 5. VERIFY: Each validator independently verifies their assigned proof.
        let blowup_factor = options.blowup_factor();

        let max_data_len = encoded_data_element_count::<BaseElement>(
            data_list
                .iter()
                .map(|data| data.len())
                .max()
                .unwrap_or_default(),
        );

        let domain_size = usize::max(
            (max_data_len * blowup_factor).next_power_of_two(),
            frida_const::MIN_DOMAIN_SIZE,
        );

        let all_evaluations = batch_data_to_evaluations::<BaseElement>(
            &data_list,
            poly_count,
            domain_size,
            blowup_factor,
            options.folding_factor(),
        )
        .unwrap();

        for i in 0..n_validators {
            if let Some(proof) = &validator_proofs[i] {
                let positions = &validator_positions[i];

                let evaluations = get_evaluations_from_positions(
                    &all_evaluations,
                    positions,
                    poly_count,
                    domain_size,
                    options.folding_factor(),
                );

                // A. Validator initializes a verifier from the public commitment.
                let verifier = FridaDasVerifier::<BaseElement, Blake3, Blake3>::from_commitment(
                    &prover_commitment,
                    options.clone(),
                )
                .expect("Verifier initialization failed");

                // B. Validator verifies their specific proof against the global context.
                let verification_result = verifier.verify(proof, &evaluations, positions);

                assert!(
                    verification_result.is_ok(),
                    "Verification failed for validator {} with error: {:?}",
                    i,
                    verification_result.err()
                );
            }
        }
    }
}
