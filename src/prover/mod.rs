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

pub mod builder;
pub mod channel;
pub mod proof;

#[cfg(test)]
mod tests;

use crate::{
    constants,
    core::data::{build_evaluations_from_data, encoded_data_element_count},
    error::FridaError,
    prover::{
        builder::FridaProverBuilder,
        channel::FridaProverChannel,
        proof::{FridaProof, FridaProofBatchLayer, FridaProofLayer},
    },
};

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

// HELPER FUNCTIONS
// ================================================================================================

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
    let bucket_count = domain_size / folding_factor;
    let bucket_size = poly_count * folding_factor;

    for position in positions.iter() {
        let bucket = position % bucket_count;
        let offset = poly_count * (position / bucket_count);

        for i in 0..poly_count {
            let index = bucket * bucket_size + i + offset;
            evaluations.push(all_evaluations[index]);
        }
    }
    evaluations
}

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