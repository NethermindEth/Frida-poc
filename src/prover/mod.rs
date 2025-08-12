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
    constants,
    core::data::{build_evaluations_from_data, encoded_data_element_count},
    error::FridaError,
    prover::proof::{FridaProofBatchLayer, FridaProofLayer},
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

#[cfg(test)]
mod base_tests;

#[cfg(test)]
mod tests {
    use winter_crypto::hashers::Blake3_256;
    use winter_fri::{folding::fold_positions, FriOptions, ProverChannel};
    use winter_math::fields::f128::BaseElement;
    use winter_rand_utils::{rand_value, rand_vector};

    use crate::prover::channel::FridaProverChannel;

    use super::*;

    #[test]
    fn test_commit() {
        let options = FriOptions::new(2, 2, 0);
        let prover_builder: FridaProverBuilder<BaseElement, Blake3_256<BaseElement>> =
            FridaProverBuilder::new(options.clone());

        let domain_error = prover_builder
            .commit(&[0; constants::MAX_DOMAIN_SIZE * 15 / 2 + 1], 1)
            .unwrap_err();
        assert_eq!(
            FridaError::DomainSizeTooBig(constants::MAX_DOMAIN_SIZE * 2),
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
            constants::MIN_DOMAIN_SIZE.ilog2() as usize,
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

