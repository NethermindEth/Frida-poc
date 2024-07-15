use winter_crypto::{BatchMerkleProof, ElementHasher, Hasher, MerkleTree};
use winter_fri::{VerifierChannel, VerifierError};
use winter_math::FieldElement;

use crate::{frida_error::FridaError, frida_prover::proof::FridaProof};

pub struct FridaVerifierChannel<E: FieldElement, H: ElementHasher<BaseField = E::BaseField>> {
    layer_commitments: Vec<H::Digest>,
    poly_count: usize,
    layer_proofs: Vec<BatchMerkleProof<H>>,
    pub(crate) batch_data: Option<BatchData<E, H>>,
    pub(crate) layer_queries: Vec<Vec<E>>,
    remainder: Vec<E>,
    num_partitions: usize,
}

pub struct BatchData<E: FieldElement, H: ElementHasher<BaseField = E::BaseField>> {
    pub(crate) batch_layer_queries: Option<Vec<E>>,
    batch_layer_proof: Option<BatchMerkleProof<H>>,
}

impl<E, H> FridaVerifierChannel<E, H>
where
    E: FieldElement,
    H: ElementHasher<BaseField = E::BaseField>,
{
    pub fn new(
        mut proof: FridaProof,
        layer_commitments: Vec<H::Digest>,
        mut domain_size: usize,
        folding_factor: usize,
        poly_count: usize,
    ) -> Result<Self, FridaError> {
        assert!(poly_count != 0, "poly_count must be greater than 0");

        let num_partitions = proof.num_partitions();

        let remainder = proof
            .parse_remainder()
            .map_err(|e| FridaError::DeserializationError(e))?;

        let batch_data = if poly_count > 1 {
            let (batch_layer_queries, batch_layer_proof) = proof
                .parse_batch_layer::<H, E>(domain_size, folding_factor, poly_count)
                .map_err(|e| FridaError::DeserializationError(e))?;
            domain_size /= folding_factor;
            Some(BatchData {
                batch_layer_queries: Some(batch_layer_queries),
                batch_layer_proof: Some(batch_layer_proof),
            })
        } else {
            if proof.batch_layer.is_some() {
                return Err(FridaError::ProofPolyCountMismatch());
            }
            None
        };

        let (layer_queries, layer_proofs) = proof
            .parse_layers::<H, E>(domain_size, folding_factor)
            .map_err(|e| FridaError::DeserializationError(e))?;
        Ok(Self {
            layer_commitments,
            poly_count,
            batch_data,
            layer_proofs,
            layer_queries,
            remainder,
            num_partitions,
        })
    }
}

impl<E, H> VerifierChannel<E> for FridaVerifierChannel<E, H>
where
    E: FieldElement,
    H: ElementHasher<BaseField = E::BaseField>,
{
    type Hasher = H;

    fn read_fri_num_partitions(&self) -> usize {
        self.num_partitions
    }

    fn read_fri_layer_commitments(&mut self) -> Vec<H::Digest> {
        self.layer_commitments.drain(..).collect()
    }

    fn take_next_fri_layer_proof(&mut self) -> BatchMerkleProof<H> {
        self.layer_proofs.remove(0)
    }

    fn take_next_fri_layer_queries(&mut self) -> Vec<E> {
        self.layer_queries.remove(0)
    }

    fn take_fri_remainder(&mut self) -> Vec<E> {
        self.remainder.clone()
    }
}

pub trait BaseVerifierChannel<E>: VerifierChannel<E>
where
    E: FieldElement,
{
    fn poly_count(&self) -> usize;
    fn read_batch_layer_queries(
        &mut self,
        positions: &[usize],
        commitment: &<<Self as VerifierChannel<E>>::Hasher as Hasher>::Digest,
    ) -> Result<Vec<E>, VerifierError>;
}

impl<E, H> BaseVerifierChannel<E> for FridaVerifierChannel<E, H>
where
    E: FieldElement,
    H: ElementHasher<BaseField = E::BaseField>,
{
    fn poly_count(&self) -> usize {
        self.poly_count
    }
    fn read_batch_layer_queries(
        &mut self,
        positions: &[usize],
        commitment: &<<Self as VerifierChannel<E>>::Hasher as Hasher>::Digest,
    ) -> Result<Vec<E>, VerifierError> {
        let mut batch_data = self.batch_data.take().unwrap();
        let layer_proof = batch_data.batch_layer_proof.take().unwrap();
        MerkleTree::<Self::Hasher>::verify_batch(commitment, positions, &layer_proof)
            .map_err(|_| VerifierError::LayerCommitmentMismatch)?;
        let layer_queries = batch_data.batch_layer_queries.take().unwrap();
        Ok(layer_queries)
    }
}
