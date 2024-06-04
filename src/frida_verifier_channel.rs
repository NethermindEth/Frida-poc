use winter_crypto::{BatchMerkleProof, ElementHasher, Hasher, MerkleTree};
use winter_fri::{VerifierChannel, VerifierError};
use winter_math::FieldElement;
use winter_utils::DeserializationError;

use crate::frida_prover::proof::FridaProof;

pub struct FridaVerifierChannel<E: FieldElement, H: ElementHasher<BaseField = E::BaseField>> {
    layer_commitments: Vec<H::Digest>,
    batch_data: Option<BatchData<E, H>>,
    layer_proofs: Vec<BatchMerkleProof<H>>,
    layer_queries: Vec<Vec<E>>,
    remainder: Vec<E>,
    num_partitions: usize,
}

pub struct BatchData<E: FieldElement, H: ElementHasher<BaseField = E::BaseField>> {
    pub batch_size: usize,
    pub batch_commitment: Option<H::Digest>,
    pub batch_layer_queries: Option<Vec<Vec<E>>>,
    pub batch_layer_proof: Option<BatchMerkleProof<H>>,
}

impl<E, H> FridaVerifierChannel<E, H>
where
    E: FieldElement,
    H: ElementHasher<BaseField = E::BaseField>,
{
    pub fn new(
        mut proof: FridaProof,
        mut layer_commitments: Vec<H::Digest>,
        domain_size: usize,
        folding_factor: usize,
        batch_size: usize,
    ) -> Result<Self, DeserializationError> {
        let num_partitions = proof.num_partitions();

        let remainder = proof.parse_remainder()?;

        let batch_data = if batch_size != 0 {
            let (batch_layer_queries, batch_layer_proof) =
                proof.parse_batch_layer::<H, E>(domain_size, folding_factor, batch_size)?;
            let batch_commitment = layer_commitments.remove(0);
            Some(BatchData {
                batch_size,
                batch_commitment: Some(batch_commitment),
                batch_layer_queries: Some(batch_layer_queries),
                batch_layer_proof: Some(batch_layer_proof),
            })
        } else {
            None
        };

        let (layer_queries, layer_proofs) =
            proof.parse_layers::<H, E>(domain_size, folding_factor)?;

        Ok(Self {
            layer_commitments,
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
    fn batch_size(&self) -> usize;
    fn batch_data(&self) -> &BatchData<E, Self::Hasher>;
    fn read_batch_layer_queries(
        &mut self,
        positions: &[usize],
        commitment: &<<Self as VerifierChannel<E>>::Hasher as Hasher>::Digest,
    ) -> Result<Vec<Vec<E>>, VerifierError>;
}

impl<E, H> BaseVerifierChannel<E> for FridaVerifierChannel<E, H>
where
    E: FieldElement,
    H: ElementHasher<BaseField = E::BaseField>,
{
    fn batch_size(&self) -> usize {
        if self.batch_data.is_none() {
            0
        } else {
            self.batch_data.as_ref().unwrap().batch_size
        }
    }
    fn batch_data(&self) -> &BatchData<E, H> {
        self.batch_data.as_ref().unwrap()
    }
    fn read_batch_layer_queries(
        &mut self,
        positions: &[usize],
        commitment: &<<Self as VerifierChannel<E>>::Hasher as Hasher>::Digest,
    ) -> Result<Vec<Vec<E>>, VerifierError> {
        let batch_data = self.batch_data.as_mut().unwrap();
        let layer_proof = batch_data.batch_layer_proof.take().unwrap();
        MerkleTree::<Self::Hasher>::verify_batch(commitment, positions, &layer_proof)
            .map_err(|_| VerifierError::LayerCommitmentMismatch)?;

        // TODO: make sure layer queries hash into leaves of layer proof
        let layer_queries = batch_data.batch_layer_queries.take().unwrap();
        Ok(layer_queries)
    }
}
