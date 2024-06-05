use core::marker::PhantomData;

use winter_crypto::{ElementHasher, Hasher, MerkleTree};
use winter_math::{fft, FieldElement, StarkField};
use winter_utils::{flatten_vector_elements, group_slice_elements, transpose_slice};

use winter_fri::{
    folding::{apply_drp, fold_positions},
    utils::hash_values,
    FriOptions, ProverChannel,
};

use crate::frida_prover::proof::FridaProofBatchLayer;

use super::{
    proof::{FridaProof, FridaProofLayer},
    BatchFridaLayer, FridaLayer, FridaRemainder,
};

// TRAIT implementing the default behavior for a fri prover
// ================================================================================================
pub trait BaseFriProver<B, E, C, H>
where
    B: StarkField,
    E: FieldElement<BaseField = B>,
    C: ProverChannel<E, Hasher = H>,
    H: ElementHasher<BaseField = B>,
{
    fn new(options: FriOptions) -> Self;
    fn options(&self) -> &FriOptions;
    fn folding_factor(&self) -> usize;
    fn domain_size(&self) -> usize;
    fn domain_offset(&self) -> B;
    fn remainder_poly(&self) -> &FridaRemainder<E>;
    fn num_layers(&self) -> usize;
    fn is_batch(&self) -> bool;
    fn reset(&mut self);

    fn store_layer(&mut self, layer: FridaLayer<B, E, H>);
    fn get_layer(&self, index: usize) -> &FridaLayer<B, E, H>;
    fn get_batch_layer(&self) -> &Option<BatchFridaLayer<B, E, H>>;
    fn set_remainer_poly(&mut self, remainder: FridaRemainder<E>);

    fn build_layers(&mut self, channel: &mut C, mut evaluations: Vec<E>) {
        assert!(
            self.num_layers() == 0,
            "a prior proof generation request has not been completed yet"
        );

        // reduce the degree by folding_factor at each iteration until the remaining polynomial
        // has small enough degree
        for _ in 0..self.options().num_fri_layers(evaluations.len()) {
            match self.folding_factor() {
                2 => self.build_layer::<2>(channel, &mut evaluations),
                4 => self.build_layer::<4>(channel, &mut evaluations),
                8 => self.build_layer::<8>(channel, &mut evaluations),
                16 => self.build_layer::<16>(channel, &mut evaluations),
                _ => unimplemented!("folding factor {} is not supported", self.folding_factor()),
            }
        }

        self.set_remainder(channel, &mut evaluations);
    }

    /// Builds a single FRI layer by first committing to the `evaluations`, then drawing a random
    /// alpha from the channel and use it to perform degree-respecting projection.
    fn build_layer<const N: usize>(&mut self, channel: &mut C, evaluations: &mut Vec<E>) {
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
        *evaluations = apply_drp(&transposed_evaluations, self.domain_offset(), alpha);
        self.store_layer(FridaLayer {
            tree: evaluation_tree,
            evaluations: flatten_vector_elements(transposed_evaluations),
            _base_field: PhantomData,
        });
    }

    /// Creates remainder polynomial in coefficient form from a vector of `evaluations` over a domain.
    fn set_remainder(&mut self, channel: &mut C, evaluations: &mut [E]) {
        let inv_twiddles = fft::get_inv_twiddles(evaluations.len());
        fft::interpolate_poly_with_offset(
            evaluations,
            &inv_twiddles,
            self.options().domain_offset(),
        );
        let remainder_poly_size = evaluations.len() / self.options().blowup_factor();
        let remainder_poly = evaluations[..remainder_poly_size].to_vec();
        let commitment = <H as ElementHasher>::hash_elements(&remainder_poly);
        channel.commit_fri_layer(commitment);

        self.set_remainer_poly(FridaRemainder(remainder_poly));
    }

    fn build_proof(&mut self, positions: &[usize]) -> FridaProof {
        assert!(
            !self.remainder_poly().0.is_empty(),
            "FRI layers have not been built yet"
        );

        let layers_len = self.num_layers();
        let mut layers = Vec::with_capacity(layers_len);

        if layers_len != 0 {
            let mut positions = positions.to_vec();
            let mut domain_size = self.domain_size();
            let folding_factor = self.options().folding_factor();

            // for all FRI layers, except the last one, record tree root, determine a set of query
            // positions, and query the layer at these positions.
            for i in 0..layers_len {
                positions = fold_positions(&positions, domain_size, folding_factor);

                // sort of a static dispatch for folding_factor parameter
                let proof_layer = match folding_factor {
                    2 => query_layer::<B, E, H, 2>(&self.get_layer(i), &positions),
                    4 => query_layer::<B, E, H, 4>(&self.get_layer(i), &positions),
                    8 => query_layer::<B, E, H, 8>(&self.get_layer(i), &positions),
                    16 => query_layer::<B, E, H, 16>(&self.get_layer(i), &positions),
                    _ => unimplemented!("folding factor {} is not supported", folding_factor),
                };

                layers.push(proof_layer);
                domain_size /= folding_factor;
            }
        }

        // use the remaining polynomial values directly as proof
        let remainder = self.remainder_poly().0.clone();

        let mut batch_layer = None;

        if self.is_batch() {
            let positions = fold_positions(&positions, self.domain_size(), self.folding_factor());
            let proof = self
                .get_batch_layer()
                .as_ref()
                .unwrap()
                .tree
                .prove_batch(&positions)
                .expect("failed to generate a Merkle proof for FRI layer queries");
            let evaluations = &self.get_batch_layer().as_ref().unwrap().evaluations;
            let mut queried_values: Vec<&Vec<E>> = Vec::with_capacity(positions.len());
            for &position in positions.iter() {
                queried_values.push(&evaluations[position]);
            }
            batch_layer = Some(FridaProofBatchLayer::new(queried_values, proof));
        }

        FridaProof::new(batch_layer, layers, remainder, 1)
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
