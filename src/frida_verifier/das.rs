use std::marker::PhantomData;

use winter_crypto::{Digest, ElementHasher};
use winter_fri::{folding::fold_positions, FriOptions};
use winter_math::{FieldElement, StarkField};
use winter_utils::group_slice_elements;

use crate::{
    frida_error::FridaError,
    frida_prover::{proof::FridaProof, Commitment},
    frida_random::FridaRandomCoin,
    frida_verifier::get_query_values,
    frida_verifier_channel::{BaseVerifierChannel, FridaVerifierChannel},
};

use super::get_batch_query_values;
use super::traits::BaseFridaVerifier;

pub struct FridaDasVerifier<E, HHst, HRandom, R>
where
    E: FieldElement,
    HHst: ElementHasher<BaseField = E::BaseField>,
    HRandom: ElementHasher<BaseField = E::BaseField>,
    R: FridaRandomCoin<BaseField = E::BaseField, HashHst = HHst, HashRandom = HRandom>,
{
    max_poly_degree: usize,
    domain_size: usize,
    domain_generator: E::BaseField,
    layer_commitments: Vec<HRandom::Digest>,
    xi: Option<Vec<E>>,
    layer_alphas: Vec<E>,
    options: FriOptions,
    num_partitions: usize,
    poly_count: usize,
    _public_coin: PhantomData<R>,
    _field_element: PhantomData<E>,
    _h_random: PhantomData<HRandom>,
}

impl<E, HHst, HRandom, R> FridaDasVerifier<E, HHst, HRandom, R>
where
    E: FieldElement,
    HHst: ElementHasher<BaseField = E::BaseField>,
    HRandom: ElementHasher<BaseField = E::BaseField>,
    R: FridaRandomCoin<
        FieldElement = E,
        BaseField = E::BaseField,
        HashHst = HHst,
        HashRandom = HRandom,
    >,
{
    pub fn verify(
        &self,
        proof: FridaProof,
        evaluations: &[E],
        positions: &[usize],
    ) -> Result<(), FridaError> {
        let mut verifier_channel = FridaVerifierChannel::<E, HRandom>::new(
            proof,
            self.layer_commitments.clone(),
            self.domain_size,
            self.options.folding_factor(),
            self.poly_count,
        )?;

        self.check_auth(&mut verifier_channel, evaluations, positions)
            .map_err(|_e| FridaError::FailToVerify)
    }

    fn get_query_values_from_commitment<const N: usize>(
        verifier_channel: &mut FridaVerifierChannel<E, HRandom>,
        positions: &[usize],
        folded_positions: &[usize],
        domain_size: usize,
    ) -> Vec<E> {
        if verifier_channel.poly_count() > 1 {
            let layer_values = verifier_channel
                .batch_data
                .as_ref()
                .unwrap()
                .batch_layer_queries
                .as_ref()
                .unwrap();

            get_batch_query_values::<E, N>(
                layer_values,
                positions,
                folded_positions,
                domain_size,
                verifier_channel.poly_count(),
            )
        } else {
            let layer_values = group_slice_elements(&verifier_channel.layer_queries[0]);
            get_query_values::<E, N>(layer_values, positions, folded_positions, domain_size)
        }
    }

    #[cfg(test)]
    pub fn layer_alphas(&self) -> &Vec<E> {
        &self.layer_alphas
    }
}

impl<E, HHst, HRandom, R> BaseFridaVerifier<E, HHst, HRandom, R>
    for FridaDasVerifier<E, HHst, HRandom, R>
where
    E: FieldElement<BaseField: StarkField>,
    HHst: ElementHasher<BaseField = E::BaseField>,
    HRandom: ElementHasher<BaseField = E::BaseField>,
    R: FridaRandomCoin<
        FieldElement = E,
        BaseField = E::BaseField,
        HashHst = HHst,
        HashRandom = HRandom,
    >,
{
    /**
     * Accepts DAS commitment as input
     * Will perform verification on correctness of folding
     */
    fn new(
        das_commitment: Commitment<HRandom>,
        public_coin: &mut R,
        options: FriOptions,
    ) -> Result<Self, FridaError> {
        let domain_size = das_commitment.domain_size;
        let num_partitions = das_commitment.proof.num_partitions();
        let max_poly_degree = domain_size / options.blowup_factor() - 1;

        // read layer commitments from the channel and use them to build a list of alphas
        let poly_count = das_commitment.poly_count;
        let layer_commitments = das_commitment.roots;
        let alpha_commitments = &layer_commitments[..];

        let mut xi = None;
        let mut layer_alphas = Vec::with_capacity(alpha_commitments.len());
        let mut max_degree_plus_1 = max_poly_degree + 1;
        for (depth, commitment) in alpha_commitments.iter().enumerate() {
            public_coin.reseed(&commitment.as_bytes());
            if depth == 0 && poly_count > 1 {
                xi = Some(public_coin.draw_xi(poly_count)?)
            }

            let alpha = public_coin.draw().map_err(|_e| FridaError::DrawError())?;
            layer_alphas.push(alpha);

            // make sure the degree can be reduced by the folding factor at all layers
            // but the remainder layer
            if depth != alpha_commitments.len() - 1
                && max_degree_plus_1 % options.folding_factor() != 0
            {
                return Err(FridaError::DegreeTruncation(
                    max_degree_plus_1 - 1,
                    options.folding_factor(),
                    depth,
                ));
            }
            max_degree_plus_1 /= options.folding_factor();
        }

        let positions =
            public_coin.draw_query_positions(das_commitment.num_queries, domain_size)?;

        let mut verifier_channel = FridaVerifierChannel::<E, HRandom>::new(
            das_commitment.proof,
            layer_commitments.clone(),
            domain_size,
            options.folding_factor(),
            poly_count,
        )
        .map_err(|_e| FridaError::InvalidDASCommitment)?;

        // get query value from commitment
        let query_values = {
            let folded_positions =
                fold_positions(&positions, domain_size, options.folding_factor());

            let folding_factor = options.folding_factor();
            match folding_factor {
                2 => Ok(Self::get_query_values_from_commitment::<2>(
                    &mut verifier_channel,
                    &positions,
                    &folded_positions,
                    domain_size,
                )),
                4 => Ok(Self::get_query_values_from_commitment::<4>(
                    &mut verifier_channel,
                    &positions,
                    &folded_positions,
                    domain_size,
                )),
                8 => Ok(Self::get_query_values_from_commitment::<8>(
                    &mut verifier_channel,
                    &positions,
                    &folded_positions,
                    domain_size,
                )),
                16 => Ok(Self::get_query_values_from_commitment::<16>(
                    &mut verifier_channel,
                    &positions,
                    &folded_positions,
                    domain_size,
                )),
                _ => Err(FridaError::UnsupportedFoldingFactor(folding_factor)),
            }?
        };

        let domain_generator = E::BaseField::get_root_of_unity(domain_size.ilog2());

        let verifier = Self {
            max_poly_degree,
            domain_size,
            num_partitions,
            poly_count,
            layer_commitments,
            xi,
            layer_alphas,
            options,
            domain_generator,
            _field_element: PhantomData,
            _h_random: PhantomData,
            _public_coin: PhantomData,
        };

        verifier
            .check_auth(&mut verifier_channel, &query_values, &positions)
            .map_err(|_e| FridaError::InvalidDASCommitment)?;

        Ok(verifier)
    }

    /// Returns protocol configuration options for this verifier.
    fn options(&self) -> &FriOptions {
        &self.options
    }

    fn domain_generator(&self) -> E::BaseField {
        self.domain_generator
    }

    fn domain_size(&self) -> usize {
        self.domain_size
    }

    fn max_poly_degree(&self) -> usize {
        self.max_poly_degree
    }

    fn num_partitions(&self) -> usize {
        self.num_partitions
    }

    fn get_layer_commitment(&self, depth: usize) -> HRandom::Digest {
        self.layer_commitments[depth]
    }

    fn get_layer_alpha(&self, depth: usize) -> E {
        self.layer_alphas[depth]
    }

    fn xi(&self) -> Option<&Vec<E>> {
        self.xi.as_ref()
    }
}
