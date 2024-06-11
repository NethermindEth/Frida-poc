use std::marker::PhantomData;

use winter_crypto::{Digest, ElementHasher};
use winter_fri::{
    folding::fold_positions, utils::map_positions_to_indexes, FriOptions, VerifierChannel,
};
use winter_math::FieldElement;

use crate::{
    frida_error::FridaError,
    frida_prover::{proof::FridaProof, Commitment},
    frida_random::FridaRandomCoin,
    frida_verifier::get_query_values,
    frida_verifier_channel::FridaVerifierChannel,
};

use super::verifier::FridaVerifier;

pub struct FridaDasVerifier<E, HHst, HRandom, R>
where
    E: FieldElement,
    HHst: ElementHasher<BaseField = E::BaseField>,
    HRandom: ElementHasher<BaseField = E::BaseField>,
    R: FridaRandomCoin<BaseField = E::BaseField, HashHst = HHst, HashRandom = HRandom>,
{
    max_poly_degree: usize,
    domain_size: usize,
    layer_commitments: Vec<HRandom::Digest>,
    layer_alphas: Vec<E>,
    options: FriOptions,
    num_partitions: usize,
    _public_coin: PhantomData<R>,
    _field_element: PhantomData<E>,
    _h_random: PhantomData<HRandom>,
}

// TODO: add a base trait for verifier similar to FridaProver
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
    /**
     * Accepts DAS commitment as input
     * Will perform verification on correctness of folding
     */
    pub fn new(
        das_commitment: Commitment<HRandom>,
        public_coin: &mut R,
        options: FriOptions,
        max_poly_degree: usize,
        batch_size: usize,
    ) -> Result<Self, FridaError> {
        let domain_size = max_poly_degree.next_power_of_two() * options.blowup_factor();
        let num_partitions = das_commitment.proof.num_partitions();

        // read layer commitments from the channel and use them to build a list of alphas
        let layer_commitments = das_commitment.roots;
        let mut layer_alphas = Vec::with_capacity(layer_commitments.len());
        let mut max_degree_plus_1 = max_poly_degree + 1;
        for (depth, commitment) in layer_commitments.iter().enumerate() {
            public_coin.reseed(&commitment.as_bytes());
            let alpha = public_coin.draw().map_err(|_e| FridaError::DrawError())?;

            layer_alphas.push(alpha);

            // make sure the degree can be reduced by the folding factor at all layers
            // but the remainder layer
            if depth != layer_commitments.len() - 1
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

        // get query value from commitment
        let query_values = {
            let folded_positions =
                fold_positions(&positions, domain_size, options.folding_factor());

            let mut verifier_channel = FridaVerifierChannel::<E, HRandom>::new(
                das_commitment.proof.clone(),
                layer_commitments.clone(),
                domain_size.clone(),
                options.folding_factor(),
                batch_size
            )
            .map_err(|_e| FridaError::InvalidDASCommitment)?;
            let position_indexes = map_positions_to_indexes(
                &folded_positions,
                domain_size,
                options.folding_factor(),
                num_partitions,
            );
            let layer_commitment = layer_commitments[0];

            let folding_factor = options.folding_factor();
            match folding_factor {
                2 => {
                    let layer_values = verifier_channel
                        .read_layer_queries(&position_indexes, &layer_commitment)
                        .unwrap();
                    Ok(get_query_values::<E, 2>(
                        &layer_values,
                        &positions,
                        &folded_positions,
                        domain_size,
                    ))
                }
                4 => {
                    let layer_values = verifier_channel
                        .read_layer_queries(&position_indexes, &layer_commitment)
                        .unwrap();
                    Ok(get_query_values::<E, 4>(
                        &layer_values,
                        &positions,
                        &folded_positions,
                        domain_size,
                    ))
                }
                8 => {
                    let layer_values = verifier_channel
                        .read_layer_queries(&position_indexes, &layer_commitment)
                        .unwrap();
                    Ok(get_query_values::<E, 8>(
                        &layer_values,
                        &positions,
                        &folded_positions,
                        domain_size,
                    ))
                }
                16 => {
                    let layer_values = verifier_channel
                        .read_layer_queries(&position_indexes, &layer_commitment)
                        .unwrap();
                    Ok(get_query_values::<E, 16>(
                        &layer_values,
                        &positions,
                        &folded_positions,
                        domain_size,
                    ))
                }
                _ => Err(FridaError::UnsupportedFoldingFactor(folding_factor)),
            }?
        };

        let mut verifier_channel = FridaVerifierChannel::<E, HRandom>::new(
            das_commitment.proof,
            layer_commitments.clone(),
            domain_size.clone(),
            options.folding_factor(),
            batch_size
        )
        .map_err(|_e| FridaError::InvalidDASCommitment)?;

        let frida_verifier = FridaVerifier::<E, HRandom>::new(
            layer_commitments.clone(),
            layer_alphas.clone(),
            num_partitions,
            options.clone(),
            max_poly_degree,
        )
        .map_err(|_e| FridaError::InvalidDASCommitment)?;

        frida_verifier
            .check_auth(&mut verifier_channel, &query_values, &positions)
            .map_err(|_e| FridaError::InvalidDASCommitment)?;

        Ok(Self {
            max_poly_degree,
            domain_size,
            num_partitions,
            layer_commitments,
            layer_alphas,
            options,
            _field_element: PhantomData,
            _h_random: PhantomData,
            _public_coin: PhantomData,
        })
    }

    pub fn verify(
        &self,
        proof: FridaProof,
        evaluations: &[E],
        positions: &[usize],
        batch_size: usize
    ) -> Result<(), FridaError> {
        let mut verifier_channel = FridaVerifierChannel::<E, HRandom>::new(
            proof,
            self.layer_commitments.clone(),
            self.domain_size.clone(),
            self.options.folding_factor(),
            batch_size
        )
        .map_err(|_e| FridaError::DeserializationError())?;

        let frida_verifier = FridaVerifier::<E, HRandom>::new(
            self.layer_commitments.clone(),
            self.layer_alphas.clone(),
            self.num_partitions,
            self.options.clone(),
            self.max_poly_degree,
        )
        .map_err(|_e| FridaError::FailToVerify)?;

        frida_verifier
            .check_auth(&mut verifier_channel, &evaluations, &positions)
            .map_err(|_e| FridaError::FailToVerify)
    }
}
