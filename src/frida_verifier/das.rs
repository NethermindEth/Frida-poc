use std::marker::PhantomData;

use winter_crypto::{Digest, ElementHasher};
use winter_fri::FriOptions;
use winter_math::{FieldElement, StarkField};

use crate::{
    frida_error::FridaError, frida_prover::Commitment, frida_random::FridaRandomCoin,
    frida_verifier_channel::FridaVerifierChannel,
};

use super::verifier2::FridaVerifier2;

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
    layer_alphas: Vec<E>,
    options: FriOptions,
    num_partitions: usize,
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
    pub fn new(
        das_commitment: Commitment<HRandom>,
        public_coin: &mut R,
        options: FriOptions,
        max_poly_degree: usize,
    ) -> Result<Self, FridaError> {
        // accepts das commitment as input
        // store layer_commitments
        // compute and store layered alpha
        // infer evaluation domain info
        let domain_size = max_poly_degree.next_power_of_two() * options.blowup_factor();
        let domain_generator = E::BaseField::get_root_of_unity(domain_size.ilog2());

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

        // double check if the hst used here is correct as 'stored layered alpha'
        // above seems to have made an 'extra' round of alpha query
        // draw_query_positions from FridaRandom for x num of queries
        // to get the openings for checking of folding for correctness
        let positions =
            public_coin.draw_query_positions(das_commitment.num_queries, domain_size)?;

        // verify commitment is correct by using CheckAuth
        // * to modify FridaVerifier to accept 'layer_commitments' and 'layered_alpha' in 'new', else it needs to recalculate
        // * this value every time
        // * actually i think we can move the entire 'new' function here

        // if CheckAuth for any of the opening fails, we will return Error in 'new' function
        // note that our FridaProof has batched multiple positions into one proof

        // perform verify
        // i think its ok to recreate FridaVerifierChannel everytime

        let frida_verifier = FridaVerifier2::<E, HRandom>::new(
            layer_commitments.clone(),
            layer_alphas.clone(),
            num_partitions,
            options.clone(),
            max_poly_degree,
        )
        .map_err(|_e| FridaError::InvalidDASCommitment)?;

        let (queried_layers, _) = das_commitment
            .proof
            .clone()
            .parse_layers::<HRandom, E>(domain_size.clone(), options.folding_factor())
            .map_err(|_e| FridaError::InvalidDASCommitment)?;
        let evaluations = queried_layers
            .first()
            .ok_or(FridaError::InvalidDASCommitment)?
            .to_owned();

        let mut verifier_channel = FridaVerifierChannel::<E, HRandom>::new(
            das_commitment.proof,
            layer_commitments.clone(),
            domain_size.clone(),
            options.folding_factor(),
        )
        .map_err(|_e| FridaError::InvalidDASCommitment)?;

        let _ = frida_verifier
            .check_auth(&mut verifier_channel, &evaluations, &positions)
            .map_err(|_e| FridaError::InvalidDASCommitment);

        Ok(Self {
            max_poly_degree,
            domain_size,
            num_partitions,
            layer_commitments,
            domain_generator,
            layer_alphas,
            options,
            _field_element: PhantomData,
            _h_random: PhantomData,
            _public_coin: PhantomData,
        })
    }

    pub fn verify(&self) {}
}

#[cfg(test)]
mod test {
    use winter_crypto::hashers::Blake3_256;
    use winter_fri::FriOptions;
    use winter_math::fields::f128::BaseElement;
    use winter_rand_utils::rand_vector;

    use crate::{
        frida_data::encoded_data_element_count,
        frida_prover::{traits::BaseFriProver, FridaProver},
        frida_prover_channel::FridaProverChannel,
        frida_random::{FridaRandom, FridaRandomCoin},
        utils::{build_evaluations, build_prover_channel},
    };

    use super::FridaDasVerifier;

    #[test]
    fn test_frida_das_verify() {
        let lde_blowup_e = 3;
        let folding_factor_e = 1;
        let max_remainder_degree = 7;
        let lde_blowup = 1 << lde_blowup_e;
        let folding_factor = 1 << folding_factor_e;

        let options = FriOptions::new(lde_blowup, folding_factor, max_remainder_degree);

        // instantiate the prover and generate the proof
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

        let mut public_coin =
            FridaRandom::<Blake3_256<BaseElement>, Blake3_256<BaseElement>, BaseElement>::new(&[
                123,
            ]);

        let encoded_element_count = encoded_data_element_count::<BaseElement>(data.len());

        let verifier = FridaDasVerifier::new(
            commitment,
            &mut public_coin,
            options,
            encoded_element_count - 1,
        )
        .unwrap();
    }
}
