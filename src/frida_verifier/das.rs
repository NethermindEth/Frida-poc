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
        println!("positions in verifier::new(): {:?}", positions);

        let folded_positions = fold_positions(&positions, domain_size, options.folding_factor());

        println!(
            "folded_positions in verifier::new(): {:?}",
            folded_positions
        );
        // let positions = vec![1];

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

        println!("queried_layers in verifier::new(): {:?}", queried_layers);
        let evaluations = queried_layers
            .first()
            .ok_or(FridaError::InvalidDASCommitment)?
            .to_owned();
        println!("evaluations in verifier::new(): {:?}", evaluations);

        // let query_values =
        //         get_query_values::<E, N>(&layer_values, &positions, &folded_positions, domain_size);
        // let actual_evaluation = get_query_values2(
        //     queried_layers.clone(),
        //     &positions,
        //     &folded_positions,
        //     domain_size,
        // );

        let mut verifier_channel = FridaVerifierChannel::<E, HRandom>::new(
            das_commitment.proof.clone(),
            layer_commitments.clone(),
            domain_size.clone(),
            options.folding_factor(),
        )
        .map_err(|_e| FridaError::InvalidDASCommitment)?;

        //       // determine which evaluations were queried in the folded layer
        //       let mut folded_positions =
        //       fold_positions(&positions, domain_size, self.options.folding_factor());
        //   // determine where these evaluations are in the commitment Merkle tree
        let position_indexes = map_positions_to_indexes(
            &folded_positions,
            domain_size,
            options.folding_factor(),
            num_partitions,
        );
        let layer_commitment = layer_commitments[0];
        let layer_values = verifier_channel
            .read_layer_queries(&position_indexes, &layer_commitment)
            .unwrap();
        let query_values =
            get_query_values::<E, 2>(&layer_values, &positions, &folded_positions, domain_size);
        //   if evaluations != query_values {
        //       return Err(VerifierError::InvalidLayerFolding(depth));
        //   }
        // verifier_channel.take_next_fri_layer_queries();

        // let layer_values =
        //     verifier_channel.read_layer_queries(&position_indexes, &layer_commitment)?;

        println!("query_values in verifier::new(): {:?}", query_values);

        let mut verifier_channel = FridaVerifierChannel::<E, HRandom>::new(
            das_commitment.proof,
            layer_commitments.clone(),
            domain_size.clone(),
            options.folding_factor(),
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
    ) -> Result<(), FridaError> {
        let mut verifier_channel = FridaVerifierChannel::<E, HRandom>::new(
            proof,
            self.layer_commitments.clone(),
            self.domain_size.clone(),
            self.options.folding_factor(),
        )
        .map_err(|_e| FridaError::DeserializationError())?;

        let frida_verifier = FridaVerifier2::<E, HRandom>::new(
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

fn get_query_values2<E: FieldElement>(
    values: Vec<Vec<E>>,
    positions: &[usize],
    folded_positions: &[usize],
    domain_size: usize,
) -> Vec<E> {
    let length = values.first().unwrap().len();
    let row_length = domain_size / length;

    let mut result = Vec::new();
    for position in positions {
        let idx = folded_positions
            .iter()
            .position(|&v| v == position % row_length)
            .unwrap();
        let value = values[idx][position / row_length];
        result.push(value);
    }

    result
}
#[cfg(test)]
mod test {
    use winter_crypto::hashers::Blake3_256;
    use winter_fri::FriOptions;
    use winter_math::fields::f128::BaseElement;
    use winter_rand_utils::rand_vector;

    use crate::{
        frida_data::{build_evaluations_from_data, encoded_data_element_count},
        frida_prover::{traits::BaseFriProver, FridaProver},
        frida_prover_channel::FridaProverChannel,
        frida_random::{FridaRandom, FridaRandomCoin},
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
        let (commitment, _) = prover.commit(data.clone(), 31).unwrap();

        let mut public_coin =
            FridaRandom::<Blake3_256<BaseElement>, Blake3_256<BaseElement>, BaseElement>::new(&[
                123,
            ]);

        let encoded_element_count = encoded_data_element_count::<BaseElement>(data.len());

        let verifier = FridaDasVerifier::new(
            commitment,
            &mut public_coin,
            options.clone(),
            encoded_element_count - 1,
        )
        .unwrap();

        // query for a position
        let open_position = [1];
        let proof = prover.open(&open_position);

        let domain_size = (encoded_element_count - 1).next_power_of_two() * options.blowup_factor();
        let evaluations: Vec<BaseElement> =
            build_evaluations_from_data(&data, domain_size, options.blowup_factor()).unwrap();

        let queried_evaluations = open_position
            .iter()
            .map(|&p| evaluations[p])
            .collect::<Vec<_>>();
        let result = verifier.verify(proof, &queried_evaluations, &open_position);

        assert!(result.is_ok(), "{:?}", result.err().unwrap());
    }
}
