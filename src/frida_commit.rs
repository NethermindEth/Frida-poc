use winter_crypto::ElementHasher;
use winter_fri::{FriOptions, FriProof, FriProver};
use winter_math::{FieldElement, StarkField};

use crate::{
    frida_const,
    frida_data::{build_evaluations_from_data, encoded_data_element_count},
    frida_error::FridaError,
    frida_prover_channel::FridaProverChannel,
    frida_random::FridaRandomCoin,
};

#[derive(Debug, PartialEq)]
pub struct Commitment<HRoot: ElementHasher> {
    pub roots: Vec<HRoot::Digest>,
    pub proof: FriProof,
}

pub fn commit<E, HHst, HRandom, R>(
    data: Vec<u8>,
    num_queries: usize,
    options: FriOptions,
) -> Result<(Commitment<HRandom>, Vec<u8>), FridaError>
where
    E: FieldElement + StarkField,
    HHst: ElementHasher<BaseField = E::BaseField>,
    HRandom: ElementHasher<BaseField = E::BaseField>,
    R: FridaRandomCoin<
        BaseField = E::BaseField,
        FieldElement = E,
        HashHst = HHst,
        HashRandom = HRandom,
    >, // R: FridaRandomCoin<BaseField = E::BaseField, HashHst = HHst, HashRandom = HRandom>,
{
    // TODO: Decide if we want to dynamically set domain_size like here
    let blowup_factor = options.blowup_factor();
    let encoded_element_count = encoded_data_element_count::<E>(data.len());

    let domain_size = usize::max(
        (encoded_element_count * blowup_factor).next_power_of_two(),
        frida_const::MIN_DOMAIN_SIZE,
    );

    if domain_size > frida_const::MAX_DOMAIN_SIZE {
        return Err(FridaError::DomainSizeTooBig(domain_size));
    }
    if num_queries >= domain_size || num_queries == 0 {
        return Err(FridaError::BadNumQueries(num_queries));
    }

    let evaluations = build_evaluations_from_data::<E>(&data, domain_size, blowup_factor)?;
    let mut prover = FriProver::new(options);
    let mut channel = FridaProverChannel::<E, HHst, HRandom, R>::new(domain_size, num_queries);
    prover.build_layers(&mut channel, evaluations);

    let query_positions = channel.draw_query_positions();
    let proof = prover.build_proof(&query_positions);

    Ok((
        Commitment {
            roots: channel.layer_commitments().to_vec(),
            proof,
        },
        data,
    ))
}

#[cfg(test)]
mod tests {
    use crate::frida_random::FridaRandom;

    use super::*;
    use winter_crypto::hashers::Blake3_256;
    use winter_math::fields::f128::BaseElement;
    use winter_rand_utils::rand_vector;

    #[test]
    fn test_commit() {
        let options = FriOptions::new(2, 2, 0);

        let domain_error = commit::<
            BaseElement,
            Blake3_256<BaseElement>,
            Blake3_256<BaseElement>,
            FridaRandom<Blake3_256<BaseElement>, Blake3_256<BaseElement>, BaseElement>,
        >(
            vec![0; frida_const::MAX_DOMAIN_SIZE * 15 / 2 + 1],
            1,
            options.clone(),
        )
        .unwrap_err();
        assert_eq!(
            FridaError::DomainSizeTooBig(frida_const::MAX_DOMAIN_SIZE * 2),
            domain_error
        );

        let num_qeuries_error_zero = commit::<
            BaseElement,
            Blake3_256<BaseElement>,
            Blake3_256<BaseElement>,
            FridaRandom<Blake3_256<BaseElement>, Blake3_256<BaseElement>, BaseElement>,
        >(rand_vector::<u8>(10), 0, options.clone())
        .unwrap_err();
        assert_eq!(FridaError::BadNumQueries(0), num_qeuries_error_zero);

        let num_qeuries_error_bigger_than_domain =
            commit::<
                BaseElement,
                Blake3_256<BaseElement>,
                Blake3_256<BaseElement>,
                FridaRandom<Blake3_256<BaseElement>, Blake3_256<BaseElement>, BaseElement>,
            >(rand_vector::<u8>(200), 32, options.clone())
            .unwrap_err();
        assert_eq!(
            FridaError::BadNumQueries(32),
            num_qeuries_error_bigger_than_domain
        );

        // Make sure minimum domain size is correctly enforced
        let (commitment, _) = commit::<
            BaseElement,
            Blake3_256<BaseElement>,
            Blake3_256<BaseElement>,
            FridaRandom<Blake3_256<BaseElement>, Blake3_256<BaseElement>, BaseElement>,
        >(rand_vector::<u8>(1), 1, options.clone())
        .unwrap();
        assert_eq!(
            frida_const::MIN_DOMAIN_SIZE.ilog2() as usize,
            commitment.roots.len()
        );

        let data = rand_vector::<u8>(200);
        let (commitment, state) = commit::<
            BaseElement,
            Blake3_256<BaseElement>,
            Blake3_256<BaseElement>,
            FridaRandom<Blake3_256<BaseElement>, Blake3_256<BaseElement>, BaseElement>,
        >(data.clone(), 31, options.clone())
        .unwrap();

        let evaluations = build_evaluations_from_data(&data, 32, 2).unwrap();
        let mut prover = FriProver::new(options.clone());
        let mut channel = FridaProverChannel::<
            BaseElement,
            Blake3_256<BaseElement>,
            Blake3_256<BaseElement>,
            FridaRandom<Blake3_256<BaseElement>, Blake3_256<BaseElement>, BaseElement>,
        >::new(32, 31);
        prover.build_layers(&mut channel, evaluations.clone());
        let positions = channel.draw_query_positions();
        let proof = prover.build_proof(&positions);

        assert_eq!(
            commitment,
            Commitment {
                roots: channel.layer_commitments().to_vec(),
                proof: proof
            }
        );
        assert_eq!(state, data);
    }
}
