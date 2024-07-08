use winter_math::FieldElement;

pub mod das;
mod test;
pub mod traits;

fn get_query_values<E: FieldElement, const N: usize>(
    values: &[[E; N]],
    positions: &[usize],
    folded_positions: &[usize],
    domain_size: usize,
) -> Vec<E> {
    let row_length = domain_size / N;

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

fn get_batch_query_values<E: FieldElement, const N: usize>(
    values: &[Vec<E>],
    positions: &[usize],
    folded_positions: &[usize],
    domain_size: usize,
    batch_size: usize,
) -> Vec<E> {
    let row_length = domain_size / N;
    let mut result = Vec::with_capacity(batch_size * positions.len());
    for position in positions.iter() {
        let idx = folded_positions
            .iter()
            .position(|&v| v == position % row_length)
            .unwrap();
        values[idx][(position / row_length) * batch_size
            ..(position / row_length) * batch_size + batch_size]
            .iter()
            .for_each(|e| {
                result.push(*e);
            });
    }
    result
}

// Evaluates a polynomial with coefficients in an extension field at a point in the base field.
pub fn eval_horner<E>(p: &[E], x: E::BaseField) -> E
where
    E: FieldElement,
{
    p.iter()
        .rev()
        .fold(E::ZERO, |acc, &coeff| acc * E::from(x) + coeff)
}

#[cfg(test)]
mod tests {
    use winter_crypto::hashers::Blake3_256;
    use winter_fri::FriOptions;
    use winter_math::fields::f128::BaseElement;
    use winter_rand_utils::rand_vector;

    use crate::{
        frida_data::{build_evaluations_from_data, encoded_data_element_count},
        frida_prover::{traits::BaseFriProver, FridaProver},
        frida_prover_channel::FridaProverChannel,
        frida_random::{FridaRandom, FridaRandomCoin},
        frida_verifier::{das::FridaDasVerifier, traits::BaseFridaVerifier},
    };

    type FridaTestProver = FridaProver<
        BaseElement,
        BaseElement,
        FridaProverChannel<
            BaseElement,
            Blake3_256<BaseElement>,
            Blake3_256<BaseElement>,
            FridaRandom<Blake3_256<BaseElement>, Blake3_256<BaseElement>, BaseElement>,
        >,
        Blake3_256<BaseElement>,
    >;

    // FIXME: This test fails with DegreeTruncation(0, 2, 1) or InvalidDASCommitment!
    #[test]
    fn test_frida_das_verify_short() {
        let max_remainder_degree = 0;
        // TODO: Alternatively:
        let max_remainder_degree = 1;
        let folding_factor = 2;
        let blowup_factor = 2;

        let options = FriOptions::new(blowup_factor, folding_factor, max_remainder_degree);

        // instantiate the prover and generate the proof
        let mut prover: FridaTestProver = FridaProver::new(options.clone());

        let data: Vec<_> = (0..20).collect();
        let encoded_element_count =
            encoded_data_element_count::<BaseElement>(data.len()).next_power_of_two();
        let (commitment, _) = prover.commit(data.clone(), 3).unwrap();

        let mut public_coin =
            FridaRandom::<Blake3_256<BaseElement>, Blake3_256<BaseElement>, BaseElement>::new(&[
                123,
            ]);

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
        verifier.verify(proof, &queried_evaluations, &open_position).unwrap();
    }

    #[test]
    fn test_frida_das_verify() {
        let max_remainder_degree = 7;
        let folding_factor = 2;
        let blowup_factor = 8;

        let options = FriOptions::new(blowup_factor, folding_factor, max_remainder_degree);

        // instantiate the prover and generate the proof
        let mut prover: FridaTestProver = FridaProver::new(options.clone());

        let data = rand_vector::<u8>(200);
        let encoded_element_count =
            encoded_data_element_count::<BaseElement>(data.len()).next_power_of_two();
        let (commitment, _) = prover.commit(data.clone(), 31).unwrap();

        let mut public_coin =
            FridaRandom::<Blake3_256<BaseElement>, Blake3_256<BaseElement>, BaseElement>::new(&[
                123,
            ]);

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
        verifier.verify(proof, &queried_evaluations, &open_position).unwrap();
    }
}
