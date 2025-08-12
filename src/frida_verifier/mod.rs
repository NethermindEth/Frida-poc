use winter_math::FieldElement;

mod channel;
pub mod das;

#[cfg(test)]
mod test;

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
    values: &[E],
    positions: &[usize],
    folded_positions: &[usize],
    domain_size: usize,
    poly_count: usize,
) -> Vec<E> {
    let row_length = domain_size / N;
    let mut result = Vec::with_capacity(poly_count * positions.len());
    for position in positions.iter() {
        let idx = folded_positions
            .iter()
            .position(|&v| v == position % row_length)
            .unwrap();
        let start = idx * (poly_count * N) + (position / row_length) * poly_count;
        values[start..start + poly_count].iter().for_each(|e| {
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
    use winter_fri::FriOptions;
    use winter_math::fields::f128::BaseElement;
    use winter_rand_utils::rand_vector;

    use crate::core::data::{build_evaluations_from_data, encoded_data_element_count};
    use crate::utils::test_utils::*;

    #[test]
    fn test_frida_das_verify_short() {
        for max_remainder_degree in [0, 1] {
            let folding_factor = 2;
            let blowup_factor = 2;

            let options = FriOptions::new(blowup_factor, folding_factor, max_remainder_degree);

            // instantiate the prover and generate the proof
            let prover_builder = TestFridaProverBuilder::new(options.clone());

            let data: Vec<_> = (0..20).collect();
            let (commitment, prover) =
                prover_builder.commit_and_prove(&data, 3).unwrap();

            let (verifier, _coin) = TestFridaDasVerifier::new(commitment, options.clone()).unwrap();

            // query for a position
            let open_position = [1];
            let proof = prover.open(&open_position);

            let domain_size = 8;
            let evaluations: Vec<BaseElement> =
                build_evaluations_from_data(&data, domain_size, options.blowup_factor()).unwrap();

            let queried_evaluations = open_position
                .iter()
                .map(|&p| evaluations[p])
                .collect::<Vec<_>>();
            verifier
                .verify(&proof, &queried_evaluations, &open_position)
                .unwrap();
        }
    }

    #[test]
    fn test_frida_das_verify() {
        let max_remainder_degree = 7;
        let folding_factor = 2;
        let blowup_factor = 8;

        let options = FriOptions::new(blowup_factor, folding_factor, max_remainder_degree);

        // instantiate the prover and generate the proof
        let prover_builder = TestFridaProverBuilder::new(options.clone());

        let data = rand_vector::<u8>(200);
        let encoded_element_count =
            encoded_data_element_count::<BaseElement>(data.len()).next_power_of_two();
        let (commitment, prover) =
            prover_builder.commit_and_prove(&data, 31).unwrap();

        let (verifier, _coin) = TestFridaDasVerifier::new(commitment, options.clone()).unwrap();

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
        verifier
            .verify(&proof, &queried_evaluations, &open_position)
            .unwrap();
    }
}
