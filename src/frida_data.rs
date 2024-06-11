use crate::frida_error::FridaError;
use core::mem;
use winter_math::{fft, polynom, FieldElement, StarkField};

pub fn encoded_data_element_count<E: FieldElement>(data_size: usize) -> usize {
    let element_size = E::ELEMENT_BYTES - 1;
    // element_size - 1 is to force a round up
    (mem::size_of::<u64>() + data_size + element_size - 1) / element_size
}

fn encode_data<E: FieldElement>(data: &[u8], domain_size: usize, blowup_factor: usize) -> Vec<u8> {
    // -1 to make sure the data cannot exceed the field prime
    let data_size = data.len();
    let encoded_element_count = encoded_data_element_count::<E>(data_size);
    assert!(
        encoded_element_count <= domain_size / blowup_factor,
        "Data size will exceed the maximum degree after encoding"
    );

    let mut encoded_data = vec![0; encoded_element_count * E::ELEMENT_BYTES];

    let data_size_bytes = (data_size as u64).to_be_bytes();
    let mut index = 0;
    for i in 0..8 {
        encoded_data[index] = data_size_bytes[i];
        index += 1;
    }

    data.iter().for_each(|byte| {
        if (index + 1) % E::ELEMENT_BYTES == 0 {
            index += 1;
        }
        encoded_data[index] = *byte;
        index += 1;
    });

    encoded_data
}

fn data_to_field_element<E: FieldElement>(
    encoded_data: &[u8],
    domain_size: usize,
) -> Result<Vec<E>, FridaError> {
    let mut symbols = Vec::with_capacity(domain_size);
    for chunk in encoded_data.chunks(E::ELEMENT_BYTES) {
        match E::read_from_bytes(chunk) {
            Ok(val) => symbols.push(val),
            Err(_) => return Err(FridaError::DeserializationError()),
        };
    }
    Ok(symbols)
}

// TODO: Decide if we want evaluations to be []DATA + []Parity or DATA[0] + PARITY + DATA[1] + PARITY + ...
pub fn build_evaluations_from_data<E: FieldElement>(
    data: &[u8],
    domain_size: usize,
    blowup_factor: usize,
) -> Result<Vec<E>, FridaError> {
    let encoded_data = encode_data::<E>(data, domain_size, blowup_factor);
    let mut symbols: Vec<E> = data_to_field_element(&encoded_data, domain_size)?;
    symbols.resize(domain_size / blowup_factor, E::default());

    reed_solomon_encode_data(&mut symbols, domain_size / blowup_factor, blowup_factor);

    Ok(symbols)
}

pub fn reed_solomon_encode_data<E: FieldElement>(
    symbols: &mut Vec<E>,
    ori_domain_size: usize,
    blowup_factor: usize,
) {
    let inv_twiddles = fft::get_inv_twiddles(ori_domain_size);
    // let mut symbols = symbols.to_vec();
    fft::interpolate_poly(symbols, &inv_twiddles);

    let domain_size = ori_domain_size * blowup_factor;
    symbols.resize(domain_size, E::default());
    let twiddles = fft::get_twiddles(domain_size);
    fft::evaluate_poly(symbols, &twiddles);
}

fn reconstruct_evaluations<E: FieldElement>(
    evaluations: &[E],
    positions: &[usize],
    domain_size: usize,
    blowup_factor: usize,
) -> Result<Vec<E>, FridaError> {
    if positions.len() < domain_size / blowup_factor {
        return Err(FridaError::NotEnoughDataPoints());
    }
    if evaluations.len() != positions.len() {
        return Err(FridaError::XYCoordinateLengthMismatch());
    }

    let omega = E::from(E::BaseField::get_root_of_unity(domain_size.ilog2()));
    let xs = positions
        .iter()
        .map(|pos| omega.exp_vartime(E::PositiveInteger::from(*pos as u64)))
        .collect::<Vec<E>>();

    // TODO: This is too slow. fft::interpolate_poly is impossible to use as well. Refer to the post below for improvements
    // https://ethresear.ch/t/reed-solomon-erasure-code-recovery-in-n-log-2-n-time-with-ffts/3039
    let mut recovered_evaluations = polynom::interpolate(&xs, evaluations, false);

    recovered_evaluations.resize(domain_size, E::default());
    let twiddles = fft::get_twiddles(domain_size);
    fft::evaluate_poly(&mut recovered_evaluations, &twiddles);

    Ok(recovered_evaluations)
}

fn extract_and_decode_data<E: FieldElement>(
    evaluations: &[E],
    domain_size: usize,
    blowup_factor: usize,
) -> Result<Vec<u8>, FridaError> {
    if evaluations.len() != domain_size {
        return Err(FridaError::NotEnoughEvaluationsForDecoding());
    }

    let element_size = E::ELEMENT_BYTES - 1;
    let data_len = u64::from_be_bytes(
        evaluations[0].as_bytes()[0..core::mem::size_of::<u64>()]
            .try_into()
            .unwrap(),
    ) as usize;
    let encoded_element_count = encoded_data_element_count::<E>(data_len);

    if encoded_element_count > domain_size / blowup_factor {
        return Err(FridaError::BadDataLength());
    }

    let decoded = evaluations
        .iter()
        .step_by(blowup_factor)
        .take(encoded_element_count)
        .flat_map(|e| &e.as_bytes()[..element_size])
        .skip(8)
        .take(data_len)
        .map(|e| *e)
        .collect::<Vec<u8>>();
    Ok(decoded)
}

pub fn recover_data_from_evaluations<E: FieldElement>(
    evaluations: &[E],
    positions: &[usize],
    domain_size: usize,
    blowup_factor: usize,
) -> Result<Vec<u8>, FridaError> {
    // Need to reconstruct if we don't have all the data
    if evaluations.len() != domain_size {
        let evaluations =
            reconstruct_evaluations(evaluations, positions, domain_size, blowup_factor)?;
        return Ok(extract_and_decode_data(
            &evaluations,
            domain_size,
            blowup_factor,
        )?);
    }

    Ok(extract_and_decode_data(
        evaluations,
        domain_size,
        blowup_factor,
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use winter_math::fields::f128::BaseElement;

    #[test]
    fn test_build_evaluations_from_data() {
        let data = b"Test string";
        let blowup_factor = 2;
        let domain_size = (blowup_factor * data.len()).next_power_of_two();
        let data = data.repeat(10);

        let evaluations =
            build_evaluations_from_data::<BaseElement>(&data, domain_size, blowup_factor).unwrap();
        let positions = (0..evaluations.len()).collect::<Vec<usize>>();
        let recovered =
            recover_data_from_evaluations(&evaluations, &positions, domain_size, blowup_factor)
                .unwrap();
        assert_eq!(data, recovered);
    }

    #[test]
    #[should_panic(expected = "Data size will exceed the maximum degree after encoding")]
    fn test_bad_data_size() {
        let data = b"Test string";
        let blowup_factor = 2;
        let domain_size = 4;
        let data = data.repeat(10);
        build_evaluations_from_data::<BaseElement>(&data, domain_size, blowup_factor).unwrap();
    }

    #[test]
    fn recovery_evaluations_and_positions_len_mismatch() {
        let blowup_factor = 2;
        let domain_size = 4;
        assert_eq!(
            FridaError::XYCoordinateLengthMismatch(),
            recover_data_from_evaluations(
                &vec![BaseElement::default(); 10],
                &vec![0; 2],
                domain_size,
                blowup_factor,
            )
            .unwrap_err()
        );
    }

    #[test]
    fn recovery_not_enough_data_points() {
        let blowup_factor = 2;
        let domain_size = 4;
        assert_eq!(
            FridaError::NotEnoughDataPoints(),
            recover_data_from_evaluations(
                &vec![BaseElement::default(); 1],
                &vec![0; 1],
                domain_size,
                blowup_factor,
            )
            .unwrap_err()
        );
    }

    #[test]
    fn test_reed_solomon_encoding() {
        let example_evaluation = vec![
            BaseElement::new(1),
            BaseElement::new(2),
            BaseElement::new(3),
            BaseElement::new(4),
        ];

        let mut reed_solomon_encoded_evaluation = example_evaluation.clone();

        let blowup_factor = 8;
        reed_solomon_encode_data(
            &mut reed_solomon_encoded_evaluation,
            example_evaluation.len(),
            blowup_factor,
        );

        let positions = (0..4).map(|i| i * blowup_factor).collect::<Vec<_>>();
        let rs_evaluations = positions
            .iter()
            .map(|p| reed_solomon_encoded_evaluation[*p])
            .collect::<Vec<_>>();

        assert_eq!(example_evaluation, rs_evaluations);
    }

    #[test]
    fn test_build_evaluations_from_data_exceed_field_prime() {
        let data = [0xff; 10].repeat(16);
        let blowup_factor = 2;
        let domain_size = (blowup_factor * data.len()).next_power_of_two();

        let mut evaluations = vec![BaseElement::default(); domain_size];
        data.chunks(16).enumerate().for_each(|(index, chunk)| {
            let val = u128::from_be_bytes(chunk.try_into().unwrap());
            evaluations[index] = BaseElement::new(val);
        });
        let twiddles = fft::get_twiddles::<BaseElement>(domain_size);
        fft::evaluate_poly(&mut evaluations, &twiddles);

        let inv_twiddles = fft::get_inv_twiddles::<BaseElement>(domain_size);
        fft::interpolate_poly::<BaseElement, BaseElement>(&mut evaluations, &inv_twiddles);
        let recovered: Vec<u8> = evaluations
            .iter()
            .enumerate()
            .filter(|(index, _)| *index < domain_size / blowup_factor)
            .flat_map(|(_, eval)| eval.as_int().to_be_bytes())
            .collect();

        // If data wraps around the field prime then it can't be recovered properly
        assert_ne!(data, recovered);

        let evaluations =
            build_evaluations_from_data::<BaseElement>(&data, domain_size, blowup_factor).unwrap();
        let positions = (0..evaluations.len()).collect::<Vec<usize>>();
        let recovered =
            recover_data_from_evaluations(&evaluations, &positions, domain_size, blowup_factor)
                .unwrap();
        assert_eq!(data, recovered);
    }

    #[test]
    fn test_reconstruct_evaluations() {
        let data = b"Test string";
        let blowup_factor = 2;
        let domain_size = (blowup_factor * data.len()).next_power_of_two();
        let data = data.repeat(10);

        let evaluations =
            build_evaluations_from_data::<BaseElement>(&data, domain_size, blowup_factor).unwrap();
        let positions = (0..evaluations.len() / blowup_factor).collect::<Vec<usize>>();
        let recovered_evaluations = reconstruct_evaluations(
            &evaluations[0..evaluations.len() / blowup_factor],
            &positions,
            domain_size,
            blowup_factor,
        )
        .unwrap();

        let recovered_data = recover_data_from_evaluations(
            &evaluations[0..evaluations.len() / blowup_factor],
            &positions,
            domain_size,
            blowup_factor,
        )
        .unwrap();

        assert_eq!(evaluations, recovered_evaluations);
        assert_eq!(data, recovered_data)
    }

    #[test]
    fn test_extract_and_decode_data() {
        let data = b"Test string";
        let blowup_factor = 2;
        let domain_size = (blowup_factor * data.len()).next_power_of_two();
        let data = data.repeat(10);

        let evaluations =
            build_evaluations_from_data::<BaseElement>(&data, domain_size, blowup_factor).unwrap();

        let recovered_data =
            extract_and_decode_data(&evaluations, domain_size, blowup_factor).unwrap();

        assert_eq!(data, recovered_data);

        let not_enough_evals = extract_and_decode_data(
            &evaluations[0..evaluations.len() - 1],
            domain_size,
            blowup_factor,
        )
        .unwrap_err();

        assert_eq!(
            FridaError::NotEnoughEvaluationsForDecoding(),
            not_enough_evals
        );
    }

    #[test]
    fn test_encoded_data_element_count() {
        let element_size = BaseElement::ELEMENT_BYTES - 1;
        for i in 0..10 {
            let size = 10usize.pow(i) - 1;
            assert_eq!(
                (8 + size + element_size - 1) / element_size,
                encoded_data_element_count::<BaseElement>(size)
            );
        }
    }
}
