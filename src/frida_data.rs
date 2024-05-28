use crate::frida_error::FridaError;
use core::mem;
use winter_math::{fft::{self, get_twiddles}, polynom, FieldElement, StarkField};

fn encode_data<E: FieldElement + StarkField>(
    data: &[u8],
    domain_size: usize,
    blowup_factor: usize,
) -> Vec<u8> {
    // -1 to make sure the data cannot exceed the field prime
    let element_size = E::ELEMENT_BYTES - 1;
    let data_size = data.len();

    // element_size - 1 is to force a round up
    let encoded_elements = (mem::size_of::<u64>() + data_size + element_size - 1) / element_size;
    assert!(
        encoded_elements <= domain_size / blowup_factor,
        "Data size will exceed the maximum degree after encoding"
    );

    let mut encoded_data = vec![0; encoded_elements * E::ELEMENT_BYTES];

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

fn data_to_field_element<E: FieldElement + StarkField>(
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

pub fn build_evaluations_from_data<E: FieldElement + StarkField>(
    data: &[u8],
    domain_size: usize,
    blowup_factor: usize,
) -> Result<Vec<E>, FridaError> {
    let encoded_data = encode_data::<E>(data, domain_size, blowup_factor);
    let mut symbols: Vec<E> = data_to_field_element(&encoded_data, domain_size)?;
    symbols.resize(domain_size / blowup_factor, E::default());

    let inv_twiddles = fft::get_inv_twiddles::<E>(symbols.len());
    fft::interpolate_poly(&mut symbols, &inv_twiddles);

    symbols.resize(domain_size, E::default());
    let twiddles = fft::get_twiddles::<E>(domain_size);
    fft::evaluate_poly(&mut symbols, &twiddles);

    Ok(symbols)
}

pub fn recover_data_from_evaluations<E: FieldElement + StarkField>(
    evaluations: &[E],
    positions: &[usize],
    domain_size: usize,
    blowup_factor: usize,
) -> Result<Vec<u8>, FridaError> {
    if positions.len() < domain_size / blowup_factor {
        return Err(FridaError::NotEnoughDataPoints());
    }
    if evaluations.len() != positions.len() {
        return Err(FridaError::XYCoordinateLengthMismatch());
    }
    let element_size = E::ELEMENT_BYTES - 1;

    let omega = E::get_root_of_unity(domain_size.ilog2());
    let xs = positions
        .iter()
        .map(|pos| omega.exp_vartime(E::PositiveInteger::from(*pos as u64)))
        .collect::<Vec<E>>();
    // TODO: This is too slow. Need to figure out how to use fft::interpolate_poly here
    let mut coefficients = polynom::interpolate(&xs, evaluations, false);

    let twiddles = get_twiddles(domain_size);
    fft::evaluate_poly(&mut coefficients, &twiddles);

    let data_len =
        u64::from_be_bytes(coefficients[0].as_bytes()[0..8].try_into().unwrap()) as usize;
    let recovered = coefficients
        .iter()
        .step_by(blowup_factor)
        .take((8 + data_len + element_size - 1) / element_size)
        .flat_map(|coeff| coeff.as_bytes()[..element_size].to_vec())
        .skip(8)
        .take(data_len)
        .collect::<Vec<u8>>();
    Ok(recovered)
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
}
