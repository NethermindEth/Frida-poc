use winter_math::FieldElement;

mod channel;

pub mod das;

#[cfg(test)]
mod tests;

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