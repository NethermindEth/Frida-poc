use crate::{
    constants,
    core::data::encoded_data_element_count,
    error::FridaError,
    winterfell::{f128::BaseElement, FriOptions},
};


/// Calculates the required number of FRI queries (`σ`) for a given security level.
///
/// # Parameters
/// - `data_size`: The size of the original data in bytes.
/// - `options`: The `FriOptions` struct containing blowup factor, folding factor, etc.
/// - `batch_size`: The number of polynomials being batched together.
/// - `lambda_security`: The target cryptographic security level in bits (e.g., 128).
///
/// # Returns
/// The calculated number of queries as a `usize`, capped at `domain_size - 1`.
pub fn calculate_num_queries(
    data_size: usize,
    options: &FriOptions,
    batch_size: usize,
    lambda_security: u32,
) -> Result<usize, FridaError> {
    let blowup_factor = options.blowup_factor();
    if blowup_factor <= 1 {
        return Err(FridaError::InvalidBlowupFactor);
    }

    // Determine the evaluation domain size based on data and blowup factor.
    let encoded_element_count = encoded_data_element_count::<BaseElement>(data_size);
    let domain_size = usize::max(
        encoded_element_count.next_power_of_two() * blowup_factor,
        constants::MIN_DOMAIN_SIZE,
    );

    // The degree of the polynomial.
    let degree = (domain_size / blowup_factor) - 1;

    // Calculate the security loss due to folding, if any.
    let security_loss =
        security_loss_due_to_folding(degree, options.folding_factor(), options.remainder_max_degree());

    // Main formula calculation
    let log2_blowup = (blowup_factor as f64).log2();
    let log2_batch_size = if batch_size > 0 {
        (batch_size as f64).log2()
    } else {
        0.0 
    };

    let num_queries_float =
        (lambda_security as f64 / log2_blowup) + security_loss + log2_batch_size;

    let calculated_queries = num_queries_float.ceil() as usize;

    // The number of queries cannot exceed the number of available points in the domain.
    let max_possible_queries = domain_size.saturating_sub(1);

    Ok(calculated_queries.min(max_possible_queries))
}

/// Calculates the security loss incurred from using a folding factor greater than 2.
fn security_loss_due_to_folding(degree: usize, folding_factor: usize, max_remainder_degree: usize) -> f64 {
    if folding_factor <= 2 {
        return 0.0;
    }

    // The number of coefficients is degree + 1.
    let poly_coeffs = (degree + 1) as f64;
    let remainder_poly_coeffs = (max_remainder_degree + 1) as f64;
    
    // If the polynomial is already smaller than the target remainder, no folding occurs.
    if poly_coeffs <= remainder_poly_coeffs {
        return 0.0;
    }

    let phi = folding_factor as f64;
    let log2_phi = phi.log2();

    let inner_log = (poly_coeffs / remainder_poly_coeffs).log2();
    
    log2_phi * (inner_log / log2_phi).ceil()
}



#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::data::encoded_data_element_count;
    use crate::constants;
    use crate::winterfell::f128::BaseElement;

    #[test]
    fn test_basic_calculation() {
        let options = FriOptions::new(8, 4, 63);
        let queries = calculate_num_queries(1024 * 32, &options, 1, 128).unwrap();
        // For 32KB data, domain_size is correctly calculated as 32768.
        // Degree = 32768/8 - 1 = 4095. Coeffs = 4096. Remainder coeffs = 64.
        // loss = log2(4) * ceil(log2(4096/64)/log2(4)) = 2 * ceil(log2(64)/2) = 2 * ceil(6/2) = 2*3 = 6
        // queries = ceil(128/log2(8) + 6 + 0) = ceil(42.66 + 6) = ceil(48.66) = 49
        assert_eq!(queries, 49);
    }

    #[test]
    fn test_common_case_blowup_2_folding_2() {

        let options = FriOptions::new(2, 2, 0);
        let queries = calculate_num_queries(1024 * 64, &options, 1, 128).unwrap();
        // Expected: ceil(128/log2(2) + 0 + 0) = ceil(128/1) = 128
        assert_eq!(queries, 128);


        let queries_batched = calculate_num_queries(1024 * 64, &options, 32, 128).unwrap();
        // Expected: ceil(128/1 + 0 + log2(32)) = ceil(128 + 5) = 133
        assert_eq!(queries_batched, 133);
    }

    #[test]
    fn test_folding_factor_of_two() {
        let options = FriOptions::new(4, 2, 15);
        let queries = calculate_num_queries(1024, &options, 1, 100).unwrap();
        // Expected: ceil(100/log2(4) + 0 + 0) = ceil(100/2) = 50
        assert_eq!(queries, 50);
    }

    #[test]
    fn test_with_batching() {
        let options = FriOptions::new(4, 2, 15);
        let queries = calculate_num_queries(1024, &options, 16, 100).unwrap();
        // Expected: ceil(100/log2(4) + 0 + log2(16)) = ceil(50 + 4) = 54
        assert_eq!(queries, 54);
    }

    #[test]
    fn test_query_capping() {

        let data_size = 10;
        let options = FriOptions::new(16, 4, 3);
        // Use a very high security parameter to force a large number of queries.
        let queries = calculate_num_queries(data_size, &options, 1, 200).unwrap();

        let encoded_element_count = encoded_data_element_count::<BaseElement>(data_size);
        let domain_size = usize::max(
            encoded_element_count.next_power_of_two() * options.blowup_factor(),
            constants::MIN_DOMAIN_SIZE,
        );
        
        // The result must be capped at domain_size - 1.
        assert_eq!(queries, domain_size - 1);
        // For these parameters, domain_size is 32, so queries should be 31.
        assert_eq!(queries, 31);
    }
    
    #[test]
    fn test_invalid_blowup_factor() {
        let options = FriOptions::new(1, 4, 7); // Invalid blowup factor
        let result = calculate_num_queries(100, &options, 1, 128);
        assert_eq!(result, Err(FridaError::InvalidBlowupFactor));
    }
    
    #[test]
    fn test_zero_lambda() {
        let options = FriOptions::new(8, 4, 3);
        let queries = calculate_num_queries(256, &options, 1, 0).unwrap();
        // Expected: Domain size = 256. Degree = 256/8 - 1 = 31. Coeffs = 32. Remainder Coeffs = 4.
        // loss = 2 * ceil(log2(32/4)/2) = 2 * ceil(log2(8)/2) = 2 * ceil(3/2) = 2*2 = 4
        // queries = ceil(0 + 4 + 0) = 4
        assert_eq!(queries, 4);
    }
}
