use std::{fs, io::Write, path::Path};
use winter_math::{
    fields::{f128, f64},
    FieldElement,
};

pub const RUNS: usize = 10;

pub fn get_standard_fri_options() -> Vec<(usize, usize, usize)> {
    vec![
        (2, 2, 0),
        (2, 2, 256),
        (2, 4, 2),
        (2, 4, 256),
        (2, 8, 4),
        (2, 8, 256),
        (2, 16, 8),
        (2, 16, 256),
    ]
}

pub fn get_standard_data_sizes<E: FieldElement>() -> Vec<usize> {
    vec![
        (128 * 1024) / E::ELEMENT_BYTES * (E::ELEMENT_BYTES - 1) - 8,
        (256 * 1024) / E::ELEMENT_BYTES * (E::ELEMENT_BYTES - 1) - 8,
        (512 * 1024) / E::ELEMENT_BYTES * (E::ELEMENT_BYTES - 1) - 8,
        (1024 * 1024) / E::ELEMENT_BYTES * (E::ELEMENT_BYTES - 1) - 8,
        (2048 * 1024) / E::ELEMENT_BYTES * (E::ELEMENT_BYTES - 1) - 8,
    ]
}

pub fn get_standard_num_queries() -> Vec<usize> {
    vec![8, 16, 32]
}

pub fn get_standard_batch_sizes() -> Vec<usize> {
    vec![2, 4, 8, 16]
}

pub fn get_standard_validator_counts() -> Vec<usize> {
    vec![4, 8, 16, 32, 64, 128, 512, 1024]
}

/// Creates output directory if it doesn't exist
pub fn ensure_output_dir(output_path: &str) -> std::io::Result<()> {
    if let Some(parent) = Path::new(output_path).parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

/// Saves results with CSV header to file
pub fn save_results_with_header<T>(
    results: &[T],
    output_path: &str,
    header: &str,
    to_csv: fn(&T) -> String,
) -> std::io::Result<()>
where
    T: std::fmt::Debug,
{
    ensure_output_dir(output_path)?;

    let mut file = fs::File::create(output_path)?;
    writeln!(file, "{header}")?;

    for result in results {
        writeln!(file, "{}", to_csv(result))?;
    }

    println!("Results saved to: {output_path}");
    println!("Total results: {}", results.len());
    Ok(())
}

pub mod field_names {
    pub const F64: &str = "f64";
    pub const F128: &str = "f128";
}

pub type F64Element = f64::BaseElement;
pub type F128Element = f128::BaseElement;
pub type Blake3F64 = winter_crypto::hashers::Blake3_256<F64Element>;
pub type Blake3F128 = winter_crypto::hashers::Blake3_256<F128Element>;
