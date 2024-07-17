use crate::utils::write_to_file;
use std::{fs, io, path::Path};
use winter_rand_utils::rand_vector;

pub fn run(size: usize, file_path: &Path) -> Result<Vec<u8>, GenerateDataError> {
    // Generate random data
    let data = rand_vector::<u8>(size);

    // Ensure directory exists
    if let Some(parent) = std::path::Path::new(file_path).parent() {
        fs::create_dir_all(parent).map_err(GenerateDataError::IoError)?;
    }

    // Write data to file
    write_to_file(file_path, &data).map_err(GenerateDataError::IoError)?;

    // Print success message
    println!(
        "Generated data of size {} and saved to {}",
        size,
        file_path.display()
    );

    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::{read_file_to_vec, CleanupFiles};

    #[test]
    fn test_generate_data() -> Result<(), GenerateDataError> {
        let size = 200;
        let file_path = Path::new("data/data.bin");

        let _cleanup = CleanupFiles::new(vec![file_path]);

        // Generate data and write to file
        let data = run(size, file_path)?;

        // Read data from file
        let file_data = read_file_to_vec(file_path).map_err(GenerateDataError::IoError)?;

        // Verify data
        assert_eq!(data, file_data);

        Ok(())
    }
}

#[derive(Debug)]
pub enum GenerateDataError {
    IoError(io::Error),
    CustomError(String),
}

impl std::fmt::Display for GenerateDataError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            GenerateDataError::IoError(ref err) => write!(f, "IO error: {}", err),
            GenerateDataError::CustomError(ref err) => write!(f, "Custom error: {}", err),
        }
    }
}

impl std::error::Error for GenerateDataError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            GenerateDataError::IoError(ref err) => Some(err),
            GenerateDataError::CustomError(_) => None,
        }
    }
}

impl From<io::Error> for GenerateDataError {
    fn from(err: io::Error) -> GenerateDataError {
        GenerateDataError::IoError(err)
    }
}
