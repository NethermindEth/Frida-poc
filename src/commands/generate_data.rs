use std::fs;
use std::fs::File;
use std::io::Write;
use winter_rand_utils::rand_vector;

pub fn run(size: usize, file_path: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Generate random data
    let data = rand_vector::<u8>(size);

    // Ensure directory exists
    if let Some(parent) = std::path::Path::new(file_path).parent() {
        fs::create_dir_all(parent).expect("Unable to create directories");
    }

    // Write data to file
    let mut file = File::create(file_path).expect("Unable to create file");
    file.write_all(&data).expect("Unable to write data");

    // Print success message
    println!("Generated data of size {} and saved to {}", size, file_path);

    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Read;

    #[test]
    fn test_generate_data() {
        let size = 200;
        let file_path = "data/data.bin";

        // Ensure directory exists
        if let Some(parent) = std::path::Path::new(file_path).parent() {
            fs::create_dir_all(parent).expect("Unable to create directories");
        }

        // Generate data and write to file
        let data = run(size, file_path).unwrap();

        // Read data from file
        let mut file = File::open(file_path).expect("Unable to open file");
        let mut file_data = Vec::new();
        file.read_to_end(&mut file_data)
            .expect("Unable to read file");

        // Verify data
        assert_eq!(data, file_data);

        // Clean up
        fs::remove_file(file_path).expect("Unable to delete file");
    }
}
