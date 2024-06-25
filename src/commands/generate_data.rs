use std::fs::File;
use std::io::Write;
use winter_rand_utils::rand_vector;

pub fn run(size: usize, file_path: &str) {
    let data = rand_vector::<u8>(size);
    let mut file = File::create(file_path).expect("Unable to create file");
    file.write_all(&data).expect("Unable to write data");
    println!("Generated data of size {} and saved to {}", size, file_path);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_generate_data() {
        let size = 200;
        let file_path = "data/data.bin";
        run(size, file_path);
        let metadata = fs::metadata(file_path).expect("Unable to read metadata");
        assert!(metadata.is_file());
        assert_eq!(metadata.len(), size as u64);
    }
}
