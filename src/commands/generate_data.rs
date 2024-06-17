use std::fs::File;
use std::io::Write;
use winter_rand_utils::rand_vector;

pub fn run(size: usize, file_path: &str) {
    let data = rand_vector::<u8>(size);
    let mut file = File::create(file_path).expect("Unable to create file");
    file.write_all(&data).expect("Unable to write data");
    println!("Generated data of size {} and saved to {}", size, file_path);
}
