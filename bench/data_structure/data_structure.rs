use winter_math::{FieldElement, fields::{f64, f128}};
use winter_rand_utils::rand_vector;

pub struct DataDesign {
    pub chunk_amount: usize
}

impl DataDesign {
    pub fn new(chunk_amount: usize) -> DataDesign {
        DataDesign {
            chunk_amount
        }
    }

    fn data_size<E: FieldElement>(chunk_amount: usize) -> usize {
        chunk_amount * E::ELEMENT_BYTES - (mem::size_of::<u64>() + E::ELEMENT_BYTES - 1)
    }

    // Approach 1 data creation:
    pub fn create_data(&self) -> Vec<Vec<u8>> {
        let square_k = (self.chunk_amount as f64).sqrt().ceil() as usize;
        let data_size = data_size(square_k);
    
        let mut res = Vec::with_capacity(square_k);

        for _ in 0..square_k {
            res.push(rand_vector::<u8>(data_size));
        }
        res
    }

    // Approach 2 data creation:
    pub fn create_subsquare_data(&self) -> Vec<Vec<Vec<u8>>> {
        let cubic_k = f64::powf(self.chunk_amount as f64, 1.0 / 3.0).ceil() as usize;
        let data_size = data_size(square_k);

        let mut res = Vec::with_capacity(cubic_k);
    
        for _ in 0..cubic_k {
            let mut app_res = Vec::with_capacity(cubic_k);
            for _ in 0..cubic_k {
                app_res.push(rand_vector::<u8>(data_size));
            }
            res.push(app_res);
        }
        res
    }
}
