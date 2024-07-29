use winter_math::{FieldElement, fields::{f64, f128}};
use winter_rand_utils::rand_vector;
use core::mem;

pub struct DataDesign {
    pub chunk_amount: usize
}

impl DataDesign {
    pub fn new(chunk_amount: usize) -> DataDesign {
        DataDesign {
            chunk_amount
        }
    }

    pub fn data_size<E: FieldElement>(chunk_amount: usize) -> usize {
        chunk_amount * E::ELEMENT_BYTES - (mem::size_of::<u64>() + E::ELEMENT_BYTES - 1)
    }

    // the function generates the numbers within the specified limit range
    // that can both be square-rooted and cube-rooted.
    // essentially these are numbers that are perfect sixth powers.
    pub fn generate_sixth_powers(lower_limit: usize, upper_limit: usize) -> Vec<usize> {
        let mut sixth_powers = Vec::new();
        let mut n: usize = 1;
    
        while n.pow(6) < lower_limit {
            n += 1;
        }
    
        while n.pow(6) <= upper_limit {
            sixth_powers.push(n.pow(6));
            n += 1;
        }
    
        sixth_powers
    }
    

    // Approach 1 data creation:
    pub fn create_data<E: FieldElement>(&self) -> Vec<Vec<u8>> {
        let square_k = (self.chunk_amount as f64).sqrt().ceil() as usize;
        let data_size = DataDesign::data_size::<E>(square_k);
    
        let mut res = Vec::with_capacity(square_k);

        for _ in 0..square_k {
            res.push(rand_vector::<u8>(data_size));
        }
        res
    }

    // Approach 2 data creation:
    pub fn create_subsquare_data<E: FieldElement>(&self) -> Vec<Vec<Vec<u8>>> {
        let cubic_k = f64::powf(self.chunk_amount as f64, 1.0 / 3.0).ceil() as usize;
        let data_size = DataDesign::data_size::<E>(cubic_k);

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
