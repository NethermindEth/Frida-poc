use winter_math::{FieldElement, fields::{f64, f128}};
use winter_rand_utils::rand_vector;
use core::mem;

pub struct DataDesign {
    pub chunk_amount: usize
}

impl DataDesign {

    pub fn data_size<E: FieldElement>(chunk_amount: usize) -> usize {
        chunk_amount * E::ELEMENT_BYTES - (mem::size_of::<u64>() + E::ELEMENT_BYTES - 1)
    }

    /// The function generates the numbers within the specified limit range
    /// that can both be square-rooted and cube-rooted.
    /// Essentially these are numbers that are perfect sixth powers.
    pub fn generate_sixth_powers(lower_limit: usize, upper_limit: usize) -> Vec<usize> {
        (1_usize..)
            .map(|n| n.pow(6))
            .skip_while(|&x| x < lower_limit)
            .take_while(|&x| x <= upper_limit)
            .collect()
    }
    

    /// Function for Approach 1 data creation:
    pub fn create_data<E: FieldElement>(&self) -> Vec<Vec<u8>> {
        let square_k = (self.chunk_amount as f64).sqrt().ceil() as usize;
        let data_size = DataDesign::data_size::<E>(square_k);
    
        (0..square_k)
            .map(|_| rand_vector::<u8>(data_size))
            .collect()
    }

    /// Function for Approach 2 data creation:
    pub fn create_subsquare_data<E: FieldElement>(&self) -> Vec<Vec<Vec<u8>>> {
        let cubic_k = f64::powf(self.chunk_amount as f64, 1.0 / 3.0).ceil() as usize;
        let data_size = DataDesign::data_size::<E>(cubic_k);
    
        (0..cubic_k)
            .map(|_| {
                (0..cubic_k)
                    .map(|_| rand_vector::<u8>(data_size))
                    .collect()
            })
            .collect()
    }
}
