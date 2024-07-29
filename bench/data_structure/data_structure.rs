use winter_math::{FieldElement, fields::{f64, f128}};
use winter_rand_utils::rand_vector;

pub struct DataDesign {
    // for now, the only field needed is size..
    pub chunk_amount: usize
}

impl DataDesign {
    pub fn new(chunk_amount: usize) -> DataDesign {
        DataDesign {
            chunk_amount
        }
    }


    // Approach 1 data creation:
    pub fn create_data(&self) -> Vec<Vec<u8>> {
        // let square_root_size = (self.chunk_amount as f64).sqrt().ceil() as usize;

        // Another way to create a 2D matrix:
        // let data = Array::<u8, _>::random((squared_size, squared_size), Standard);
    
        let mut res = Vec::with_capacity(self.chunk_amount as usize);
        for _ in 0..self.chunk_amount {
            res.push(rand_vector::<u8>(self.chunk_amount as usize));
        }
        res
    }

    // Approach 2 data creation:
    pub fn create_subsquare_data(&self) -> Vec<Vec<Vec<u8>>> {
        // let cubic_root_size = f64::powf(self.chunk_amount as f64, 1.0 / 3.0).ceil() as u8;
        let mut res = Vec::with_capacity(self.chunk_amount as usize);
    
        for _ in 0..self.chunk_amount {
            let mut app_res = Vec::with_capacity(self.chunk_amount as usize);
            for _ in 0..self.chunk_amount {
                app_res.push(rand_vector::<u8>(self.chunk_amount as usize));
            }
            res.push(app_res);
        }
        res
    }
}

// fn main() {
//     let datas = DataDesign {
//         batch_size: 2,
//         chunk_amounts: 114680,
//         element_bytes: 8
//     };

//     let batch_size = datas.create_data();

//     DataDesign::new(batch_size, chunk_amount, element_bytes)
// }