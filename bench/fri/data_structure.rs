use winter_math::{FieldElement, fields::{f64, f128}};
use winter_rand_utils::rand_vector;

pub struct DataDesign {
    // for now, the only field needed is size..
    pub data_size: usize
}

impl DataDesign {
    pub fn new(data_size: usize) -> DataDesign {
        DataDesign {
            data_size
        }
    }


    // Approach 1 data creation:
    pub fn create_square_data(&self) -> Vec<Vec<u8>> {
        let square_root_size = (self.data_size as f64).sqrt().ceil() as usize;

        // Another way to create a 2D matrix (just decided to save):
        // let data = Array::<u8, _>::random((squared_size, squared_size), Standard);
    
        let mut res = Vec::with_capacity(square_root_size as usize);
        for _ in 0..square_root_size {
            res.push(rand_vector::<u8>(square_root_size as usize));
        }
        res
    }

    // Approach 2 data creation:
    pub fn create_subsquare_data(&self) -> Vec<Vec<Vec<u8>>> {
        let cubic_root_size = f64::powf(self.data_size as f64, 1.0 / 3.0).ceil() as u8;
    
        let mut res = Vec::with_capacity(cubic_root_size as usize);
    
        for _ in 0..cubic_root_size {
            let mut app_res = Vec::with_capacity(cubic_root_size as usize);
            for _ in 0..cubic_root_size {
                app_res.push(rand_vector::<u8>(cubic_root_size as usize));
            }
            res.push(app_res);
        }
        res
    }
}

// fn main() {
//     let datas = DataDesign {
//         batch_size: 2,
//         data_sizes: 114680,
//         element_bytes: 8
//     };

//     let batch_size = datas.create_data();

//     DataDesign::new(batch_size, data_size, element_bytes)
// }