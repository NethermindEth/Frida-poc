//! # Frida-poc
//!
//! A proof-of-concept implementation of FRI (Fast Reed-Solomon Interactive Oracle Proofs of Proximity)
//! for building polynomial commitment schemes. This library is based on components from the
//! Winterfell STARK prover and verifier.
//!
//! ## Core Components
//!
//! - **Prover (`prover`):** Contains the `FridaProverBuilder` to construct FRI proofs over data.
//! - **Verifier (`verifier`):** Contains the `FridaDasVerifier` to verify FRI proofs.
//! - **Data Handling (`core::data`):** Includes functions for Reed-Solomon encoding data into polynomials.
//! - **Queries (`core::queries`):** Provides functionality to calculate the number of queries needed for a target security level.

#[cfg(any(test, feature = "cli"))]
pub mod commands;
pub mod constants;
pub mod core;
pub mod error;
pub mod prover;
pub mod verifier;
pub mod utils;
pub mod winterfell;

pub use error::FridaError;
