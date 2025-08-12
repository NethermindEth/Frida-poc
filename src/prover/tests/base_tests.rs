use winter_fri::{FriOptions, FriProver};
use winter_utils::Serializable;

use crate::utils::test_utils::*;

use crate::prover::FridaProverBuilder;

// TEST TRAIT IMPLEMENTATION
// ================================================================================================
#[test]
fn fri_folding_2() {
    let trace_length_e = 12;
    let lde_blowup_e = 3;
    let folding_factor_e = 1;
    let max_remainder_degree = 7;
    fri_trait_check(
        trace_length_e,
        lde_blowup_e,
        folding_factor_e,
        max_remainder_degree,
    )
}

#[test]
fn fri_folding_4() {
    let trace_length_e = 12;
    let lde_blowup_e = 3;
    let folding_factor_e = 2;
    let max_remainder_degree = 255;
    fri_trait_check(
        trace_length_e,
        lde_blowup_e,
        folding_factor_e,
        max_remainder_degree,
    )
}

// Match outputs with FriProver to make sure the BaseFriProver trait is implemented correctly
fn fri_trait_check(
    trace_length_e: usize,
    lde_blowup_e: usize,
    folding_factor_e: usize,
    max_remainder_degree: usize,
) {
    let trace_length = 1 << trace_length_e;
    let lde_blowup = 1 << lde_blowup_e;
    let folding_factor = 1 << folding_factor_e;

    let options = FriOptions::new(lde_blowup, folding_factor, max_remainder_degree);
    let mut channel = test_build_prover_channel(trace_length, &options);
    let evaluations = test_build_evaluations(trace_length, lde_blowup);

    let positions = channel.draw_query_positions();

    // instantiate the prover and generate the proof
    let fri_proof = {
        let mut fri_prover = FriProver::new(options.clone());
        fri_prover.build_layers(&mut channel, evaluations.clone());
        fri_prover.build_proof(&positions)
    };

    let mut frida_channel = test_build_prover_channel(trace_length, &options);
    let frida_proof =  {
        let frida_prover = FridaProverBuilder::new(options);
        let prover = frida_prover.test_build_layers(&mut frida_channel, evaluations);
        prover.open(&positions)
    };

    assert_eq!(
        channel.commitments,
        frida_channel.commitments
    );

    // Skipping 1 byte because frida_proof has batch layer information encoded
    assert_eq!(fri_proof.to_bytes(), frida_proof.to_bytes()[1..]);
}
