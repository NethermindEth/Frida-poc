use winter_fri::{FriOptions, FriProver};
use winter_utils::Serializable;

use crate::{
    frida_prover_channel::BaseProverChannel,
    utils::{build_evaluations, build_prover_channel},
};

use super::{traits::BaseFriProver, FridaProver};

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
    let mut channel = build_prover_channel(trace_length, &options);
    let evaluations = build_evaluations(trace_length, lde_blowup);

    // instantiate the prover and generate the proof
    let mut prover = FriProver::new(options.clone());
    prover.build_layers(&mut channel, evaluations.clone());
    let positions = channel.draw_query_positions();
    let proof = prover.build_proof(&positions);

    let mut frida_channel = build_prover_channel(trace_length, &options);
    let mut frida_prover = FridaProver::new(options);
    frida_prover.build_layers(&mut frida_channel, evaluations);
    let frida_proof = frida_prover.build_proof(&positions);

    assert_eq!(
        channel.layer_commitments(),
        frida_channel.layer_commitments()
    );

    // Skipping 1 byte because frida_proof has batch layer information encoded
    assert_eq!(proof.to_bytes(), frida_proof.to_bytes()[1..]);
}
