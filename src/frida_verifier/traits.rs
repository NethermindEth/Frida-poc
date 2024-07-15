use std::mem;

use winter_crypto::ElementHasher;
use winter_fri::{
    folding::fold_positions, utils::map_positions_to_indexes, FriOptions, VerifierError,
};
use winter_math::{polynom, FieldElement};

use winter_utils::iter_mut;
#[cfg(feature = "concurrent")]
use winter_utils::iterators::*;

use crate::{
    frida_error::FridaError, frida_prover::Commitment, frida_random::FridaRandomCoin,
    frida_verifier_channel::BaseVerifierChannel,
};

use super::eval_horner;

pub trait BaseFridaVerifier<E, HHst, HRandom, R>
where
    E: FieldElement,
    HHst: ElementHasher<BaseField = E::BaseField>,
    HRandom: ElementHasher<BaseField = E::BaseField>,
    R: FridaRandomCoin<BaseField = E::BaseField, HashHst = HHst, HashRandom = HRandom>,
    Self: Sized,
{
    fn new(
        das_commitment: Commitment<HRandom>,
        public_coin: &mut R,
        options: FriOptions,
    ) -> Result<Self, FridaError>;

    /// Returns protocol configuration options for this verifier.
    fn options(&self) -> &FriOptions;
    fn domain_generator(&self) -> E::BaseField;
    fn domain_size(&self) -> usize;
    fn max_poly_degree(&self) -> usize;
    fn num_partitions(&self) -> usize;
    fn get_layer_commitment(&self, depth: usize) -> HRandom::Digest;
    fn get_layer_alpha(&self, depth: usize) -> E;
    fn xi(&self) -> Option<&Vec<E>>;

    fn check_auth<C: BaseVerifierChannel<E, Hasher = HRandom>>(
        &self,
        channel: &mut C,
        evaluations: &[E],
        positions: &[usize],
    ) -> Result<(), VerifierError> {
        if evaluations.len() != positions.len() * channel.poly_count() {
            return Err(VerifierError::NumPositionEvaluationMismatch(
                positions.len(),
                evaluations.len(),
            ));
        }
        let options = self.options();

        // static dispatch for folding factor parameter
        let folding_factor = options.folding_factor();
        match folding_factor {
            2 => self.verify_generic::<2, C>(channel, evaluations, positions),
            4 => self.verify_generic::<4, C>(channel, evaluations, positions),
            8 => self.verify_generic::<8, C>(channel, evaluations, positions),
            16 => self.verify_generic::<16, C>(channel, evaluations, positions),
            _ => Err(VerifierError::UnsupportedFoldingFactor(folding_factor)),
        }
    }

    /// This is the actual implementation of the verification procedure described above, but it
    /// also takes folding factor as a generic parameter N.
    fn verify_generic<const N: usize, C: BaseVerifierChannel<E, Hasher = HRandom>>(
        &self,
        channel: &mut C,
        evaluations: &[E],
        positions: &[usize],
    ) -> Result<(), VerifierError> {
        let options = self.options();
        let original_domain_size = self.domain_size();
        let poly_count = channel.poly_count();
        let mut domain_generator = self.domain_generator();

        // pre-compute roots of unity used in computing x coordinates in the folded domain
        let folding_roots = (0..N)
            .map(|i| domain_generator.exp_vartime(((original_domain_size / N * i) as u64).into()))
            .collect::<Vec<_>>();

        // 1 ----- verify the recursive components of the FRI proof -----------------------------------
        let mut domain_size = original_domain_size;
        let mut max_degree_plus_1 = self.max_poly_degree() + 1;
        let mut positions = positions.to_vec();
        let mut evaluations = evaluations.to_vec();

        let num_fri_layers = options.num_fri_layers(original_domain_size);
        for depth in 0..num_fri_layers {
            // determine which evaluations were queried in the folded layer
            let mut folded_positions =
                fold_positions(&positions, domain_size, options.folding_factor());
            // determine where these evaluations are in the commitment Merkle tree
            let position_indexes = map_positions_to_indexes(
                &folded_positions,
                domain_size,
                options.folding_factor(),
                self.num_partitions(),
            );
            // read query values from the specified indexes in the Merkle tree
            let layer_commitment = self.get_layer_commitment(depth);
            // TODO: add layer depth to the potential error message
            let layer_values = if poly_count > 1 && depth == 0 {
                let xi = self.xi().unwrap();
                let layer_values =
                    channel.read_batch_layer_queries(&position_indexes, &layer_commitment)?;
                let mut combined_layer_values: Vec<[E; N]> =
                    vec![[E::default(); N]; layer_values.len() / poly_count / N];
                iter_mut!(combined_layer_values, 1024)
                    .enumerate()
                    .for_each(|(i, b)| {
                        iter_mut!(b, 1024).enumerate().for_each(|(j, f)| {
                            let start = i * (poly_count * N) + poly_count * j;
                            layer_values[start..start + poly_count]
                                .iter()
                                .enumerate()
                                .for_each(|(j, e)| {
                                    *f += *e * xi[j];
                                });
                        });
                    });

                let mut new_eval = vec![E::default(); evaluations.len() / poly_count];
                iter_mut!(new_eval, 1024).enumerate().for_each(|(i, f)| {
                    evaluations[i * poly_count..i * poly_count + poly_count]
                        .iter()
                        .enumerate()
                        .for_each(|(j, e)| {
                            *f += *e * xi[j];
                        });
                });
                evaluations = new_eval;
                combined_layer_values
            } else {
                channel.read_layer_queries(&position_indexes, &layer_commitment)?
            };
            let query_values =
                get_query_values::<E, N>(&layer_values, &positions, &folded_positions, domain_size);
            if evaluations != query_values {
                return Err(VerifierError::InvalidLayerFolding(depth));
            }

            // build a set of x coordinates for each row polynomial
            #[rustfmt::skip]
            let xs = folded_positions.iter().map(|&i| {
                let xe = domain_generator.exp_vartime((i as u64).into()) * options.domain_offset();
                folding_roots.iter()
                    .map(|&r| E::from(xe * r))
                    .collect::<Vec<_>>().try_into().unwrap()
            })
            .collect::<Vec<_>>();

            // interpolate x and y values into row polynomials
            let row_polys = polynom::interpolate_batch(&xs, &layer_values);

            // calculate the pseudo-random value used for linear combination in layer folding
            let alpha = self.get_layer_alpha(depth);

            // check that when the polynomials are evaluated at alpha, the result is equal to
            // the corresponding column value
            evaluations = row_polys.iter().map(|p| polynom::eval(p, alpha)).collect();

            // make sure next degree reduction does not result in degree truncation
            if max_degree_plus_1 % N != 0 {
                return Err(VerifierError::DegreeTruncation(
                    max_degree_plus_1 - 1,
                    N,
                    depth,
                ));
            }

            // update variables for the next iteration of the loop
            domain_generator = domain_generator.exp_vartime((N as u32).into());
            max_degree_plus_1 /= N;
            domain_size /= N;
            mem::swap(&mut positions, &mut folded_positions);
        }

        // 2 ----- verify the remainder polynomial of the FRI proof -------------------------------

        // read the remainder polynomial from the channel and make sure it agrees with the evaluations
        // from the previous layer.
        let remainder_poly = channel.read_remainder()?;
        if remainder_poly.len() > max_degree_plus_1 {
            return Err(VerifierError::RemainderDegreeMismatch(
                max_degree_plus_1 - 1,
            ));
        }
        let offset: E::BaseField = options.domain_offset();

        for (&position, evaluation) in positions.iter().zip(evaluations) {
            let comp_eval = eval_horner::<E>(
                &remainder_poly,
                offset * domain_generator.exp_vartime((position as u64).into()),
            );
            if comp_eval != evaluation {
                return Err(VerifierError::InvalidRemainderFolding);
            }
        }

        Ok(())
    }
}

fn get_query_values<E: FieldElement, const N: usize>(
    values: &[[E; N]],
    positions: &[usize],
    folded_positions: &[usize],
    domain_size: usize,
) -> Vec<E> {
    let row_length = domain_size / N;

    let mut result = Vec::new();
    for position in positions {
        let idx = folded_positions
            .iter()
            .position(|&v| v == position % row_length)
            .unwrap();
        let value = values[idx][position / row_length];
        result.push(value);
    }

    result
}
