use std::mem;

use winter_crypto::ElementHasher;
use winter_fri::{
    folding::fold_positions, utils::map_positions_to_indexes, FriOptions, VerifierError,
};
use winter_math::{polynom, FieldElement, StarkField};

#[cfg(feature = "concurrent")]
use winter_utils::iterators::*;
use winter_utils::{iter_mut, uninit_vector};

use crate::frida_verifier_channel::BaseVerifierChannel;

use super::{eval_horner, get_batch_query_values};

pub struct FridaVerifier<E, HRandom>
where
    E: FieldElement,
    HRandom: ElementHasher<BaseField = E::BaseField>,
{
    max_poly_degree: usize,
    domain_size: usize,
    domain_generator: E::BaseField,
    layer_commitments: Vec<HRandom::Digest>,
    xi: Option<Vec<E>>,
    layer_alphas: Vec<E>,
    options: FriOptions,
    num_partitions: usize,
}

impl<E, HRandom> FridaVerifier<E, HRandom>
where
    E: FieldElement,
    HRandom: ElementHasher<BaseField = E::BaseField>,
{
    pub fn new(
        mut layer_commitments: Vec<HRandom::Digest>,
        xi: Option<Vec<E>>,
        layer_alphas: Vec<E>,
        num_partitions: usize,
        options: FriOptions,
        max_poly_degree: usize,
    ) -> Result<Self, VerifierError> {
        // infer evaluation domain info
        let domain_size = max_poly_degree.next_power_of_two() * options.blowup_factor();
        let domain_generator = E::BaseField::get_root_of_unity(domain_size.ilog2());

        // Ignore first layer if batched
        if xi.is_some() {
            layer_commitments.remove(0);
        }

        Ok(Self {
            max_poly_degree,
            domain_size,
            domain_generator,
            layer_commitments,
            xi,
            layer_alphas,
            options,
            num_partitions,
        })
    }

    /// Returns protocol configuration options for this verifier.
    pub fn options(&self) -> &FriOptions {
        &self.options
    }

    pub fn check_auth<C: BaseVerifierChannel<E, Hasher = HRandom>>(
        &self,
        channel: &mut C,
        evaluations: &[E],
        positions: &[usize],
    ) -> Result<(), VerifierError> {
        if evaluations.len() != positions.len() * usize::max(channel.batch_size(), 1) {
            return Err(VerifierError::NumPositionEvaluationMismatch(
                positions.len(),
                evaluations.len(),
            ));
        }

        // static dispatch for folding factor parameter
        let folding_factor = self.options.folding_factor();
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
        // pre-compute roots of unity used in computing x coordinates in the folded domain
        let folding_roots = (0..N)
            .map(|i| {
                self.domain_generator
                    .exp_vartime(((self.domain_size / N * i) as u64).into())
            })
            .collect::<Vec<_>>();

        // 1 ----- verify the recursive components of the FRI proof -----------------------------------
        let mut domain_generator = self.domain_generator;
        let mut domain_size = self.domain_size;
        let mut max_degree_plus_1 = self.max_poly_degree + 1;
        let mut positions = positions.to_vec();
        let mut evaluations = if channel.batch_size() > 0 {
            self.verify_batch_layer::<C, N>(channel, &evaluations, &positions)?
        } else {
            evaluations.to_vec()
        };

        for depth in 0..self.options.num_fri_layers(self.domain_size) {
            // determine which evaluations were queried in the folded layer
            let mut folded_positions =
                fold_positions(&positions, domain_size, self.options.folding_factor());
            // determine where these evaluations are in the commitment Merkle tree
            let position_indexes = map_positions_to_indexes(
                &folded_positions,
                domain_size,
                self.options.folding_factor(),
                self.num_partitions,
            );
            // read query values from the specified indexes in the Merkle tree
            let layer_commitment = self.layer_commitments[depth];
            // TODO: add layer depth to the potential error message
            let layer_values = channel.read_layer_queries(&position_indexes, &layer_commitment)?;
            let query_values =
                get_query_values::<E, N>(&layer_values, &positions, &folded_positions, domain_size);
            if evaluations != query_values {
                return Err(VerifierError::InvalidLayerFolding(depth));
            }

            // build a set of x coordinates for each row polynomial
            #[rustfmt::skip]
            let xs = folded_positions.iter().map(|&i| {
                let xe = domain_generator.exp_vartime((i as u64).into()) * self.options.domain_offset();
                folding_roots.iter()
                    .map(|&r| E::from(xe * r))
                    .collect::<Vec<_>>().try_into().unwrap()
            })
            .collect::<Vec<_>>();

            // interpolate x and y values into row polynomials
            let row_polys = polynom::interpolate_batch(&xs, &layer_values);

            // calculate the pseudo-random value used for linear combination in layer folding
            let alpha = self.layer_alphas[depth];

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
        let offset: E::BaseField = self.options().domain_offset();

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

    fn verify_batch_layer<C: BaseVerifierChannel<E, Hasher = HRandom>, const N: usize>(
        &self,
        channel: &mut C,
        evaluations: &[E],
        positions: &[usize],
    ) -> Result<Vec<E>, VerifierError> {
        // determine which evaluations were queried in the folded layer
        let folded_positions =
            fold_positions(&positions, self.domain_size, self.options.folding_factor());
        // determine where these evaluations are in the commitment Merkle tree
        let position_indexes = map_positions_to_indexes(
            &folded_positions,
            self.domain_size,
            self.options.folding_factor(),
            self.num_partitions,
        );

        let batch_size = channel.batch_size();
        let layer_values = channel.read_batch_layer_queries(&position_indexes)?;
        let query_values = get_batch_query_values::<E, N>(
            &layer_values,
            positions,
            &folded_positions,
            self.domain_size,
            batch_size,
        );
        if evaluations != query_values {
            return Err(VerifierError::InvalidLayerFolding(0));
        }

        let xi = self.xi.as_ref().unwrap();
        let mut next_eval = unsafe { uninit_vector(query_values.len() / batch_size) };
        iter_mut!(next_eval, 1024).enumerate().for_each(|(i, f)| {
            *f = E::default();
            query_values[i * batch_size..i * batch_size + batch_size]
                .iter()
                .enumerate()
                .for_each(|(j, e)| {
                    *f += *e * xi[j];
                });
        });
        Ok(next_eval)
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
