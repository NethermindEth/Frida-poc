mod test;

use std::{marker::PhantomData, mem};

use crate::{frida_random::FridaRandomCoin, frida_verifier_channel::BaseVerifierChannel};
use winter_crypto::{Digest, ElementHasher, RandomCoinError};
use winter_fri::{
    folding::fold_positions, utils::map_positions_to_indexes, FriOptions, VerifierChannel,
    VerifierError,
};
use winter_math::{polynom, FieldElement, StarkField};

pub struct FridaVerifier<E, C, HHst, HRandom, R>
where
    E: FieldElement,
    C: VerifierChannel<E, Hasher = HRandom>,
    HHst: ElementHasher<BaseField = E::BaseField>,
    HRandom: ElementHasher<BaseField = E::BaseField>,
    R: FridaRandomCoin<BaseField = E::BaseField, HashHst = HHst, HashRandom = HRandom>,
{
    max_poly_degree: usize,
    domain_size: usize,
    domain_generator: E::BaseField,
    layer_commitments: Vec<HRandom::Digest>,
    zi: Option<Vec<E>>,
    layer_alphas: Vec<E>,
    options: FriOptions,
    num_partitions: usize,
    _channel: PhantomData<C>,
    _public_coin: PhantomData<R>,
}

impl<E, C, HHst, HRandom, R> FridaVerifier<E, C, HHst, HRandom, R>
where
    E: FieldElement,
    C: BaseVerifierChannel<E, Hasher = HRandom>,
    HHst: ElementHasher<BaseField = E::BaseField>,
    HRandom: ElementHasher<BaseField = E::BaseField>,
    R: FridaRandomCoin<
        BaseField = E::BaseField,
        FieldElement = E,
        HashHst = HHst,
        HashRandom = HRandom,
    >,
{
    pub fn new(
        channel: &mut C,
        public_coin: &mut R,
        options: FriOptions,
        max_poly_degree: usize,
    ) -> Result<Self, VerifierError> {
        // infer evaluation domain info
        let domain_size = max_poly_degree.next_power_of_two() * options.blowup_factor();
        let domain_generator = E::BaseField::get_root_of_unity(domain_size.ilog2());

        let num_partitions = channel.read_fri_num_partitions();

        // read layer commitments from the channel and use them to build a list of alphas
        let layer_commitments = channel.read_fri_layer_commitments();

        let zi = if channel.batch_size() > 0 {
            let batch_layer_root = channel.batch_data().batch_commitment.unwrap();
            public_coin.reseed(&batch_layer_root.as_bytes());
            Some(public_coin.draw_zi(channel.batch_size()).map_err(|_e| {
                VerifierError::RandomCoinError(RandomCoinError::FailedToDrawFieldElement(
                    channel.batch_size(),
                ))
            })?)
        } else {
            None
        };

        let mut layer_alphas = Vec::with_capacity(layer_commitments.len());
        let mut max_degree_plus_1 = max_poly_degree + 1;
        for (depth, commitment) in layer_commitments.iter().enumerate() {
            public_coin.reseed(&commitment.as_bytes());
            let alpha = public_coin.draw().map_err(|_e| {
                VerifierError::RandomCoinError(RandomCoinError::FailedToDrawFieldElement(1000))
            })?;

            layer_alphas.push(alpha);

            // make sure the degree can be reduced by the folding factor at all layers
            // but the remainder layer
            if depth != layer_commitments.len() - 1
                && max_degree_plus_1 % options.folding_factor() != 0
            {
                return Err(VerifierError::DegreeTruncation(
                    max_degree_plus_1 - 1,
                    options.folding_factor(),
                    depth,
                ));
            }
            max_degree_plus_1 /= options.folding_factor();
        }

        Ok(Self {
            max_poly_degree,
            domain_size,
            domain_generator,
            layer_commitments,
            zi,
            layer_alphas,
            options,
            num_partitions,
            _channel: PhantomData,
            _public_coin: PhantomData,
        })
    }

    /// Returns protocol configuration options for this verifier.
    pub fn options(&self) -> &FriOptions {
        &self.options
    }

    pub fn verify(
        &self,
        channel: &mut C,
        evaluations: &[E],
        positions: &[usize],
    ) -> Result<(), VerifierError> {
        let batch_size = usize::max(channel.batch_size(), 1);
        if evaluations.len() != positions.len() * batch_size {
            return Err(VerifierError::NumPositionEvaluationMismatch(
                positions.len() * batch_size,
                evaluations.len(),
            ));
        }

        // static dispatch for folding factor parameter
        let folding_factor = self.options.folding_factor();
        match folding_factor {
            2 => self.verify_generic::<2>(channel, evaluations, positions),
            4 => self.verify_generic::<4>(channel, evaluations, positions),
            8 => self.verify_generic::<8>(channel, evaluations, positions),
            16 => self.verify_generic::<16>(channel, evaluations, positions),
            _ => Err(VerifierError::UnsupportedFoldingFactor(folding_factor)),
        }
    }

    /// This is the actual implementation of the verification procedure described above, but it
    /// also takes folding factor as a generic parameter N.
    fn verify_generic<const N: usize>(
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
            self.verify_batch_layer::<N>(channel, &evaluations, &positions)?
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

    fn verify_batch_layer<const N: usize>(
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
        let layer_values = channel.read_batch_layer_queries(
            &position_indexes,
            &channel.batch_data().batch_commitment.unwrap(),
        )?;
        let query_values = {
            let row_length = self.domain_size / N;
            let mut result = Vec::with_capacity(batch_size * positions.len());
            for position in positions.iter() {
                let idx = folded_positions
                    .iter()
                    .position(|&v| v == position % row_length)
                    .unwrap();
                layer_values[idx]
                    [(position / row_length) * batch_size..position / row_length + batch_size]
                    .iter()
                    .for_each(|e| {
                        result.push(*e);
                    });
            }
            result
        };
        if evaluations != query_values {
            return Err(VerifierError::InvalidLayerFolding(0));
        }

        let zi = self.zi.as_ref().unwrap();
        Ok(query_values
            .chunks(batch_size)
            .map(|chunk| {
                chunk
                    .iter()
                    .enumerate()
                    .fold(E::default(), |accumulator, (i, e)| accumulator + *e * zi[i])
            })
            .collect())
    }

    pub fn layer_alphas(&self) -> Vec<E> {
        let alphas = &self.layer_alphas;
        alphas.clone()
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

// Evaluates a polynomial with coefficients in an extension field at a point in the base field.
pub fn eval_horner<E>(p: &[E], x: E::BaseField) -> E
where
    E: FieldElement,
{
    p.iter()
        .rev()
        .fold(E::ZERO, |acc, &coeff| acc * E::from(x) + coeff)
}

#[cfg(test)]
mod tests {
    use winter_crypto::hashers::Blake3_256;
    use winter_math::fields::f128::BaseElement;
    use winter_rand_utils::{rand_value, rand_vector};

    use crate::{
        frida_prover::{traits::BaseFriProver, FridaProver},
        frida_prover_channel::FridaProverChannel,
        frida_random::FridaRandom,
        frida_verifier_channel::FridaVerifierChannel,
    };

    use super::*;

    #[test]
    fn test_verify_batch() {
        let batch_size = 10;
        let mut data = vec![];
        for _ in 0..batch_size {
            data.push(rand_vector::<u8>(usize::min(
                rand_value::<u64>() as usize,
                1024,
            )));
        }

        let blowup_factor = 2;
        let folding_factor = 2;
        let options = FriOptions::new(blowup_factor, folding_factor, 0);
        let mut prover: FridaProver<
            BaseElement,
            BaseElement,
            FridaProverChannel<
                BaseElement,
                Blake3_256<BaseElement>,
                Blake3_256<BaseElement>,
                FridaRandom<Blake3_256<BaseElement>, Blake3_256<BaseElement>, BaseElement>,
            >,
            Blake3_256<BaseElement>,
        > = FridaProver::new(options.clone());
        let (commitment, _) = prover.commit_batch(data, 1).unwrap();

        let mut channel = FridaVerifierChannel::<BaseElement, Blake3_256<BaseElement>>::new(
            commitment.proof,
            commitment.roots,
            prover.domain_size(),
            options.folding_factor(),
            batch_size,
        )
        .unwrap();
        let mut coin =
            FridaRandom::<Blake3_256<BaseElement>, Blake3_256<BaseElement>, BaseElement>::new(&[
                123,
            ]);

        let verifier = FridaVerifier::new(
            &mut channel,
            &mut coin,
            options.clone(),
            prover.domain_size() / options.blowup_factor() - 1,
        )
        .unwrap();

        let mut query_positions = coin.draw_query_positions(1, prover.domain_size()).unwrap();
        query_positions.dedup();
        query_positions = fold_positions(&query_positions, prover.domain_size(), folding_factor);

        let mut evaluations = vec![];
        for position in query_positions.iter() {
            let bucket = position % (prover.domain_size() / folding_factor);
            let start_index = (position / (prover.domain_size() / folding_factor)) * batch_size;
            prover.get_batch_layer().as_ref().unwrap().evaluations[bucket]
                [start_index..start_index + batch_size]
                .iter()
                .for_each(|e| {
                    evaluations.push(*e);
                });
        }

        verifier
            .verify(&mut channel, &evaluations, &query_positions)
            .unwrap();
    }
}
