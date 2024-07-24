use std::marker::PhantomData;
use std::mem;
use winter_crypto::{Digest, ElementHasher};
use winter_fri::{folding::fold_positions, FriOptions, VerifierError};
use winter_fri::utils::map_positions_to_indexes;
use winter_math::{FieldElement, polynom, StarkField};
use winter_utils::{group_slice_elements, iter_mut};

use crate::{
    frida_error::FridaError,
    frida_prover::{proof::FridaProof, Commitment},
    frida_random::{FridaRandom, FridaRandomCoin},
    frida_verifier::get_query_values,
    utils::FreshPublicCoin,
};
use super::{eval_horner, get_batch_query_values};
use super::channel::{BaseVerifierChannel, FridaVerifierChannel};

pub struct FridaDasVerifier<E, HHst, HRandom>
where
    E: FieldElement,
    HHst: ElementHasher<BaseField = E::BaseField>,
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
    poly_count: usize,
    _phantom_hash_hst: PhantomData<HHst>,
    _phantom_hash_random: PhantomData<HRandom>,
}

struct RandomlyDrawn<E: FieldElement> {
    xi: Option<Vec<E>>,
    layer_alphas: Vec<E>,
    positions: Vec<usize>,
}

impl<E, HHst, HRandom> FridaDasVerifier<E, HHst, HRandom>
where
    E: FieldElement,
    HHst: ElementHasher<BaseField = E::BaseField>,
    HRandom: ElementHasher<BaseField = E::BaseField>,
{
    /**
     * Accepts DAS commitment as input
     * Will perform verification on correctness of folding
     */
    pub fn new(
        das_commitment: Commitment<HRandom>,
        options: FriOptions,
    ) -> Result<(Self, FridaRandom<E, HHst, HRandom>), FridaError> {
        let domain_size = das_commitment.domain_size;
        let num_partitions = das_commitment.proof.num_partitions();
        let max_poly_degree = domain_size / options.blowup_factor() - 1;

        let (drawn, public_coin) =
            Self::draw_randomly(&das_commitment, max_poly_degree, options.folding_factor(), domain_size)?;

        // read layer commitments from the channel and use them to build a list of alphas
        let poly_count = das_commitment.poly_count;
        let layer_commitments = das_commitment.roots;

        let mut verifier_channel = FridaVerifierChannel::<E, HRandom>::new(
            &das_commitment.proof,
            layer_commitments.clone(),
            domain_size,
            options.folding_factor(),
            poly_count,
        )
        .map_err(|_e| FridaError::InvalidDASCommitment)?;

        // get query value from commitment
        let query_values = {
            let folded_positions =
                fold_positions(&drawn.positions, domain_size, options.folding_factor());

            let folding_factor = options.folding_factor();
            match folding_factor {
                2 => Ok(Self::get_query_values_from_commitment::<2>(
                    &verifier_channel,
                    &drawn.positions,
                    &folded_positions,
                    domain_size,
                )),
                4 => Ok(Self::get_query_values_from_commitment::<4>(
                    &verifier_channel,
                    &drawn.positions,
                    &folded_positions,
                    domain_size,
                )),
                8 => Ok(Self::get_query_values_from_commitment::<8>(
                    &verifier_channel,
                    &drawn.positions,
                    &folded_positions,
                    domain_size,
                )),
                16 => Ok(Self::get_query_values_from_commitment::<16>(
                    &verifier_channel,
                    &drawn.positions,
                    &folded_positions,
                    domain_size,
                )),
                _ => Err(FridaError::UnsupportedFoldingFactor(folding_factor)),
            }?
        };

        let domain_generator = E::BaseField::get_root_of_unity(domain_size.ilog2());

        let verifier = Self {
            max_poly_degree,
            domain_size,
            domain_generator,
            layer_commitments,
            xi: drawn.xi,
            layer_alphas: drawn.layer_alphas,
            options,
            num_partitions,
            poly_count,
            _phantom_hash_hst: PhantomData,
            _phantom_hash_random: PhantomData,
        };

        verifier
            .check_auth(&mut verifier_channel, &query_values, &drawn.positions)
            .map_err(|_e| FridaError::InvalidDASCommitment)?;

        Ok((verifier, public_coin))
    }

    pub fn verify(
        &self,
        proof: &FridaProof,
        evaluations: &[E],
        positions: &[usize],
    ) -> Result<(), FridaError> {
        let mut verifier_channel = FridaVerifierChannel::<E, HRandom>::new(
            &proof,
            self.layer_commitments.clone(),
            self.domain_size,
            self.options.folding_factor(),
            self.poly_count,
        )?;

        self.check_auth(&mut verifier_channel, evaluations, positions)
            .map_err(|_e| FridaError::FailToVerify)
    }

    fn check_auth(
        &self,
        channel: &mut FridaVerifierChannel<E, HRandom>,
        evaluations: &[E],
        positions: &[usize],
    ) -> Result<(), VerifierError> {
        if evaluations.len() != positions.len() * channel.poly_count() {
            return Err(VerifierError::NumPositionEvaluationMismatch(
                positions.len(),
                evaluations.len(),
            ));
        }

        // static dispatch for folding factor parameter
        let folding_factor = self.options.folding_factor();
        match folding_factor {
            2 => self.verify_generic::<2, _>(channel, evaluations, positions),
            4 => self.verify_generic::<4, _>(channel, evaluations, positions),
            8 => self.verify_generic::<8, _>(channel, evaluations, positions),
            16 => self.verify_generic::<16, _>(channel, evaluations, positions),
            _ => Err(VerifierError::UnsupportedFoldingFactor(folding_factor)),
        }
    }

    fn get_query_values_from_commitment<const N: usize>(
        verifier_channel: &FridaVerifierChannel<E, HRandom>,
        positions: &[usize],
        folded_positions: &[usize],
        domain_size: usize,
    ) -> Vec<E> {
        if verifier_channel.poly_count() > 1 {
            let layer_values = verifier_channel
                .batch_data
                .as_ref()
                .unwrap()
                .batch_layer_queries
                .as_ref()
                .unwrap();

            get_batch_query_values::<E, N>(
                layer_values,
                positions,
                folded_positions,
                domain_size,
                verifier_channel.poly_count(),
            )
        } else {
            let layer_values = group_slice_elements(&verifier_channel.layer_queries[0]);
            get_query_values::<E, N>(layer_values, positions, folded_positions, domain_size)
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
        let original_domain_size = self.domain_size;
        let poly_count = channel.poly_count();
        let folding_factor = self.options.folding_factor();
        let domain_offset: E::BaseField = self.options.domain_offset();

        let mut domain_generator = self.domain_generator;

        // pre-compute roots of unity used in computing x coordinates in the folded domain
        let folding_roots = (0..N)
            .map(|i| domain_generator.exp_vartime(((original_domain_size / N * i) as u64).into()))
            .collect::<Vec<_>>();

        // 1 ----- verify the recursive components of the FRI proof -----------------------------------
        let mut domain_size = original_domain_size;
        let mut max_degree_plus_1 = self.max_poly_degree + 1;
        let mut positions = positions.to_vec();
        let mut evaluations = evaluations.to_vec();

        let num_fri_layers = self.options.num_fri_layers(original_domain_size);
        for depth in 0..num_fri_layers {
            // determine which evaluations were queried in the folded layer
            let mut folded_positions =
                fold_positions(&positions, domain_size, folding_factor);
            // determine where these evaluations are in the commitment Merkle tree
            let position_indexes = map_positions_to_indexes(
                &folded_positions,
                domain_size,
                folding_factor,
                self.num_partitions,
            );
            // read query values from the specified indexes in the Merkle tree
            let layer_commitment = self.layer_commitments[depth];
            // TODO: add layer depth to the potential error message
            let layer_values = if poly_count > 1 && depth == 0 {
                let xi = self.xi.as_ref().expect("xi values not set");
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
                let xe = domain_generator.exp_vartime((i as u64).into()) * domain_offset;
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

        for (&position, evaluation) in positions.iter().zip(evaluations) {
            let comp_eval = eval_horner::<E>(
                &remainder_poly,
                domain_offset * domain_generator.exp_vartime((position as u64).into()),
            );
            if comp_eval != evaluation {
                return Err(VerifierError::InvalidRemainderFolding);
            }
        }

        Ok(())
    }

    /// Constructs a pseudorandom public coin and draws values for the verifier in the pedefined order,
    /// reseeding it appropriately.
    fn draw_randomly(
        das_commitment: &Commitment<HRandom>,
        max_poly_degree: usize,
        folding_factor: usize,
        domain_size: usize,
    ) -> Result<(RandomlyDrawn<E>, FridaRandom<E, HHst, HRandom>), FridaError> {
        let public_coin = FreshPublicCoin::<E, HHst, HRandom>::new();
        let mut public_coin = public_coin.unwrap();

        let poly_count = das_commitment.poly_count;

        // read layer commitments from the channel and use them to build a list of alphas
        let alpha_commitments = &das_commitment.roots[..];

        let mut xi = None;
        let mut layer_alphas = Vec::with_capacity(alpha_commitments.len());
        let mut max_degree_plus_1 = max_poly_degree + 1;
        for (depth, commitment) in alpha_commitments.iter().enumerate() {
            public_coin.reseed(&commitment.as_bytes());
            if depth == 0 && poly_count > 1 {
                xi = Some(public_coin.draw_xi(poly_count)?)
            }

            let alpha = public_coin.draw()?;
            layer_alphas.push(alpha);

            // make sure the degree can be reduced by the folding factor at all layers
            // but the remainder layer
            if depth != alpha_commitments.len() - 1
                && max_degree_plus_1 % folding_factor != 0
            {
                return Err(FridaError::DegreeTruncation(
                    max_degree_plus_1 - 1,
                    folding_factor,
                    depth,
                ));
            }
            max_degree_plus_1 /= folding_factor;
        }

        let positions =
            public_coin.draw_query_positions(das_commitment.num_queries, domain_size)?;
        Ok((RandomlyDrawn {
            xi,
            layer_alphas,
            positions,
        }, public_coin))
    }

    #[cfg(test)]
    pub fn layer_alphas(&self) -> &Vec<E> {
        &self.layer_alphas
    }
}
