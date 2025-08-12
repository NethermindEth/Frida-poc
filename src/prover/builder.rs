

impl<E, H> FridaProverBuilder<E, H>
where
    E: FieldElement,
    H: ElementHasher<BaseField = E::BaseField>,
{
    pub fn new(options: FriOptions) -> Self {
        FridaProverBuilder {
            options,
            _phantom_field_element: PhantomData,
            _phantom_hasher: PhantomData,
        }
    }

    /// Builds a prover for a specific data, along with a channel that should be used for commitment.
    pub fn commit_and_prove(
        &self,
        data: &[u8],
        num_queries: usize,
    ) -> Result<(Commitment<H>, FridaProver<E, H>), FridaError> {
        let (channel, prover) = self.prepare_prover_state(data, num_queries)?;

        let commitment = self.build_commitment(&prover, channel)?;
        Ok((commitment, prover))
    }

    /// Builds a prover for a specific batched data, along with a channel that should be used for commitment. This produces a commitment, and also produces a proof for num_queries number of position.
    pub fn commit_and_prove_batch(
        &self,
        data_list: &[Vec<u8>],
        num_queries: usize,
    ) -> Result<(Commitment<H>, FridaProver<E, H>), FridaError> {
        let (channel, prover) = self.prepare_prover_state_batch(data_list, num_queries)?;

        let commitment = self.build_commitment(&prover, channel)?;
        Ok((commitment, prover))
    }

    /// This method returns a commitment containing only the Merkle roots and metadata,
    /// and a stateful `FridaProver` instance which can be used generate many
    /// proofs for different query sets.
    pub fn commitment(
        &self,
        data: &[u8],
        num_queries: usize,
    ) -> Result<(ProverCommitment<H>, FridaProver<E, H>, Vec<usize>), FridaError> {
        // We use a dummy num_queries here because we are not generating a proof yet.
        let (mut channel, prover) = self.prepare_prover_state(data, num_queries)?;

        let commitment = ProverCommitment {
            roots: channel.commitments.clone(),
            domain_size: prover.domain_size,
            poly_count: prover.poly_count,
        };

        let base_positions: Vec<usize> = channel.draw_query_positions();

        Ok((commitment, prover, base_positions))
    }

    pub fn commitment_batch(
        &self,
        data_list: &[Vec<u8>],
        num_queries: usize,
    ) -> Result<(ProverCommitment<H>, FridaProver<E, H>, Vec<usize>), FridaError> {
        let (mut channel, prover) = self.prepare_prover_state_batch(data_list, num_queries)?;

        let commitment = ProverCommitment {
            roots: channel.commitments.clone(),
            domain_size: prover.domain_size,
            poly_count: prover.poly_count,
        };

        let base_positions: Vec<usize> = channel.draw_query_positions();

        Ok((commitment, prover, base_positions))
    }

    /// It calculates the domain size and generates the initial evaluations.
    fn prepare_prover_state(
        &self,
        data: &[u8],
        num_queries: usize,
    ) -> Result<(Channel<E, H>, FridaProver<E, H>), FridaError> {
        if num_queries == 0 {
            return Err(FridaError::BadNumQueries(num_queries));
        }

        let blowup_factor = self.options.blowup_factor();
        let encoded_element_count = encoded_data_element_count::<E>(data.len());

        let domain_size = usize::max(
            encoded_element_count.next_power_of_two() * blowup_factor,
            constants::MIN_DOMAIN_SIZE,
        );

        if domain_size > constants::MAX_DOMAIN_SIZE {
            return Err(FridaError::DomainSizeTooBig(domain_size));
        }

        let evaluations = build_evaluations_from_data(data, domain_size, blowup_factor)?;

        if num_queries >= domain_size {
            return Err(FridaError::BadNumQueries(num_queries));
        }
        if self.options.num_fri_layers(domain_size) == 0 {
            return Err(FridaError::NotEnoughDataPoints());
        }

        let mut channel = Channel::<E, H>::new(domain_size, num_queries);
        let prover = self.build_layers(&mut channel, evaluations, 1, None);
        Ok((channel, prover))
    }

    fn prepare_prover_state_batch(
        &self,
        data_list: &[Vec<u8>],
        num_queries: usize,
    ) -> Result<(Channel<E, H>, FridaProver<E, H>), FridaError> {
        #[cfg(feature = "bench")]
        unsafe {
            bench::TIMER = Some(Instant::now());
        }

        if num_queries == 0 {
            return Err(FridaError::BadNumQueries(num_queries));
        }

        let poly_count = data_list.len();
        if poly_count <= 1 {
            return Err(FridaError::SinglePolyBatch);
        }

        let blowup_factor = self.options.blowup_factor();

        let max_data_len = encoded_data_element_count::<E>(
            data_list
                .iter()
                .map(|data| data.len())
                .max()
                .unwrap_or_default(),
        );

        let domain_size = usize::max(
            (max_data_len * blowup_factor).next_power_of_two(),
            constants::MIN_DOMAIN_SIZE,
        );

        let folding_factor = self.options.folding_factor();

        if domain_size > constants::MAX_DOMAIN_SIZE {
            return Err(FridaError::DomainSizeTooBig(domain_size));
        }
        if num_queries >= domain_size {
            return Err(FridaError::BadNumQueries(num_queries));
        }
        if self.options.num_fri_layers(domain_size) == 0 {
            // Verification currently cannot work without FRI layers
            return Err(FridaError::NotEnoughDataPoints());
        }

        let evaluations = batch_data_to_evaluations::<E>(
            data_list,
            poly_count,
            domain_size,
            blowup_factor,
            folding_factor,
        )?;

        #[cfg(feature = "bench")]
        unsafe {
            bench::ERASURE_TIME =
                Some(bench::ERASURE_TIME.unwrap_or_default() + bench::TIMER.unwrap().elapsed());
            bench::TIMER = Some(Instant::now());
        }

        let mut channel = Channel::<E, H>::new(domain_size, num_queries);
        let prover = self.build_layers_batched(&mut channel, evaluations, domain_size)?;

        Ok((channel, prover))
    }


    /// Commits to the evaluated data, consuming the channel constructed along with this prover.
    pub fn build_commitment(
        &self,
        prover: &FridaProver<E, H>,
        mut channel: Channel<E, H>,
    ) -> Result<Commitment<H>, FridaError> {
        let query_positions = channel.draw_query_positions();
        let proof = prover.open(&query_positions);

        #[cfg(feature = "bench")]
        unsafe {
            bench::COMMIT_TIME =
                Some(bench::COMMIT_TIME.unwrap_or_default() + bench::TIMER.unwrap().elapsed());
        }

        let num_queries = channel.num_queries;

        let commitment = Commitment {
            roots: channel.commitments,
            proof,
            domain_size: prover.domain_size,
            num_queries,
            poly_count: prover.poly_count,
        };

        Ok(commitment)
    }

    fn build_layers(
        &self,
        channel: &mut Channel<E, H>,
        evaluations: Vec<E>,
        poly_count: usize,
        batch_layer: Option<FridaLayer<E, H>>,
    ) -> FridaProver<E, H> {
        let is_batched = batch_layer.is_some();
        assert!(!is_batched && poly_count == 1 || is_batched && poly_count > 1);

        // reduce the degree by folding_factor at each iteration until the remaining polynomial
        // has small enough degree
        let mut evaluations = evaluations;
        let domain_size = if is_batched {
            evaluations.len() * self.options.folding_factor()
        } else {
            evaluations.len()
        };

        let num_fri_layers = self.options.num_fri_layers(domain_size);
        let mut layers = Vec::with_capacity(num_fri_layers);
        if let Some(batch_layer) = batch_layer {
            layers.push(batch_layer);
        }
        let start = if is_batched { 1 } else { 0 };
        for _ in start..num_fri_layers {
            let (new_evaluations, frida_layer) = match self.options.folding_factor() {
                2 => self.build_layer::<2>(channel, &evaluations),
                4 => self.build_layer::<4>(channel, &evaluations),
                8 => self.build_layer::<8>(channel, &evaluations),
                16 => self.build_layer::<16>(channel, &evaluations),
                _ => unimplemented!(
                    "folding factor {} is not supported",
                    self.options.folding_factor()
                ),
            };
            layers.push(frida_layer);
            evaluations = new_evaluations;
        }

        let remainder_poly = self.build_remainder(channel, &mut evaluations);

        FridaProver {
            layers,
            poly_count,
            remainder_poly,
            domain_size,
            folding_factor: self.options.folding_factor(),
        }
    }

    fn build_layers_batched(
        &self,
        channel: &mut Channel<E, H>,
        evaluations: Vec<E>,
        domain_size: usize,
    ) -> Result<FridaProver<E, H>, FridaError> {
        let poly_count = evaluations.len() / domain_size;
        let folding_factor = self.options.folding_factor();
        let bucket_count = domain_size / folding_factor;
        let bucket_size = poly_count * folding_factor;

        let mut hashed_evaluations: Vec<H::Digest> = unsafe { uninit_vector(bucket_count) };
        iter_mut!(hashed_evaluations, 1024)
            .enumerate()
            .for_each(|(i, r)| {
                *r = H::hash_elements(&evaluations[i * bucket_size..i * bucket_size + bucket_size]);
            });
        let evaluation_tree =
            MerkleTree::<H>::new(hashed_evaluations).expect("failed to construct FRI layer tree");
        channel.commit_fri_layer(*evaluation_tree.root());

        let xi = channel.draw_xi(poly_count)?;
        let alpha = channel.draw_fri_alpha();
        let second_layer = match folding_factor {
            2 => apply_drp_batched::<_, 2>(&evaluations, poly_count, &self.options, xi, alpha),
            4 => apply_drp_batched::<_, 4>(&evaluations, poly_count, &self.options, xi, alpha),
            8 => apply_drp_batched::<_, 8>(&evaluations, poly_count, &self.options, xi, alpha),
            16 => apply_drp_batched::<_, 16>(&evaluations, poly_count, &self.options, xi, alpha),
            _ => unimplemented!("folding factor {} is not supported", folding_factor),
        };

        Ok(self.build_layers(
            channel,
            second_layer,
            poly_count,
            Some(FridaLayer {
                tree: evaluation_tree,
                evaluations,
            }),
        ))
    }

    

    // #[cfg(test)]
    // pub fn test_build_layers(
    //     &self,
    //     channel: &mut Channel<E, H>,
    //     evaluations: Vec<E>,
    // ) -> FridaProver<E, H> {
    //     self.build_layers(channel, evaluations, 1, None)
    // }

    /// Builds a single FRI layer by first committing to the `evaluations`, then drawing a random
    /// alpha from the channel and use it to perform degree-respecting projection.
    fn build_layer<const N: usize>(
        &self,
        channel: &mut Channel<E, H>,
        evaluations: &[E],
    ) -> (Vec<E>, FridaLayer<E, H>) {
        // commit to the evaluations at the current layer; we do this by first transposing the
        // evaluations into a matrix of N columns, and then building a Merkle tree from the
        // rows of this matrix; we do this so that we could de-commit to N values with a single
        // Merkle authentication path.
        let transposed_evaluations = transpose_slice(evaluations);
        let hashed_evaluations = hash_values::<H, E, N>(&transposed_evaluations);

        let evaluation_tree =
            MerkleTree::<H>::new(hashed_evaluations).expect("failed to construct FRI layer tree");
        channel.commit_fri_layer(*evaluation_tree.root());

        // draw a pseudo-random coefficient from the channel, and use it in degree-respecting
        // projection to reduce the degree of evaluations by N
        let alpha = channel.draw_fri_alpha();
        let evaluations =
            folding::apply_drp(&transposed_evaluations, self.options.domain_offset(), alpha);
        (
            evaluations,
            FridaLayer {
                tree: evaluation_tree,
                evaluations: flatten_vector_elements(transposed_evaluations),
            },
        )
    }

    /// Creates remainder polynomial in coefficient form from a vector of `evaluations` over a domain.
    fn build_remainder(
        &self,
        channel: &mut Channel<E, H>,
        evaluations: &mut [E],
    ) -> FridaRemainder<E> {
        let inv_twiddles = fft::get_inv_twiddles(evaluations.len());
        fft::interpolate_poly_with_offset(evaluations, &inv_twiddles, self.options.domain_offset());
        let remainder_poly_size = evaluations.len() / self.options.blowup_factor();
        let remainder_poly = evaluations[..remainder_poly_size].to_vec();
        let commitment = <H as ElementHasher>::hash_elements(&remainder_poly);
        channel.commit_fri_layer(commitment);

        FridaRemainder(remainder_poly)
    }
}
