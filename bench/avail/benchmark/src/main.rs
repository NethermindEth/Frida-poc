use avail_core::{
    kate_commitment as kc, AppExtrinsic, BlockLengthColumns, BlockLengthRows, BLOCK_CHUNK_SIZE,
    DA_DISPATCH_RATIO,
};
use frame_system::{limits::BlockLength, native::hosted_header_builder::MIN_WIDTH};
use kate_recovery::{matrix::{Dimensions, Position}, data::Cell};
use rand::{thread_rng, RngCore};
use sp_core::H256;
use sp_runtime::SaturatedConversion;
use kate::{
    couscous::multiproof_params,
    gridgen::{AsBytes, EvaluationGrid, PolynomialGrid},
    pmp::m1_blst::M1NoPrecomp,
    PublicParameters,
};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use std::{
    num::NonZeroU16,
    sync::Arc,
    time::{Duration, Instant},
    sync::OnceLock,
    vec::Vec
};
use tokio::task::JoinSet;
use tracing::Instrument;

static SRS: std::sync::OnceLock<M1NoPrecomp> = std::sync::OnceLock::new();
static PMP: OnceLock<M1NoPrecomp> = OnceLock::new();

fn make_txs(block_length: &BlockLength, tx_count: u32) -> Vec<AppExtrinsic> {
    let max_size = block_length.rows.0
        * block_length.cols.0
        * (block_length.chunk_size().get().checked_sub(2).unwrap());
    let data_length = max_size / tx_count;

    let mut data = Vec::new();
    for _ in 0..(max_size / data_length) {
        let mut r = vec![0; usize::try_from(data_length).unwrap()];
        thread_rng().fill_bytes(&mut r);
        data.push(AppExtrinsic::from(r));
    }
    data
}

fn block_length(cols: u32, rows: u32) -> BlockLength {
    BlockLength::with_normal_ratio(
        BlockLengthRows(rows),
        BlockLengthColumns(cols),
        BLOCK_CHUNK_SIZE,
        DA_DISPATCH_RATIO,
    )
    .unwrap()
}

const RUNS: u32 = 10;

fn get_proof(grid: &EvaluationGrid, poly: &PolynomialGrid, cell_count: u32) -> Vec<Cell> {
    let srs = SRS.get_or_init(multiproof_params);

    (0..cell_count)
        .into_par_iter()
        .map(|row| -> Cell {
            let col = row;
            let data = grid
                .get(row as usize, col as usize)
                .unwrap()
                .to_bytes()
                .unwrap();

            let proof = poly
                .proof(
                    srs,
                    &kate::com::Cell::new(BlockLengthRows(row), BlockLengthColumns(col)),
                )
                .unwrap()
                .to_bytes()
                .unwrap();

            let mut proof_bytes = [0; 80];
            let mut j = 0;
            for b in proof {
                proof_bytes[j] = b;
                j += 1;
            }
            for b in data {
                proof_bytes[j] = b;
                j += 1;
            }

            Cell {
                position: Position {
                    row,
                    col: col as u16,
                },
                content: proof_bytes,
            }
        })
        .collect::<Vec<_>>()
}

async fn verify_proof(
    public_parameters: Arc<PublicParameters>,
    dimensions: Dimensions,
    commitment: [u8; 48],
    cell: kate_recovery::data::Cell,
) -> (Position, bool) {
    kate_recovery::proof::verify(&public_parameters, dimensions, &commitment, &cell)
        .map(|verified| (cell.position, verified))
        .unwrap()
}

#[tokio::main]
async fn main() {
    let seed = [0u8; 32];
    let data_root = H256::zero();
    let public_parameters = Arc::new(kate_recovery::couscous::public_params());

    let max_cols = [64, 128, 256, 512, 1024];
    let max_rows = [64, 128, 256, 512, 1024];

    println!("Options, Data Size, Commitment, Proofs (1, 16, 32), Verification (1, 16, 32), Commitment Size, Proof Size (1, 16, 32)");
    for cols in max_cols {
        for rows in max_rows {
            let total_data_size: u32 = cols * rows * 30;

            let mut commit_time = Duration::default();
            let mut erasure_time = Duration::default();
            let mut proof_time = (
                Duration::default(),
                Duration::default(),
                Duration::default(),
            );
            let mut verify_time = (
                Duration::default(),
                Duration::default(),
                Duration::default(),
            );
            let mut commit_size = 0;
            let mut proof_size = 0;

            for _ in 0..RUNS {
                let block_length = block_length(cols, rows);

                // Data generation
                let submitted = make_txs(&block_length, 1);

                // Commitment
                let mut timer = Instant::now();
                let grid = EvaluationGrid::from_extrinsics(
                    submitted.clone(),
                    MIN_WIDTH,
                    block_length.cols.0.saturated_into(), // even if we run on a u16 target this is fine
                    block_length.rows.0.saturated_into(),
                    seed,
                )
                .map_err(|e| format!("Grid construction failed: {e:?}"))
                .unwrap();

                let pmp = PMP.get_or_init(multiproof_params);

                let poly_grid = grid
                    .make_polynomial_grid()
                    .map_err(|e| format!("Make polynomial grid failed: {e:?}"))
                    .unwrap();

                let extended_grid = poly_grid
                    .extended_commitments(pmp, 2)
                    .map_err(|e| format!("Grid extension failed: {e:?}"))
                    .unwrap();
                let mut commitment = Vec::new();
                for c in extended_grid.iter() {
                    let bytes = c.to_bytes().unwrap();
                    commitment.extend(bytes);
                }
                let rows = grid.dims().rows().get();
                let cols = grid.dims().cols().get();
                let kate_commitments =
                    kc::v3::KateCommitment::new(rows, cols, data_root, commitment);
                commit_time += timer.elapsed();

                // Erasure Coding
                timer = Instant::now();
                let grid = grid
                    .extend_columns(NonZeroU16::new(2).expect("2>0"))
                    .unwrap();
                let poly = grid.make_polynomial_grid().unwrap();
                erasure_time += timer.elapsed();

                // Proof
                let mut data_proofs = Vec::new();
                let lims = [1, 16, 32];
                timer = Instant::now();
                data_proofs.push(get_proof(&grid, &poly, lims[0]));
                proof_time.0 += timer.elapsed();

                timer = Instant::now();
                data_proofs.push(get_proof(&grid, &poly, lims[1]));
                proof_time.1 += timer.elapsed();

                timer = Instant::now();
                data_proofs.push(get_proof(&grid, &poly, lims[2]));
                proof_time.2 += timer.elapsed();

                // Verification
                let commitments =
                    kate_recovery::commitments::from_slice(&kate_commitments.commitment).unwrap();

                for (index, cells) in data_proofs.into_iter().enumerate() {
                    timer = Instant::now();
                    let mut tasks = JoinSet::new();
                    for cell in cells {
                        tasks.spawn(
                            verify_proof(
                                public_parameters.clone(),
                                Dimensions::new(kate_commitments.rows, kate_commitments.cols)
                                    .unwrap(),
                                commitments[cell.position.row as usize],
                                cell,
                            )
                            .in_current_span(),
                        );
                    }
                    while let Some(result) = tasks.join_next().await {
                        let res = result.unwrap();
                        if res.1 != true {
                            println!("{:?}", res.0);
                            panic!("FAILED A PROOF VERIFICATION");
                        }
                    }
                    match index {
                        0 => verify_time.0 += timer.elapsed(),
                        1 => verify_time.1 += timer.elapsed(),
                        2 => verify_time.2 += timer.elapsed(),
                        _ => panic!("UNEXPECTED INDEX"),
                    };
                }

                // Commitment size (rows: u16 + cols: u16 + data_root: hash (assume 32) + commitment)
                commit_size = 2 + 2 + 32 + kate_commitments.commitment.len() as u32;

                // Proof Size
                proof_size = 4 + 80; // row: u16, col: u16, proof: 80 (data: 32, proof: 48)
            }
            println!("({}, {}), {}Kb, {:?}, {:?}, ({:?}, {:?}, {:?}), ({:?}, {:?}, {:?}), {}, ({}, {}, {})",
                rows,
                cols,
                total_data_size / 1024,
                erasure_time / RUNS,
                commit_time / RUNS,
                proof_time.0 / RUNS,
                proof_time.1 / RUNS,
                proof_time.2 / RUNS,
                verify_time.0 / RUNS,
                verify_time.1 / RUNS,
                verify_time.2 / RUNS,
                commit_size,
                proof_size,
                proof_size * 16,
                proof_size * 32
            );
        }
    }
}
