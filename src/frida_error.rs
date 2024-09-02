use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FridaError {
    DeserializationError(winter_utils::DeserializationError),
    XYCoordinateLengthMismatch(),
    NotEnoughDataPoints(),
    BadDataLength(),
    NotEnoughEvaluationsForDecoding(),
    DrawError(),
    FailedToDrawEnoughQueryPoints(usize, usize),
    FailedToDrawEnoughXi(usize, usize),
    DomainSizeTooBig(usize),
    BadNumQueries(usize),
    InvalidDASCommitment,
    FailToVerify,
    /// Polynomial degree at one of the FRI layers could not be divided evenly by the folding factor.
    DegreeTruncation(usize, usize, usize),
    UnsupportedFoldingFactor(usize),
    SinglePolyBatch,
    ProofPolyCountMismatch,
}

impl fmt::Display for FridaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FridaError::DeserializationError(e) => {
                write!(f, "Deserialization error occurred: {}", e)
            }
            FridaError::XYCoordinateLengthMismatch() => write!(f, "XY coordinate length mismatch"),
            FridaError::NotEnoughDataPoints() => write!(f, "Not enough data points"),
            FridaError::BadDataLength() => write!(f, "Bad data length"),
            FridaError::NotEnoughEvaluationsForDecoding() => {
                write!(f, "Not enough evaluations for decoding")
            }
            FridaError::DrawError() => write!(f, "Draw error"),
            FridaError::FailedToDrawEnoughQueryPoints(required, drawn) => write!(
                f,
                "Failed to draw enough query points: required {}, drawn {}",
                required, drawn
            ),
            FridaError::FailedToDrawEnoughXi(required, drawn) => write!(
                f,
                "Failed to draw enough Xi: required {}, drawn {}",
                required, drawn
            ),
            FridaError::DomainSizeTooBig(size) => write!(f, "Domain size too big: {}", size),
            FridaError::BadNumQueries(num) => write!(f, "Bad number of queries: {}", num),
            FridaError::InvalidDASCommitment => write!(f, "Invalid DAS commitment"),
            FridaError::FailToVerify => write!(f, "Failed to verify"),
            FridaError::DegreeTruncation(layer, degree, factor) => write!(
                f,
                "Degree truncation error at layer {}: degree {}, factor {}",
                layer, degree, factor
            ),
            FridaError::UnsupportedFoldingFactor(factor) => {
                write!(f, "Unsupported folding factor: {}", factor)
            }
            FridaError::ProofPolyCountMismatch => {
                write!(f, "Proof's polynomial count does not match")
            }
            FridaError::SinglePolyBatch => write!(f, "Batch has only 1 polynomial"),
        }
    }
}

impl std::error::Error for FridaError {}
