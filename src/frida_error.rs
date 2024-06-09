#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FridaError {
    DeserializationError(),
    XYCoordinateLengthMismatch(),
    NotEnoughDataPoints(),
    BadDataLength(),
    NotEnoughEvaluationsForDecoding(),
    DrawError(),
    FailedToDrawEnoughQueryPoints(usize, usize),
    DomainSizeTooBig(usize),
    BadNumQueries(usize),
    InvalidDASCommitment,
    FailToVerify,
    /// Polynomial degree at one of the FRI layers could not be divided evenly by the folding factor.
    DegreeTruncation(usize, usize, usize),
}
