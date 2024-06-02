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
}
