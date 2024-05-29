#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FridaError {
    DeserializationError(),
    XYCoordinateLengthMismatch(),
    NotEnoughDataPoints(),
    BadDataLength(),
    NotEnoughEvaluationsForDecoding(),
}
