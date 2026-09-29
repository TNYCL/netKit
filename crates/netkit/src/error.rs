#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid input: {0}")]
    Invalid(String),
    #[error("resource limit: {0}")]
    Limit(String),
    #[error("capture: {0}")]
    Capture(String),
    #[error("unavailable: {0}")]
    Unavailable(String),
    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),
}
pub type Result<T> = std::result::Result<T, Error>;
