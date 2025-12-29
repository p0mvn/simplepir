//! Error types for the HIBP library

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid hash format: {0}")]
    InvalidHash(String),

    #[error("Range file not found: {0}")]
    RangeNotFound(String),

    #[error("Parse error: {0}")]
    Parse(String),
}
