use std::path::PathBuf;

use thiserror::Error;

/// Errors returned by the core Apiimo pipeline.
#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("JSON error at {path}: {source}")]
    Json {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    #[error("regular expression error: {0}")]
    Regex(#[from] regex::Error),

    #[error("crypto error: {0}")]
    Crypto(#[from] apiimo_crypto::CryptoError),

    #[error("invalid metadata: {0}")]
    InvalidMetadata(String),

    #[error("invalid PE image: {0}")]
    InvalidPe(String),

    #[error("invalid hexadecimal data: {0}")]
    InvalidHex(String),

    #[error("missing required file: {0}")]
    MissingFile(PathBuf),

    #[error("external dumper failed to start: {0}")]
    DumperStart(String),
}

pub(crate) fn io_error(path: impl Into<PathBuf>, source: std::io::Error) -> Error {
    Error::Io {
        path: path.into(),
        source,
    }
}

pub(crate) fn json_error(path: impl Into<PathBuf>, source: serde_json::Error) -> Error {
    Error::Json {
        path: path.into(),
        source,
    }
}
