use std::path::PathBuf;

/// Errors surfaced by the API facade.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error(transparent)]
    Core(#[from] apiimo_core::Error),

    #[error("I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("no dump found at {path}: run the `dump` command first")]
    MissingDump { path: PathBuf },

    #[error(transparent)]
    Network(#[from] apiimo_network::NetworkError),
}
