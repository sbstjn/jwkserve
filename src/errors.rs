use std::path::PathBuf;

use thiserror::Error;

use crate::key::KeyError;

#[derive(Error, Debug)]
pub enum JWKServeError {
    #[error("key error: {0}")]
    KeyError(#[from] KeyError),

    #[error("file already exists: {path}")]
    FileExists { path: PathBuf },

    #[error("failed to read file: {path}")]
    IoError {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}
