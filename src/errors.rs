use std::path::PathBuf;

use thiserror::Error;

use crate::key::RsaKeyError;

#[derive(Error, Debug)]
pub enum JWKServeError {
    #[error("RSA key error: {0}")]
    RsaKeyError(#[from] RsaKeyError),

    #[error("file already exists: {path}")]
    FileExists { path: PathBuf },

    #[error("failed to read file: {path}")]
    IoError {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}
