use crate::errors::JWKServeError;
use std::io::Write;
use std::path::PathBuf;

pub mod keygen;
pub mod serve;
pub mod show;
pub mod verify;

/// Write response content to file or stdout
/// Validates that the file doesn't exist to prevent accidental overwrites
pub fn write_response_to_file(path: &PathBuf, content: &str) -> color_eyre::Result<()> {
    if path.exists() {
        return Err(JWKServeError::FileExists { path: path.clone() }.into());
    }

    std::fs::write(path, content).map_err(|e| JWKServeError::IoError {
        path: path.clone(),
        source: e,
    })?;

    Ok(())
}

/// Show output to stdout or save to file
/// If output_path is Some, writes to file silently. Otherwise writes to stdout.
pub fn show_output_or_save(output_path: Option<&PathBuf>, content: &str) -> color_eyre::Result<()> {
    if let Some(path) = output_path {
        write_response_to_file(path, content)?;
    } else {
        std::io::stdout()
            .write_all(content.as_bytes())
            .map_err(|e| JWKServeError::IoError {
                path: PathBuf::from("<stdout>"),
                source: e,
            })?;
    }

    Ok(())
}
