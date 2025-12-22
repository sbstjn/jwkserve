use std::io::{self, Read};
use std::path::PathBuf;
use std::time::Duration;

use clap::Args;
use serde_json::Value;
use tracing::debug;

use crate::{errors::JWKServeError, KeySignAlgorithm};

#[derive(Args)]
pub struct ArgsSign {
    /// JWKS endpoint URL (default: https://jwkserve.com)
    #[arg(long, default_value = "https://jwkserve.com", value_name = "URL")]
    pub endpoint: String,

    /// Signing algorithm (default: RS256)
    #[arg(long, value_enum, default_value = "RS256", value_name = "ALG")]
    pub algorithm: KeySignAlgorithm,

    /// Read claims from file instead of stdin
    #[arg(long, value_name = "FILE")]
    pub file: Option<PathBuf>,
}

fn read_stdin() -> color_eyre::Result<String> {
    let mut buffer = String::new();
    io::stdin()
        .read_to_string(&mut buffer)
        .map_err(|e| color_eyre::eyre::eyre!("Failed to read from stdin: {}", e))?;
    Ok(buffer)
}

fn read_file(path: &PathBuf) -> color_eyre::Result<String> {
    std::fs::read_to_string(path).map_err(|e| {
        JWKServeError::IoError {
            path: path.clone(),
            source: e,
        }
        .into()
    })
}

fn validate_endpoint_url(url_str: &str) -> color_eyre::Result<()> {
    if url_str.is_empty() {
        return Err(color_eyre::eyre::eyre!("endpoint URL cannot be empty"));
    }

    if url_str.len() > 2048 {
        return Err(color_eyre::eyre::eyre!(
            "endpoint URL exceeds maximum length of 2048 characters"
        ));
    }

    let url = url_str
        .parse::<url::Url>()
        .map_err(|e| color_eyre::eyre::eyre!("invalid endpoint URL: {}", e))?;

    if url.scheme() != "http" && url.scheme() != "https" {
        return Err(color_eyre::eyre::eyre!(
            "endpoint URL must use http or https scheme"
        ));
    }

    if url_str.ends_with('/') {
        return Err(color_eyre::eyre::eyre!(
            "endpoint URL must not end with trailing slash"
        ));
    }

    if url.host_str().is_none() {
        return Err(color_eyre::eyre::eyre!(
            "endpoint URL must have a valid host"
        ));
    }

    Ok(())
}

pub async fn handle_sign(args: &ArgsSign) -> color_eyre::Result<()> {
    validate_endpoint_url(&args.endpoint)?;

    let json_input = if let Some(ref file_path) = args.file {
        read_file(file_path)?
    } else {
        read_stdin()?
    };

    if json_input.trim().is_empty() {
        return Err(color_eyre::eyre::eyre!(
            "No input provided{}",
            if args.file.is_some() {
                " from file"
            } else {
                " via stdin"
            }
        ));
    }

    let claims: Value = serde_json::from_str(&json_input)
        .map_err(|e| color_eyre::eyre::eyre!("Invalid JSON input: {}", e))?;

    debug!(
        "Signing claims with algorithm {}: {}",
        args.algorithm, json_input
    );

    const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
    let client = reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .build()?;

    let sign_url = format!(
        "{}/sign/{}",
        args.endpoint.trim_end_matches('/'),
        args.algorithm
    );
    debug!("POSTing to: {}", sign_url);

    let response = client.post(&sign_url).json(&claims).send().await?;

    if !response.status().is_success() {
        let status = response.status();
        let error_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown error".to_string());
        return Err(color_eyre::eyre::eyre!(
            "Signing failed with status {}: {}",
            status,
            error_text
        ));
    }

    let sign_response: Value = response.json().await?;
    let token = sign_response
        .get("token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| color_eyre::eyre::eyre!("Invalid response format: missing 'token' field"))?;

    println!("{}", token);

    Ok(())
}
