use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use tracing::info;

use clap::Args;

use crate::{
    errors::JWKServeError,
    key::{EcdsaCurve, EcdsaPrivateKey, RsaPrivateKey},
    router::{build_router, ServerState},
    KeySignAlgorithm,
};

#[derive(Args)]
pub struct ArgsServe {
    /// Port to listen on
    #[arg(short, long, default_value = "3000", value_name = "PORT")]
    pub port: u16,

    /// Bind address (use 0.0.0.0 for Docker, 127.0.0.1 for local)
    #[arg(short, long, default_value = "127.0.0.1", value_name = "ADDR")]
    pub bind: String,

    /// Issuer URL (auto-generated from bind address and port if not provided)
    #[arg(short, long, value_name = "URL")]
    pub issuer: Option<String>,

    /// Supported signing algorithms (can be used multiple times, default: RS256)
    #[arg(short, long = "algorithm", value_enum, value_name = "ALG")]
    pub algorithms: Vec<KeySignAlgorithm>,

    /// Path to PEM-encoded private key file(s) - can be specified multiple times for different key types (RSA, ECDSA P-256, P-384, P-521). Keys are auto-detected. Missing key types are generated.
    #[arg(short, long = "key", value_name = "FILE")]
    pub key_files: Vec<PathBuf>,
}

/// Generate issuer URL from bind address and port
fn generate_issuer(bind: &IpAddr, port: u16) -> String {
    let host = if bind.is_unspecified() {
        "localhost"
    } else if bind.is_ipv6() {
        return format!("http://[{bind}]:{port}");
    } else {
        &bind.to_string()
    };

    format!("http://{host}:{port}")
}

/// Validate issuer URL format using proper URL parser
fn validate_issuer_url(url_str: &str) -> color_eyre::Result<()> {
    if url_str.is_empty() {
        return Err(color_eyre::eyre::eyre!("issuer URL cannot be empty"));
    }

    // Length validation to prevent resource exhaustion
    if url_str.len() > 2048 {
        return Err(color_eyre::eyre::eyre!(
            "issuer URL exceeds maximum length of 2048 characters"
        ));
    }

    // Parse URL to validate structure
    let url = url_str
        .parse::<url::Url>()
        .map_err(|e| color_eyre::eyre::eyre!("invalid issuer URL: {}", e))?;

    // Must use http or https scheme
    if url.scheme() != "http" && url.scheme() != "https" {
        return Err(color_eyre::eyre::eyre!(
            "issuer URL must use http or https scheme"
        ));
    }

    // Must not end with trailing slash (per OIDC spec)
    if url_str.ends_with('/') {
        return Err(color_eyre::eyre::eyre!(
            "issuer URL must not end with trailing slash"
        ));
    }

    // Must have a host
    if url.host_str().is_none() {
        return Err(color_eyre::eyre::eyre!("issuer URL must have a valid host"));
    }

    Ok(())
}

/// Validate bind address format
fn validate_bind_address(addr: &str) -> color_eyre::Result<IpAddr> {
    addr.parse::<IpAddr>()
        .map_err(|_| color_eyre::eyre::eyre!("invalid bind address: {}", addr))
}

/// Collection of loaded cryptographic keys
struct KeyCollection {
    rsa: Option<RsaPrivateKey>,
    ecdsa: HashMap<EcdsaCurve, EcdsaPrivateKey>,
}

/// Load keys from provided file paths and auto-detect their types
///
/// Attempts to parse each key as RSA first, then tries ECDSA curves.
/// Returns an error if a key cannot be parsed or if duplicate keys of the same type are found.
fn load_keys(paths: &[PathBuf]) -> color_eyre::Result<KeyCollection> {
    let mut collection = KeyCollection {
        rsa: None,
        ecdsa: HashMap::new(),
    };

    for path in paths {
        // Try RSA first
        if let Ok(key) = RsaPrivateKey::from_pem_file(path) {
            info!("Loaded RSA key from {:?} ({} bits)", path, key.size_bits());
            if collection.rsa.is_some() {
                return Err(color_eyre::eyre::eyre!(
                    "Multiple RSA keys provided - only one RSA key is supported"
                ));
            }
            collection.rsa = Some(key);
            continue;
        }

        // Try ECDSA keys
        if let Ok(key) = EcdsaPrivateKey::from_pem_file(path) {
            let curve = key.curve().clone();
            info!("Loaded ECDSA {} key from {:?}", curve.as_str(), path);

            if collection.ecdsa.contains_key(&curve) {
                return Err(color_eyre::eyre::eyre!(
                    "Multiple ECDSA {} keys provided - only one {} key is supported",
                    curve.as_str(),
                    curve.as_str()
                ));
            }
            collection.ecdsa.insert(curve, key);
            continue;
        }

        // If we get here, the key couldn't be parsed
        return Err(color_eyre::eyre::eyre!(
            "Failed to load key from {:?}: not a valid RSA or ECDSA (P-256, P-384, P-521) key",
            path
        ));
    }

    Ok(collection)
}

pub async fn handle_serve(args: &ArgsServe) -> color_eyre::Result<()> {
    info!("Starting jwkserve");

    // Validate bind address
    let bind_ip = validate_bind_address(&args.bind)?;

    // Determine issuer (use provided or auto-generate)
    let issuer = if let Some(ref issuer_url) = args.issuer {
        validate_issuer_url(issuer_url)?;
        issuer_url.clone()
    } else {
        generate_issuer(&bind_ip, args.port)
    };

    let algorithms = if args.algorithms.is_empty() {
        &[
            KeySignAlgorithm::RS256,
            KeySignAlgorithm::RS384,
            KeySignAlgorithm::RS512,
            KeySignAlgorithm::ES256,
            KeySignAlgorithm::ES384,
            KeySignAlgorithm::ES512,
        ][..]
    } else {
        &args.algorithms[..]
    };

    // Load keys from files and auto-detect their types
    let mut collection = load_keys(&args.key_files)?;

    // Determine which keys to log based on configured algorithms
    use crate::KeyType;
    let log_rsa = algorithms.iter().any(|alg| alg.key_type() == KeyType::Rsa);
    let log_p256 = algorithms
        .iter()
        .any(|alg| alg.curve() == Some(EcdsaCurve::P256));
    let log_p384 = algorithms
        .iter()
        .any(|alg| alg.curve() == Some(EcdsaCurve::P384));
    let log_p521 = algorithms
        .iter()
        .any(|alg| alg.curve() == Some(EcdsaCurve::P521));

    // Always generate all keys (needed for signing flexibility), but only log configured ones
    let rsa_key = if let Some(key) = collection.rsa.take() {
        key
    } else {
        if log_rsa {
            info!("Generating new RSA-2048 key");
        }
        RsaPrivateKey::generate(2048).map_err(JWKServeError::KeyError)?
    };

    let ecdsa_p256_key = if let Some(key) = collection.ecdsa.remove(&EcdsaCurve::P256) {
        key
    } else {
        if log_p256 {
            info!("Generating ECDSA P-256 key");
        }
        EcdsaPrivateKey::generate(EcdsaCurve::P256).map_err(JWKServeError::KeyError)?
    };

    let ecdsa_p384_key = if let Some(key) = collection.ecdsa.remove(&EcdsaCurve::P384) {
        key
    } else {
        if log_p384 {
            info!("Generating ECDSA P-384 key");
        }
        EcdsaPrivateKey::generate(EcdsaCurve::P384).map_err(JWKServeError::KeyError)?
    };

    let ecdsa_p521_key = if let Some(key) = collection.ecdsa.remove(&EcdsaCurve::P521) {
        key
    } else {
        if log_p521 {
            info!("Generating ECDSA P-521 key");
        }
        EcdsaPrivateKey::generate(EcdsaCurve::P521).map_err(JWKServeError::KeyError)?
    };

    let state = ServerState::new(
        issuer.clone(),
        algorithms.to_vec(),
        rsa_key,
        ecdsa_p256_key,
        ecdsa_p384_key,
        ecdsa_p521_key,
    );
    let router = build_router(state);

    let addr = SocketAddr::new(bind_ip, args.port);
    info!("Server listening on {} for issuer {}", addr, issuer);
    info!("Supported algorithms: {:?}", algorithms);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_issuer_localhost() {
        let bind = "127.0.0.1".parse::<IpAddr>().unwrap();
        assert_eq!(generate_issuer(&bind, 3000), "http://127.0.0.1:3000");
    }

    #[test]
    fn test_generate_issuer_unspecified() {
        let bind = "0.0.0.0".parse::<IpAddr>().unwrap();
        assert_eq!(generate_issuer(&bind, 8080), "http://localhost:8080");
    }

    #[test]
    fn test_generate_issuer_ipv6() {
        let bind = "::1".parse::<IpAddr>().unwrap();
        assert_eq!(generate_issuer(&bind, 3000), "http://[::1]:3000");
    }

    #[test]
    fn test_generate_issuer_ipv6_unspecified() {
        let bind = "::".parse::<IpAddr>().unwrap();
        assert_eq!(generate_issuer(&bind, 9000), "http://localhost:9000");
    }

    #[test]
    fn test_validate_issuer_url_valid() {
        assert!(validate_issuer_url("http://localhost:3000").is_ok());
        assert!(validate_issuer_url("https://example.com").is_ok());
    }

    #[test]
    fn test_validate_issuer_url_trailing_slash() {
        assert!(validate_issuer_url("http://localhost:3000/").is_err());
    }

    #[test]
    fn test_validate_issuer_url_missing_scheme() {
        assert!(validate_issuer_url("localhost:3000").is_err());
    }
}
