use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;

use clap::Args;

use crate::{
    errors::JWKServeError,
    key::{EcdsaCurve, EcdsaPrivateKey, RsaPrivateKey},
    router::{build_router, IssuerMode, ServerState},
    KeySignAlgorithm,
};

#[derive(Args)]
pub struct ArgsServe {
    #[arg(short, long, default_value = "3000", value_name = "PORT")]
    pub port: u16,

    #[arg(short, long, default_value = "127.0.0.1", value_name = "ADDR")]
    pub bind: String,

    #[arg(short, long, value_name = "URL", conflicts_with = "issuer_from_host")]
    pub issuer: Option<String>,

    #[arg(long, conflicts_with = "issuer")]
    pub issuer_from_host: bool,

    #[arg(
        long,
        value_name = "SCHEME",
        value_parser = ["http", "https"],
        conflicts_with = "issuer"
    )]
    pub issuer_scheme: Option<String>,

    #[arg(long, conflicts_with = "issuer")]
    pub trust_forwarded_headers: bool,

    #[arg(short, long = "algorithm", value_enum, value_name = "ALG")]
    pub algorithms: Vec<KeySignAlgorithm>,

    #[arg(short, long = "key", value_name = "FILE")]
    pub key_files: Vec<PathBuf>,
}

fn validate_issuer_url(url_str: &str) -> color_eyre::Result<()> {
    if url_str.is_empty() {
        return Err(color_eyre::eyre::eyre!("issuer URL cannot be empty"));
    }

    if url_str.len() > 2048 {
        return Err(color_eyre::eyre::eyre!(
            "issuer URL exceeds maximum length of 2048 characters"
        ));
    }

    let url = url_str
        .parse::<url::Url>()
        .map_err(|e| color_eyre::eyre::eyre!("invalid issuer URL: {}", e))?;

    if url.scheme() != "http" && url.scheme() != "https" {
        return Err(color_eyre::eyre::eyre!(
            "issuer URL must use http or https scheme"
        ));
    }

    if url_str.ends_with('/') {
        return Err(color_eyre::eyre::eyre!(
            "issuer URL must not end with trailing slash"
        ));
    }

    if url.host_str().is_none() {
        return Err(color_eyre::eyre::eyre!("issuer URL must have a valid host"));
    }

    Ok(())
}

fn validate_bind_address(addr: &str) -> color_eyre::Result<IpAddr> {
    addr.parse::<IpAddr>()
        .map_err(|_| color_eyre::eyre::eyre!("invalid bind address: {}", addr))
}

fn resolve_issuer_mode(args: &ArgsServe) -> color_eyre::Result<(IssuerMode, String)> {
    if let Some(ref issuer_url) = args.issuer {
        validate_issuer_url(issuer_url)?;
        return Ok((
            IssuerMode::Static(Arc::from(issuer_url.as_str())),
            format!("for issuer {}", issuer_url),
        ));
    }

    let scheme = args.issuer_scheme.as_deref().unwrap_or("http").to_string();
    let trust_forwarded_headers = args.trust_forwarded_headers;

    Ok((
        IssuerMode::FromHost {
            scheme: Arc::from(scheme.as_str()),
            trust_forwarded_headers,
        },
        format!(
            "with issuer derived from request host using scheme {}{}",
            scheme,
            if trust_forwarded_headers {
                " and trusted forwarded headers"
            } else {
                ""
            }
        ),
    ))
}

struct KeyCollection {
    rsa: Option<RsaPrivateKey>,
    ecdsa: HashMap<EcdsaCurve, EcdsaPrivateKey>,
}

fn load_keys(paths: &[PathBuf]) -> color_eyre::Result<KeyCollection> {
    let mut collection = KeyCollection {
        rsa: None,
        ecdsa: HashMap::new(),
    };

    for path in paths {
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

        return Err(color_eyre::eyre::eyre!(
            "Failed to load key from {:?}: not a valid RSA or ECDSA (P-256, P-384, P-521) key",
            path
        ));
    }

    Ok(collection)
}

pub async fn handle_serve(args: &ArgsServe) -> color_eyre::Result<()> {
    info!("Starting jwkserve");

    let bind_ip = validate_bind_address(&args.bind)?;

    let (issuer_mode, listen_log) = resolve_issuer_mode(args)?;

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

    let mut collection = load_keys(&args.key_files)?;

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
        issuer_mode,
        algorithms.to_vec(),
        rsa_key,
        ecdsa_p256_key,
        ecdsa_p384_key,
        ecdsa_p521_key,
    );
    let router = build_router(state);

    let addr = SocketAddr::new(bind_ip, args.port);
    info!("Server listening on {} {}", addr, listen_log);
    info!("Supported algorithms: {:?}", algorithms);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct ServeCli {
        #[command(flatten)]
        args: ArgsServe,
    }

    #[test]
    fn test_default_mode_uses_request_host() {
        let args = ServeCli::try_parse_from(["jwkserve"]).unwrap().args;
        let (issuer_mode, listen_log) = resolve_issuer_mode(&args).unwrap();

        assert_eq!(
            listen_log,
            "with issuer derived from request host using scheme http"
        );
        match issuer_mode {
            IssuerMode::FromHost {
                scheme,
                trust_forwarded_headers,
            } => {
                assert_eq!(&*scheme, "http");
                assert!(!trust_forwarded_headers);
            }
            IssuerMode::Static(_) => panic!("expected dynamic issuer mode by default"),
        }
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

    #[test]
    fn test_issuer_and_issuer_from_host_conflict() {
        let result = ServeCli::try_parse_from([
            "jwkserve",
            "--issuer",
            "http://localhost:3000",
            "--issuer-from-host",
        ]);

        assert!(result.is_err());
    }

    #[test]
    fn test_issuer_scheme_is_allowed_without_issuer_from_host() {
        let args = ServeCli::try_parse_from(["jwkserve", "--issuer-scheme", "https"])
            .unwrap()
            .args;
        let (issuer_mode, _) = resolve_issuer_mode(&args).unwrap();

        match issuer_mode {
            IssuerMode::FromHost { scheme, .. } => assert_eq!(&*scheme, "https"),
            IssuerMode::Static(_) => panic!("expected dynamic issuer mode"),
        }
    }

    #[test]
    fn test_trust_forwarded_headers_is_allowed_without_issuer_from_host() {
        let args = ServeCli::try_parse_from(["jwkserve", "--trust-forwarded-headers"])
            .unwrap()
            .args;
        let (issuer_mode, _) = resolve_issuer_mode(&args).unwrap();

        match issuer_mode {
            IssuerMode::FromHost {
                trust_forwarded_headers,
                ..
            } => assert!(trust_forwarded_headers),
            IssuerMode::Static(_) => panic!("expected dynamic issuer mode"),
        }
    }

    #[test]
    fn test_explicit_issuer_stays_static() {
        let args = ServeCli::try_parse_from(["jwkserve", "--issuer", "https://issuer.example"])
            .unwrap()
            .args;
        let (issuer_mode, listen_log) = resolve_issuer_mode(&args).unwrap();

        assert_eq!(listen_log, "for issuer https://issuer.example");
        match issuer_mode {
            IssuerMode::Static(issuer) => assert_eq!(&*issuer, "https://issuer.example"),
            IssuerMode::FromHost { .. } => panic!("expected static issuer mode"),
        }
    }
}
