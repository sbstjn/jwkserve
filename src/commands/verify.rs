use std::time::Duration;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use clap::Args;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde_json::Value;
use tracing::{info, warn};

#[derive(Args)]
pub struct ArgsVerify {
    /// JWT token to verify
    #[arg(value_name = "TOKEN")]
    pub token: String,

    /// Skip issuer validation (useful for testing)
    #[arg(long)]
    pub skip_issuer: bool,

    /// Skip expiration validation (useful for testing expired tokens)
    #[arg(long)]
    pub skip_exp: bool,

    /// Skip not-before validation
    #[arg(long)]
    pub skip_nbf: bool,

    /// Expected audience (can be specified multiple times)
    #[arg(long = "aud")]
    pub audience: Vec<String>,
}

/// Validate that JWKS URI is from the same origin or trusted subdomain as issuer
fn validate_jwks_uri(issuer: &str, jwks_uri: &str) -> color_eyre::Result<()> {
    let issuer_url = issuer
        .parse::<url::Url>()
        .map_err(|_| color_eyre::eyre::eyre!("invalid issuer URL: {}", issuer))?;

    let jwks_url = jwks_uri
        .parse::<url::Url>()
        .map_err(|_| color_eyre::eyre::eyre!("invalid JWKS URI: {}", jwks_uri))?;

    // Ensure JWKS URI uses same scheme (http/https)
    if issuer_url.scheme() != jwks_url.scheme() {
        return Err(color_eyre::eyre::eyre!(
            "JWKS URI scheme '{}' does not match issuer scheme '{}'",
            jwks_url.scheme(),
            issuer_url.scheme()
        ));
    }

    // Ensure JWKS URI is from the same domain or subdomain
    let issuer_host = issuer_url
        .host_str()
        .ok_or_else(|| color_eyre::eyre::eyre!("issuer missing host"))?;

    let jwks_host = jwks_url
        .host_str()
        .ok_or_else(|| color_eyre::eyre::eyre!("JWKS URI missing host"))?;

    if jwks_host != issuer_host && !jwks_host.ends_with(&format!(".{issuer_host}")) {
        return Err(color_eyre::eyre::eyre!(
            "JWKS URI host '{}' is not from the same domain as issuer '{}'",
            jwks_host,
            issuer_host
        ));
    }

    Ok(())
}

pub async fn handle_verify(args: &ArgsVerify) -> color_eyre::Result<()> {
    info!("Verifying JWT token");

    // Create HTTP client with timeout
    const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
    let client = reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .build()?;

    // Decode header to get algorithm and kid
    let header = decode_header(&args.token)?;
    info!("Token algorithm: {:?}", header.alg);
    if let Some(kid) = &header.kid {
        info!("Token key ID (kid): {}", kid);
    }

    // Decode without verification first to get claims (especially 'iss')
    let unverified: Value = {
        let parts: Vec<&str> = args.token.split('.').collect();
        if parts.len() >= 2 {
            URL_SAFE_NO_PAD
                .decode(parts[1])
                .ok()
                .and_then(|bytes| serde_json::from_slice(&bytes).ok())
                .unwrap_or(Value::Null)
        } else {
            Value::Null
        }
    };

    info!(
        "Token claims: {}",
        serde_json::to_string_pretty(&unverified)?
    );

    // Extract issuer
    let issuer = unverified
        .get("iss")
        .and_then(|v| v.as_str())
        .ok_or_else(|| color_eyre::eyre::eyre!("Token missing 'iss' claim"))?;

    info!("Token issuer: {}", issuer);

    // Fetch OpenID configuration to discover JWKS URI
    let openid_config_url = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    info!("Fetching OpenID configuration from: {}", openid_config_url);

    let openid_config: Value = client.get(&openid_config_url).send().await?.json().await?;

    let jwks_uri = openid_config
        .get("jwks_uri")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            color_eyre::eyre::eyre!(
                "OpenID configuration missing 'jwks_uri' field at {}",
                openid_config_url
            )
        })?;

    // Validate JWKS URI is from the same domain
    validate_jwks_uri(issuer, jwks_uri)?;

    info!("Fetching JWKS from: {}", jwks_uri);

    let jwks: Value = client.get(jwks_uri).send().await?.json().await?;

    let keys = jwks
        .get("keys")
        .and_then(|k| k.as_array())
        .ok_or_else(|| color_eyre::eyre::eyre!("Invalid JWKS format"))?;

    info!("Found {} keys in JWKS", keys.len());

    // Try to find matching key
    let matching_key = if let Some(kid) = &header.kid {
        keys.iter().find(|k| {
            k.get("kid")
                .and_then(|v| v.as_str())
                .map(|k_kid| k_kid == kid)
                .unwrap_or(false)
        })
    } else {
        // No kid, try first key with matching algorithm
        keys.iter().find(|k| {
            k.get("alg")
                .and_then(|v| v.as_str())
                .map(|alg| {
                    matches!(
                        (header.alg, alg),
                        (Algorithm::RS256, "RS256")
                            | (Algorithm::RS384, "RS384")
                            | (Algorithm::RS512, "RS512")
                    )
                })
                .unwrap_or(false)
        })
    };

    let key =
        matching_key.ok_or_else(|| color_eyre::eyre::eyre!("No matching key found in JWKS"))?;

    info!("Using key: {}", serde_json::to_string_pretty(key)?);

    // Extract n and e from JWK
    let n = key
        .get("n")
        .and_then(|v| v.as_str())
        .ok_or_else(|| color_eyre::eyre::eyre!("Key missing 'n' component"))?;
    let e = key
        .get("e")
        .and_then(|v| v.as_str())
        .ok_or_else(|| color_eyre::eyre::eyre!("Key missing 'e' component"))?;

    // Create decoding key
    let decoding_key = DecodingKey::from_rsa_components(n, e)?;

    // Setup validation
    let mut validation = Validation::new(header.alg);

    if args.skip_issuer {
        warn!("Skipping issuer validation");
        validation.iss = None;
    } else {
        validation.set_issuer(&[issuer]);
    }

    if args.skip_exp {
        warn!("Skipping expiration validation");
        validation.validate_exp = false;
    }

    if args.skip_nbf {
        warn!("Skipping not-before validation");
        validation.validate_nbf = false;
    }

    if !args.audience.is_empty() {
        info!("Validating audience: {:?}", args.audience);
        validation.set_audience(&args.audience);
    } else {
        validation.validate_aud = false;
    }

    // Verify the token
    let verified = decode::<Value>(&args.token, &decoding_key, &validation)?;

    println!("✓ Token verified successfully!");
    println!("\nClaims:");
    println!("{}", serde_json::to_string_pretty(&verified.claims)?);

    Ok(())
}
