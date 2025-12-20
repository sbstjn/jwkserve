//! Common test utilities and helpers
//!
//! Provides reusable components for integration testing:
//! - TestServer: Spawn ephemeral servers with fixture keys
//! - JWT verification: Validate signatures using JWKS
//! - Fixture management: Load deterministic test keys

use std::net::TcpListener;
use std::path::Path;
use std::sync::OnceLock;
use tokio::task::JoinHandle;

use jwkserve::{
    key::{EcdsaCurve, EcdsaPrivateKey, RsaPrivateKey},
    router::{build_router, ServerState},
    KeySignAlgorithm,
};

static FIXTURE_KEY_2048: OnceLock<RsaPrivateKey> = OnceLock::new();
static FIXTURE_KEY_3072: OnceLock<RsaPrivateKey> = OnceLock::new();
static FIXTURE_KEY_4096: OnceLock<RsaPrivateKey> = OnceLock::new();
static FIXTURE_ECDSA_P256: OnceLock<EcdsaPrivateKey> = OnceLock::new();
static FIXTURE_ECDSA_P384: OnceLock<EcdsaPrivateKey> = OnceLock::new();
static FIXTURE_ECDSA_P521: OnceLock<EcdsaPrivateKey> = OnceLock::new();

pub struct TestServer {
    pub base_url: String,
    #[allow(dead_code)]
    pub issuer: String,
    handle: JoinHandle<()>,
}

/// Load RSA key from fixture file (cached for reuse)
fn load_fixture_key(bits: usize) -> color_eyre::Result<RsaPrivateKey> {
    let static_key = match bits {
        2048 => &FIXTURE_KEY_2048,
        3072 => &FIXTURE_KEY_3072,
        4096 => &FIXTURE_KEY_4096,
        _ => return Err(color_eyre::eyre::eyre!("Unsupported key size: {bits}")),
    };

    Ok(static_key
        .get_or_init(|| {
            let path = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests")
                .join("fixtures")
                .join(format!("rsa_{bits}.pem"));

            RsaPrivateKey::from_pem_file(&path)
                .unwrap_or_else(|_| panic!("Failed to load fixture key from {}", path.display()))
        })
        .clone())
}

/// Load ECDSA key from fixture file (cached for reuse)
pub fn load_ecdsa_fixture_key(curve: EcdsaCurve) -> color_eyre::Result<EcdsaPrivateKey> {
    let static_key = match curve {
        EcdsaCurve::P256 => &FIXTURE_ECDSA_P256,
        EcdsaCurve::P384 => &FIXTURE_ECDSA_P384,
        EcdsaCurve::P521 => &FIXTURE_ECDSA_P521,
    };

    Ok(static_key
        .get_or_init(|| {
            let curve_name = match curve {
                EcdsaCurve::P256 => "p256",
                EcdsaCurve::P384 => "p384",
                EcdsaCurve::P521 => "p521",
            };

            let path = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests")
                .join("fixtures")
                .join(format!("ecdsa_{}.pem", curve_name));

            EcdsaPrivateKey::from_pem_file(&path).unwrap_or_else(|_| {
                panic!("Failed to load ECDSA fixture key from {}", path.display())
            })
        })
        .clone())
}

impl TestServer {
    /// Spawn a test server with the specified configuration using fixture keys
    pub async fn spawn(
        key_size: usize,
        algorithms: Vec<KeySignAlgorithm>,
    ) -> color_eyre::Result<Self> {
        let key = load_fixture_key(key_size)?;
        Self::spawn_with_key(algorithms, key).await
    }

    /// Spawn a test server with a provided key (for testing key generation)
    pub async fn spawn_with_key(
        algorithms: Vec<KeySignAlgorithm>,
        key: RsaPrivateKey,
    ) -> color_eyre::Result<Self> {
        let port = find_available_port()?;
        let bind_addr = format!("127.0.0.1:{port}");
        let issuer = format!("http://localhost:{port}");
        let base_url = issuer.clone();

        // Use ECDSA fixture keys for deterministic testing
        let ecdsa_p256 = load_ecdsa_fixture_key(EcdsaCurve::P256)?;
        let ecdsa_p384 = load_ecdsa_fixture_key(EcdsaCurve::P384)?;
        let ecdsa_p521 = load_ecdsa_fixture_key(EcdsaCurve::P521)?;

        // Build router with state
        let state = ServerState::new(
            issuer.clone(),
            algorithms,
            key,
            ecdsa_p256,
            ecdsa_p384,
            ecdsa_p521,
        );
        let router = build_router(state);

        // Spawn server
        let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });

        // Wait for server to be ready by polling the root endpoint
        let client = reqwest::Client::new();
        let max_attempts = 10;
        let mut attempts = 0;
        loop {
            match client.get(&base_url).send().await {
                Ok(_) => break,
                Err(_) if attempts < max_attempts => {
                    attempts += 1;
                    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
                }
                Err(e) => {
                    return Err(color_eyre::eyre::eyre!(
                        "Server failed to become ready after {} attempts: {}",
                        max_attempts,
                        e
                    ));
                }
            }
        }

        Ok(Self {
            base_url,
            issuer,
            handle,
        })
    }

    /// Sign a JWT with the specified claims and algorithm
    ///
    /// Uses the standard JWT algorithm names (RS256, ES384, etc.) directly in the URL.
    pub async fn sign_jwt(
        &self,
        claims: serde_json::Value,
        algorithm: Option<&str>,
    ) -> color_eyre::Result<String> {
        let url = if let Some(alg) = algorithm {
            // Use algorithm name directly in URL path
            format!("{}/sign/{}", self.base_url, alg.to_uppercase())
        } else {
            format!("{}/sign", self.base_url)
        };

        let client = reqwest::Client::new();
        let response = client
            .post(&url)
            .json(&claims)
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        let token = response
            .get("token")
            .and_then(|t| t.as_str())
            .ok_or_else(|| color_eyre::eyre::eyre!("No token in response"))?;

        Ok(token.to_string())
    }

    /// Fetch JWKS from the server
    pub async fn fetch_jwks(&self) -> color_eyre::Result<serde_json::Value> {
        let url = format!("{}/.well-known/jwks.json", self.base_url);
        let jwks = reqwest::get(&url).await?.json().await?;
        Ok(jwks)
    }

    /// Fetch OpenID configuration
    #[allow(dead_code)]
    pub async fn fetch_openid_config(&self) -> color_eyre::Result<serde_json::Value> {
        let url = format!("{}/.well-known/openid-configuration", self.base_url);
        let config = reqwest::get(&url).await?.json().await?;
        Ok(config)
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// Find an available port for testing
fn find_available_port() -> color_eyre::Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    Ok(port)
}

/// Extract JWT header information
#[allow(dead_code)]
pub fn decode_jwt_header(token: &str) -> color_eyre::Result<jsonwebtoken::Header> {
    use jsonwebtoken::decode_header;
    Ok(decode_header(token)?)
}

/// Verify a JWT token using jsonwebtoken (supports both RSA and ECDSA)
pub fn verify_token(
    token: &str,
    jwks: &serde_json::Value,
) -> color_eyre::Result<serde_json::Value> {
    use jsonwebtoken::{decode, decode_header, DecodingKey, Validation};

    let header = decode_header(token)?;

    // Kid MUST be present in JWT header
    let header_kid = header
        .kid
        .as_ref()
        .ok_or_else(|| color_eyre::eyre::eyre!("JWT header missing required 'kid' field"))?;

    // Find matching key
    let keys = jwks
        .get("keys")
        .and_then(|k| k.as_array())
        .ok_or_else(|| color_eyre::eyre::eyre!("Invalid JWKS format"))?;

    // Determine expected algorithm from JWT header
    let expected_alg = match header.alg {
        jsonwebtoken::Algorithm::RS256 => "RS256",
        jsonwebtoken::Algorithm::RS384 => "RS384",
        jsonwebtoken::Algorithm::RS512 => "RS512",
        jsonwebtoken::Algorithm::ES256 => "ES256",
        jsonwebtoken::Algorithm::ES384 => "ES384",
        _ => {
            return Err(color_eyre::eyre::eyre!(
                "Unsupported algorithm: {:?}",
                header.alg
            ))
        }
    };

    let key_json = keys
        .iter()
        .find(|k| {
            let kid_matches = k
                .get("kid")
                .and_then(|v| v.as_str())
                .map(|jwk_kid| jwk_kid == header_kid)
                .unwrap_or(false);

            let alg_matches = k
                .get("alg")
                .and_then(|v| v.as_str())
                .map(|alg| alg == expected_alg)
                .unwrap_or(false);

            kid_matches && alg_matches
        })
        .ok_or_else(|| {
            color_eyre::eyre::eyre!(
                "No matching key in JWKS for kid '{}' and algorithm '{}'",
                header_kid,
                expected_alg
            )
        })?;

    // Determine key type and create appropriate decoding key
    let kty = key_json
        .get("kty")
        .and_then(|v| v.as_str())
        .ok_or_else(|| color_eyre::eyre::eyre!("Missing 'kty' in key"))?;

    let decoding_key = match kty {
        "RSA" => {
            let n = key_json
                .get("n")
                .and_then(|v| v.as_str())
                .ok_or_else(|| color_eyre::eyre::eyre!("Missing 'n' in RSA key"))?;
            let e = key_json
                .get("e")
                .and_then(|v| v.as_str())
                .ok_or_else(|| color_eyre::eyre::eyre!("Missing 'e' in RSA key"))?;
            DecodingKey::from_rsa_components(n, e)?
        }
        "EC" => {
            let x = key_json
                .get("x")
                .and_then(|v| v.as_str())
                .ok_or_else(|| color_eyre::eyre::eyre!("Missing 'x' in EC key"))?;
            let y = key_json
                .get("y")
                .and_then(|v| v.as_str())
                .ok_or_else(|| color_eyre::eyre::eyre!("Missing 'y' in EC key"))?;
            DecodingKey::from_ec_components(x, y)?
        }
        _ => return Err(color_eyre::eyre::eyre!("Unsupported key type: {}", kty)),
    };

    let mut validation = Validation::new(header.alg);
    validation.validate_aud = false;
    validation.validate_exp = false;
    validation.iss = None;

    let decoded = decode::<serde_json::Value>(token, &decoding_key, &validation)?;
    Ok(decoded.claims)
}
