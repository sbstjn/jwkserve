use axum::{
    extract::{DefaultBodyLimit, Path, State},
    http::{Request, StatusCode},
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use serde::Serialize;
use serde_json::{json, Value};
use std::{sync::Arc, time::Duration};
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};
use tracing::Span;

use crate::{
    key::{EcdsaPrivateKey, RsaPrivateKey},
    KeySignAlgorithm,
};
use std::collections::HashMap;

#[cfg(not(feature = "headless"))]
use axum::{http::header, response::Html};

#[cfg(not(feature = "headless"))]
use include_dir::{include_dir, Dir};

/// Embedded website directory, bundled at compile time
#[cfg(not(feature = "headless"))]
static WEBSITE_DIR: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/website");

/// Cryptographic key wrapper for unified storage
#[derive(Clone, Debug)]
pub enum CryptoKey {
    Rsa(Arc<RsaPrivateKey>),
    Ecdsa(Arc<EcdsaPrivateKey>),
}

impl CryptoKey {
    /// Sign JWT claims with this key using the specified algorithm
    fn sign_jwt(
        &self,
        claims: &Value,
        algorithm: &KeySignAlgorithm,
    ) -> Result<String, crate::key::KeyError> {
        match self {
            CryptoKey::Rsa(key) => key.sign_jwt(claims, algorithm),
            CryptoKey::Ecdsa(key) => key.sign_jwt(claims, algorithm),
        }
    }
}

/// Shared application state containing server configuration and cryptographic keys
///
/// All fields use Arc to minimize cloning overhead in Axum's State extractor,
/// which clones the state for each request handler.
#[derive(Clone)]
pub struct ServerState {
    /// Base issuer URL for OpenID configuration
    pub issuer: Arc<str>,
    /// Supported JWT signing algorithms
    pub algorithms: Arc<[KeySignAlgorithm]>,
    /// Unified key storage: algorithm -> key mapping
    keys: Arc<HashMap<KeySignAlgorithm, CryptoKey>>,
    /// Cached OpenID discovery response
    openid_config: Arc<Value>,
    /// Cached JWKS response
    jwks_response: Arc<Value>,
    /// Cached rendered HTML template (non-headless only)
    #[cfg(not(feature = "headless"))]
    cached_html: Arc<str>,
}

impl ServerState {
    /// Create new server state with the provided configuration
    pub fn new(
        issuer: String,
        algorithms: Vec<KeySignAlgorithm>,
        rsa_key: RsaPrivateKey,
        ecdsa_p256_key: EcdsaPrivateKey,
        ecdsa_p384_key: EcdsaPrivateKey,
        ecdsa_p521_key: EcdsaPrivateKey,
    ) -> Self {
        let issuer: Arc<str> = Arc::from(issuer.as_str());
        let jwks_uri = format!("{}/.well-known/jwks.json", issuer);

        // Store all keys (needed for signing with any algorithm)
        let rsa_key_arc = Arc::new(rsa_key);
        let ecdsa_p256_arc = Arc::new(ecdsa_p256_key);
        let ecdsa_p384_arc = Arc::new(ecdsa_p384_key);
        let ecdsa_p521_arc = Arc::new(ecdsa_p521_key);

        // Build key storage for ALL algorithms (signing flexibility for testing)
        let mut key_map: HashMap<KeySignAlgorithm, CryptoKey> = HashMap::new();

        // Map RSA algorithms
        for alg in [
            KeySignAlgorithm::RS256,
            KeySignAlgorithm::RS384,
            KeySignAlgorithm::RS512,
        ] {
            key_map.insert(alg, CryptoKey::Rsa(rsa_key_arc.clone()));
        }

        // Map ECDSA algorithms
        key_map.insert(
            KeySignAlgorithm::ES256,
            CryptoKey::Ecdsa(ecdsa_p256_arc.clone()),
        );
        key_map.insert(
            KeySignAlgorithm::ES384,
            CryptoKey::Ecdsa(ecdsa_p384_arc.clone()),
        );
        key_map.insert(
            KeySignAlgorithm::ES512,
            CryptoKey::Ecdsa(ecdsa_p521_arc.clone()),
        );

        // Pre-compute JWKS response from configured algorithms only
        let mut jwk_keys: Vec<Value> = Vec::new();
        for alg in &algorithms {
            let jwk = match alg {
                KeySignAlgorithm::RS256 | KeySignAlgorithm::RS384 | KeySignAlgorithm::RS512 => {
                    rsa_key_arc.to_jwk(alg)
                }
                KeySignAlgorithm::ES256 => ecdsa_p256_arc.to_jwk(alg),
                KeySignAlgorithm::ES384 => ecdsa_p384_arc.to_jwk(alg),
                KeySignAlgorithm::ES512 => ecdsa_p521_arc.to_jwk(alg),
            };
            jwk_keys.push(jwk);
        }

        let jwks_response = Arc::new(json!({
            "keys": jwk_keys
        }));

        // Pre-compute OpenID configuration
        let openid_config = Arc::new(json!({
            "issuer": issuer.as_ref(),
            "jwks_uri": jwks_uri,
        }));

        // Pre-render HTML template to avoid allocation on every request
        #[cfg(not(feature = "headless"))]
        let cached_html = {
            const TEMPLATE: &str = include_str!("../website/index.html");
            const VERSION: &str = env!("CARGO_PKG_VERSION");
            let html = TEMPLATE
                .replace("{{ISSUER}}", &issuer)
                .replace("{{VERSION}}", VERSION);
            Arc::from(html.as_str())
        };

        Self {
            issuer,
            algorithms: Arc::from(algorithms),
            keys: Arc::new(key_map),
            openid_config,
            jwks_response,
            #[cfg(not(feature = "headless"))]
            cached_html,
        }
    }

    /// Get the key for a specific algorithm
    ///
    /// Returns the key even if the algorithm is not in the configured algorithms list.
    /// This allows signing with any algorithm while only exposing configured ones in JWKS.
    fn get_key(&self, algorithm: &KeySignAlgorithm) -> Option<&CryptoKey> {
        self.keys.get(algorithm)
    }
}

/// Response for the /sign endpoint
#[derive(Serialize)]
pub struct SignResponse {
    token: String,
}

/// Build the application router with all endpoints and middleware
pub fn build_router(state: ServerState) -> Router {
    // Set maximum request body size to 1MB to prevent resource exhaustion
    const MAX_BODY_SIZE: usize = 1024 * 1024; // 1MB

    let router = Router::new()
        .route("/", get(root))
        .route("/.well-known/openid-configuration", get(openid_discovery))
        .route("/.well-known/jwks.json", get(jwks))
        .route("/sign", post(sign_default))
        .route("/sign/rsa/{size}", post(sign_rsa))
        .route("/sign/ecdsa/{size}", post(sign_ecdsa));

    #[cfg(not(feature = "headless"))]
    let router = router.route("/{*path}", get(serve_static));

    router
        .layer(DefaultBodyLimit::max(MAX_BODY_SIZE))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|request: &Request<_>| {
                    tracing::info_span!(
                        "http_request",
                        method = %request.method(),
                        uri = %request.uri(),
                    )
                })
                .on_response(
                    |response: &axum::http::Response<_>, latency: Duration, _span: &Span| {
                        tracing::info!(
                            status = response.status().as_u16(),
                            latency_ms = latency.as_millis(),
                            "request completed"
                        );
                    },
                )
                .on_failure(
                    |_error: tower_http::classify::ServerErrorsFailureClass,
                     _latency: Duration,
                     _span: &Span| {
                        tracing::error!("request failed");
                    },
                ),
        )
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        )
        .with_state(state)
}

/// Root endpoint serving the web UI or health check
#[cfg(feature = "headless")]
async fn root() -> &'static str {
    "OK"
}

/// Root endpoint serving the web UI
#[cfg(not(feature = "headless"))]
async fn root(State(state): State<ServerState>) -> Html<String> {
    // Arc clone is cheap (just ref count increment), then convert to String for response
    Html(state.cached_html.to_string())
}

/// Serve static files from the embedded website directory
#[cfg(not(feature = "headless"))]
async fn serve_static(Path(path): Path<String>) -> Response {
    // Remove leading slash for directory lookup
    let path = path.trim_start_matches('/');

    match WEBSITE_DIR.get_file(path) {
        Some(file) => {
            let mime_type = get_mime_type(path);
            let contents = file.contents();

            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, mime_type)],
                contents,
            )
                .into_response()
        }
        None => (StatusCode::NOT_FOUND, "404 Not Found").into_response(),
    }
}

/// Determine MIME type based on file extension
#[cfg(not(feature = "headless"))]
fn get_mime_type(path: &str) -> &'static str {
    if path.ends_with(".html") {
        "text/html; charset=utf-8"
    } else if path.ends_with(".css") {
        "text/css; charset=utf-8"
    } else if path.ends_with(".js") {
        "application/javascript; charset=utf-8"
    } else if path.ends_with(".json") {
        "application/json"
    } else if path.ends_with(".png") {
        "image/png"
    } else if path.ends_with(".jpg") || path.ends_with(".jpeg") {
        "image/jpeg"
    } else if path.ends_with(".svg") {
        "image/svg+xml"
    } else if path.ends_with(".ico") {
        "image/x-icon"
    } else if path.ends_with(".txt") {
        "text/plain; charset=utf-8"
    } else if path.ends_with(".webp") {
        "image/webp"
    } else {
        "application/octet-stream"
    }
}

/// OpenID Connect discovery endpoint
///
/// Returns OpenID Provider configuration metadata as defined in
/// OpenID Connect Discovery 1.0 specification.
/// Response is pre-computed at startup to avoid allocations on each request.
async fn openid_discovery(State(state): State<ServerState>) -> Json<Value> {
    // Arc clone is cheap (just ref count increment)
    Json((*state.openid_config).clone())
}

/// JSON Web Key Set (JWKS) endpoint
///
/// Returns the server's public keys in JWK format for JWT signature verification.
/// Implements RFC 7517 (JSON Web Key) and RFC 7518 (JSON Web Algorithms).
/// Response is pre-computed at startup to avoid allocations on each request.
///
/// Generates one JWK per configured algorithm, allowing the same key to be used
/// with multiple signing algorithms (RS256, RS384, RS512).
async fn jwks(State(state): State<ServerState>) -> Json<Value> {
    // Arc clone is cheap (just ref count increment)
    Json((*state.jwks_response).clone())
}

/// JWT signing endpoint with default algorithm (RS256)
///
/// Accepts arbitrary JSON claims and returns a signed JWT using RS256.
/// This is a developer tool - no validation is performed on claims.
///
/// # Request Body
/// Any valid JSON object representing JWT claims
///
/// # Example
/// ```text
/// POST /sign
/// {"sub": "user123", "aud": "my-app"}
/// ```
async fn sign_default(State(state): State<ServerState>, Json(claims): Json<Value>) -> Response {
    sign_with_algorithm(state, KeySignAlgorithm::RS256, claims).await
}

/// JWT signing endpoint with RSA key
///
/// Accepts arbitrary JSON claims and returns a signed JWT using RSA with the specified key size.
///
/// # Path Parameters
/// * `size` - Key size (256, 384, or 512 for RS256, RS384, RS512)
///
/// # Request Body
/// Any valid JSON object representing JWT claims
///
/// # Example
/// ```text
/// POST /sign/rsa/256
/// {"sub": "user123", "aud": "my-app"}
/// ```
async fn sign_rsa(
    State(state): State<ServerState>,
    Path(size): Path<String>,
    Json(claims): Json<Value>,
) -> Response {
    let algorithm = match size.as_str() {
        "256" => KeySignAlgorithm::RS256,
        "384" => KeySignAlgorithm::RS384,
        "512" => KeySignAlgorithm::RS512,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": format!("invalid RSA size: {size}. Valid sizes: 256, 384, 512")
                })),
            )
                .into_response();
        }
    };

    sign_with_algorithm(state, algorithm, claims).await
}

/// JWT signing endpoint with ECDSA key
///
/// Accepts arbitrary JSON claims and returns a signed JWT using ECDSA with the specified curve.
///
/// # Path Parameters
/// * `size` - Curve size (256 for P-256/ES256, 384 for P-384/ES384, 521 for P-521/ES512)
///
/// # Request Body
/// Any valid JSON object representing JWT claims
///
/// # Example
/// ```text
/// POST /sign/ecdsa/521
/// {"sub": "user123", "aud": "my-app"}
/// ```
async fn sign_ecdsa(
    State(state): State<ServerState>,
    Path(size): Path<String>,
    Json(claims): Json<Value>,
) -> Response {
    let algorithm = match size.as_str() {
        "256" => KeySignAlgorithm::ES256,
        "384" => KeySignAlgorithm::ES384,
        "521" => KeySignAlgorithm::ES512,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": format!("invalid ECDSA curve size: {size}. Valid sizes: 256, 384, 521")
                })),
            )
                .into_response();
        }
    };

    sign_with_algorithm(state, algorithm, claims).await
}

/// Internal signing logic shared by all signing endpoints
///
/// Note: This endpoint supports ALL algorithms (RS256-512, ES256-512) regardless
/// of server configuration. The --algorithm flag only controls which keys are
/// exposed in the JWKS endpoint, allowing you to test JWT validation scenarios
/// where the signing algorithm is not advertised in the key set.
///
/// If the claims do not include an 'iss' field, it will be automatically injected
/// from the server's issuer configuration.
async fn sign_with_algorithm(
    state: ServerState,
    algorithm: KeySignAlgorithm,
    mut claims: Value,
) -> Response {
    // Inject 'iss' claim if not present
    if let Some(claims_obj) = claims.as_object_mut() {
        if !claims_obj.contains_key("iss") {
            claims_obj.insert("iss".to_string(), json!(state.issuer.as_ref()));
        }
    }

    // Get the key for this algorithm (all algorithms are always available)
    let key = state
        .get_key(&algorithm)
        .expect("all algorithms should have keys");

    // Sign the JWT with the key
    let result = key.sign_jwt(&claims, &algorithm);

    match result {
        Ok(token) => (StatusCode::OK, Json(SignResponse { token })).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": format!("failed to sign JWT: {}", e)
            })),
        )
            .into_response(),
    }
}
