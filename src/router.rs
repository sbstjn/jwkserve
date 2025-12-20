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

#[cfg(not(feature = "headless"))]
use axum::{http::header, response::Html};

#[cfg(not(feature = "headless"))]
use include_dir::{include_dir, Dir};

/// Embedded website directory, bundled at compile time
#[cfg(not(feature = "headless"))]
static WEBSITE_DIR: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/website");

/// Supported key types and sizes for signing operations
#[derive(Clone, Debug)]
pub enum SigningKey {
    Rsa(Arc<RsaPrivateKey>),
    Ecdsa(Arc<EcdsaPrivateKey>),
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
    /// RSA private key for signing operations (legacy, for backward compatibility)
    pub rsa_key: Arc<RsaPrivateKey>,
    /// ECDSA P-256 key
    pub ecdsa_p256_key: Arc<EcdsaPrivateKey>,
    /// ECDSA P-384 key
    pub ecdsa_p384_key: Arc<EcdsaPrivateKey>,
    /// ECDSA P-521 key
    pub ecdsa_p521_key: Arc<EcdsaPrivateKey>,
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

        // Pre-compute JWKS response from all keys
        let mut keys: Vec<Value> = Vec::new();

        // Add RSA JWKs for configured algorithms
        for alg in &algorithms {
            match alg {
                KeySignAlgorithm::RS256 | KeySignAlgorithm::RS384 | KeySignAlgorithm::RS512 => {
                    keys.push(rsa_key.to_jwk(alg));
                }
                KeySignAlgorithm::ES256 => {
                    keys.push(ecdsa_p256_key.to_jwk(alg));
                }
                KeySignAlgorithm::ES384 => {
                    keys.push(ecdsa_p384_key.to_jwk(alg));
                }
                KeySignAlgorithm::ES512 => {
                    keys.push(ecdsa_p521_key.to_jwk(alg));
                }
            }
        }

        let jwks_response = Arc::new(json!({
            "keys": keys
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
            rsa_key: Arc::new(rsa_key),
            ecdsa_p256_key: Arc::new(ecdsa_p256_key),
            ecdsa_p384_key: Arc::new(ecdsa_p384_key),
            ecdsa_p521_key: Arc::new(ecdsa_p521_key),
            openid_config,
            jwks_response,
            #[cfg(not(feature = "headless"))]
            cached_html,
        }
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
    let key = SigningKey::Rsa(state.rsa_key.clone());
    sign_with_key(state, key, KeySignAlgorithm::RS256, claims).await
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

    sign_with_key(
        state.clone(),
        SigningKey::Rsa(state.rsa_key.clone()),
        algorithm,
        claims,
    )
    .await
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
    let (key, algorithm) = match size.as_str() {
        "256" => (state.ecdsa_p256_key.clone(), KeySignAlgorithm::ES256),
        "384" => (state.ecdsa_p384_key.clone(), KeySignAlgorithm::ES384),
        "521" => (state.ecdsa_p521_key.clone(), KeySignAlgorithm::ES512),
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

    sign_with_key(state, SigningKey::Ecdsa(key), algorithm, claims).await
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
async fn sign_with_key(
    state: ServerState,
    key: SigningKey,
    algorithm: KeySignAlgorithm,
    mut claims: Value,
) -> Response {
    // Inject 'iss' claim if not present
    if let Some(claims_obj) = claims.as_object_mut() {
        if !claims_obj.contains_key("iss") {
            claims_obj.insert("iss".to_string(), json!(state.issuer.as_ref()));
        }
    }

    // Sign the JWT with the specified key and algorithm
    let result = match key {
        SigningKey::Rsa(rsa_key) => rsa_key.sign_jwt(&claims, &algorithm),
        SigningKey::Ecdsa(ecdsa_key) => ecdsa_key.sign_jwt(&claims, &algorithm),
    };

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
