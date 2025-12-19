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

use crate::{key::RsaPrivateKey, KeySignAlgorithm};

#[cfg(not(feature = "headless"))]
use axum::{http::header, response::Html};

#[cfg(not(feature = "headless"))]
use include_dir::{include_dir, Dir};

/// Embedded website directory, bundled at compile time
#[cfg(not(feature = "headless"))]
static WEBSITE_DIR: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/website");

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
    /// RSA private key for signing operations
    pub key: Arc<RsaPrivateKey>,
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
    pub fn new(issuer: String, algorithms: Vec<KeySignAlgorithm>, key: RsaPrivateKey) -> Self {
        let issuer: Arc<str> = Arc::from(issuer.as_str());
        let jwks_uri = format!("{}/.well-known/jwks.json", issuer);

        // Pre-compute JWKS response
        let keys: Vec<Value> = algorithms.iter().map(|alg| key.to_jwk(alg)).collect();
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
            key: Arc::new(key),
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
        .route("/sign/{algorithm}", post(sign_with_algorithm));

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
    sign_with_alg(state, KeySignAlgorithm::RS256, claims).await
}

/// JWT signing endpoint with specified algorithm
///
/// Accepts arbitrary JSON claims and returns a signed JWT using the specified algorithm.
/// This is a developer tool - no validation is performed on claims.
///
/// # Path Parameters
/// * `algorithm` - The signing algorithm (RS256, RS384, or RS512)
///
/// # Request Body
/// Any valid JSON object representing JWT claims
///
/// # Example
/// ```text
/// POST /sign/RS384
/// {"sub": "user123", "aud": "my-app"}
/// ```
async fn sign_with_algorithm(
    State(state): State<ServerState>,
    Path(algorithm): Path<String>,
    Json(claims): Json<Value>,
) -> Response {
    let algorithm = match algorithm.parse::<KeySignAlgorithm>() {
        Ok(alg) => alg,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": e
                })),
            )
                .into_response();
        }
    };
    sign_with_alg(state, algorithm, claims).await
}

/// Internal signing logic shared by both endpoints
///
/// Note: This endpoint supports ALL RS algorithms (RS256, RS384, RS512) regardless
/// of server configuration. The --algorithm flag only controls which keys are
/// exposed in the JWKS endpoint, allowing you to test JWT validation scenarios
/// where the signing algorithm is not advertised in the key set.
///
/// If the claims do not include an 'iss' field, it will be automatically injected
/// from the server's issuer configuration.
async fn sign_with_alg(
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

    // Sign the JWT with any RS algorithm - server config only affects JWKS exposure
    match state.key.sign_jwt(&claims, &algorithm) {
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
