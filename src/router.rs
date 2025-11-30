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

/// Shared application state containing server configuration and cryptographic keys
#[derive(Clone)]
pub struct ServerState {
    /// Base issuer URL for OpenID configuration
    pub issuer: String,
    /// Supported JWT signing algorithms
    pub algorithms: Vec<KeySignAlgorithm>,
    /// RSA private key for signing operations
    pub key: Arc<RsaPrivateKey>,
}

impl ServerState {
    /// Create new server state with the provided configuration
    pub fn new(issuer: String, algorithms: Vec<KeySignAlgorithm>, key: RsaPrivateKey) -> Self {
        Self {
            issuer,
            algorithms,
            key: Arc::new(key),
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

    Router::new()
        .route("/", get(root))
        .route("/.well-known/openid-configuration", get(openid_discovery))
        .route("/.well-known/jwks.json", get(jwks))
        .route("/sign", post(sign_default))
        .route("/sign/{algorithm}", post(sign_with_algorithm))
        .layer(DefaultBodyLimit::max(MAX_BODY_SIZE))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|request: &Request<_>| {
                    tracing::info_span!(
                        "http_request",
                        method = %request.method(),
                        uri = %request.uri(),
                        version = ?request.version(),
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

/// Root endpoint returning service status
async fn root() -> &'static str {
    "JWKServe - JWT authentication testing helper"
}

/// OpenID Connect discovery endpoint
///
/// Returns OpenID Provider configuration metadata as defined in
/// OpenID Connect Discovery 1.0 specification
async fn openid_discovery(State(state): State<ServerState>) -> Json<Value> {
    let jwks_uri = format!("{}/.well-known/jwks.json", state.issuer);
    let authorization_endpoint = format!("{}/authorize", state.issuer);
    let token_endpoint = format!("{}/token", state.issuer);

    let supported_algs: Vec<&str> = state.algorithms.iter().map(|alg| alg.as_str()).collect();

    Json(json!({
        "issuer": state.issuer,
        "authorization_endpoint": authorization_endpoint,
        "token_endpoint": token_endpoint,
        "jwks_uri": jwks_uri,
        "response_types_supported": ["id_token", "token", "code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": supported_algs,
        "scopes_supported": ["openid", "profile", "email"],
        "claims_supported": ["sub", "iss", "aud", "exp", "iat", "name", "email"]
    }))
}

/// JSON Web Key Set (JWKS) endpoint
///
/// Returns the server's public keys in JWK format for JWT signature verification.
/// Implements RFC 7517 (JSON Web Key) and RFC 7518 (JSON Web Algorithms)
///
/// Generates one JWK per configured algorithm, allowing the same key to be used
/// with multiple signing algorithms (RS256, RS384, RS512).
async fn jwks(State(state): State<ServerState>) -> Json<Value> {
    let keys: Vec<Value> = state
        .algorithms
        .iter()
        .map(|alg| state.key.to_jwk(alg))
        .collect();

    Json(json!({
        "keys": keys
    }))
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
            claims_obj.insert("iss".to_string(), json!(state.issuer));
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
