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

#[derive(Clone)]
pub struct ServerState {
    pub issuer: Arc<str>,
    pub algorithms: Arc<[KeySignAlgorithm]>,
    keys: Arc<HashMap<KeySignAlgorithm, CryptoKey>>,
    openid_config: Arc<Value>,
    jwks_response: Arc<Value>,
    #[cfg(not(feature = "headless"))]
    cached_html: Arc<str>,
}

impl ServerState {
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

        let rsa_key_arc = Arc::new(rsa_key);
        let ecdsa_p256_arc = Arc::new(ecdsa_p256_key);
        let ecdsa_p384_arc = Arc::new(ecdsa_p384_key);
        let ecdsa_p521_arc = Arc::new(ecdsa_p521_key);

        let mut key_map: HashMap<KeySignAlgorithm, CryptoKey> = HashMap::new();

        for alg in [
            KeySignAlgorithm::RS256,
            KeySignAlgorithm::RS384,
            KeySignAlgorithm::RS512,
        ] {
            key_map.insert(alg, CryptoKey::Rsa(rsa_key_arc.clone()));
        }

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

        let openid_config = Arc::new(json!({
            "issuer": issuer.as_ref(),
            "jwks_uri": jwks_uri,
        }));

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

    fn get_key(&self, algorithm: &KeySignAlgorithm) -> Option<&CryptoKey> {
        self.keys.get(algorithm)
    }
}

#[derive(Serialize)]
pub struct SignResponse {
    token: String,
}

pub fn build_router(state: ServerState) -> Router {
    const MAX_BODY_SIZE: usize = 1024 * 1024;

    let router = Router::new()
        .route("/", get(root))
        .route("/.well-known/openid-configuration", get(openid_discovery))
        .route("/.well-known/jwks.json", get(jwks))
        .route("/sign", post(sign_default))
        .route("/sign/{algorithm}", post(sign_algorithm));

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

#[cfg(feature = "headless")]
async fn root() -> &'static str {
    "OK"
}

#[cfg(not(feature = "headless"))]
async fn root(State(state): State<ServerState>) -> Html<String> {
    Html(state.cached_html.to_string())
}

#[cfg(not(feature = "headless"))]
async fn serve_static(Path(path): Path<String>) -> Response {
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

/// JWT signing endpoint with explicit algorithm
///
/// Accepts arbitrary JSON claims and returns a signed JWT using the specified algorithm.
/// Uses standard JWT algorithm names (RS256, RS384, RS512, ES256, ES384, ES512).
///
/// # Path Parameters
/// * `algorithm` - JWT algorithm name (case-insensitive)
///
/// # Request Body
/// Any valid JSON object representing JWT claims
///
/// # Examples
/// ```text
/// POST /sign/RS256
/// {"sub": "user123", "aud": "my-app"}
///
/// POST /sign/ES384
/// {"sub": "user123", "aud": "my-app", "exp": 1735689600}
/// ```
async fn sign_algorithm(
    State(state): State<ServerState>,
    Path(algorithm_str): Path<String>,
    Json(claims): Json<Value>,
) -> Response {
    use std::str::FromStr;

    match KeySignAlgorithm::from_str(&algorithm_str) {
        Ok(algorithm) => sign_with_algorithm(state, algorithm, claims).await,
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": err
            })),
        )
            .into_response(),
    }
}

async fn sign_with_algorithm(
    state: ServerState,
    algorithm: KeySignAlgorithm,
    mut claims: Value,
) -> Response {
    if let Some(claims_obj) = claims.as_object_mut() {
        if !claims_obj.contains_key("iss") {
            claims_obj.insert("iss".to_string(), json!(state.issuer.as_ref()));
        }
    }

    let key = state
        .get_key(&algorithm)
        .expect("all algorithms should have keys");

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
