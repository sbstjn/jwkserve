use axum::{
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, Request, StatusCode},
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use serde::Serialize;
use serde_json::{json, Value};
use std::{fmt, sync::Arc, time::Duration};
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

#[derive(Clone, Debug)]
pub enum IssuerMode {
    Static(Arc<str>),
    FromHost {
        scheme: Arc<str>,
        trust_forwarded_headers: bool,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IssuerError;

impl IssuerError {
    const MESSAGE: &'static str = "unable to derive issuer from request host";
}

impl fmt::Display for IssuerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(Self::MESSAGE)
    }
}

impl std::error::Error for IssuerError {}

impl IntoResponse for IssuerError {
    fn into_response(self) -> Response {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": Self::MESSAGE,
            })),
        )
            .into_response()
    }
}

#[derive(Clone)]
pub struct ServerState {
    pub issuer_mode: IssuerMode,
    pub algorithms: Arc<[KeySignAlgorithm]>,
    keys: Arc<HashMap<KeySignAlgorithm, CryptoKey>>,
    static_openid_config: Option<Arc<Value>>,
    jwks_response: Arc<Value>,
    #[cfg(not(feature = "headless"))]
    cached_html: Arc<str>,
}

impl ServerState {
    pub fn new(
        issuer_mode: IssuerMode,
        algorithms: Vec<KeySignAlgorithm>,
        rsa_key: RsaPrivateKey,
        ecdsa_p256_key: EcdsaPrivateKey,
        ecdsa_p384_key: EcdsaPrivateKey,
        ecdsa_p521_key: EcdsaPrivateKey,
    ) -> Self {
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

        let jwk_keys: Vec<Value> = algorithms
            .iter()
            .map(|alg| match alg {
                KeySignAlgorithm::RS256 | KeySignAlgorithm::RS384 | KeySignAlgorithm::RS512 => {
                    rsa_key_arc.to_jwk(alg)
                }
                KeySignAlgorithm::ES256 => ecdsa_p256_arc.to_jwk(alg),
                KeySignAlgorithm::ES384 => ecdsa_p384_arc.to_jwk(alg),
                KeySignAlgorithm::ES512 => ecdsa_p521_arc.to_jwk(alg),
            })
            .collect();

        let jwks_response = Arc::new(json!({
            "keys": jwk_keys
        }));

        let static_openid_config = match &issuer_mode {
            IssuerMode::Static(issuer) => {
                let jwks_uri = format!("{}/.well-known/jwks.json", issuer);
                Some(Arc::new(json!({
                    "issuer": issuer.as_ref(),
                    "jwks_uri": jwks_uri,
                })))
            }
            IssuerMode::FromHost { .. } => None,
        };

        #[cfg(not(feature = "headless"))]
        let cached_html = {
            const TEMPLATE: &str = include_str!("../website/index.html");
            const VERSION: &str = env!("CARGO_PKG_VERSION");
            let (issuer_label, issuer_is_dynamic) = match &issuer_mode {
                IssuerMode::Static(issuer) => (issuer.to_string(), "false"),
                IssuerMode::FromHost { scheme, .. } => (format!("{scheme}://{{host}}"), "true"),
            };
            let html = TEMPLATE
                .replace("{{ISSUER}}", &issuer_label)
                .replace("{{ISSUER_IS_DYNAMIC}}", issuer_is_dynamic)
                .replace("{{VERSION}}", VERSION);
            let html = if std::env::var("JWKSERVE_ENABLE_TRACKING").as_deref() == Ok("true") {
                const TRACKING_SCRIPT: &str = r#"    <script defer src="https://track.heft.io/tracker.js" data-site-id="d4308e95-5ecf-46a9-8602-fae51ade4ba4"></script>
"#;
                html.replacen("</body>", &format!("{}</body>", TRACKING_SCRIPT), 1)
            } else {
                html
            };
            Arc::from(html.as_str())
        };

        Self {
            issuer_mode,
            algorithms: Arc::from(algorithms),
            keys: Arc::new(key_map),
            static_openid_config,
            jwks_response,
            #[cfg(not(feature = "headless"))]
            cached_html,
        }
    }

    fn get_key(&self, algorithm: &KeySignAlgorithm) -> Option<&CryptoKey> {
        self.keys.get(algorithm)
    }

    pub fn issuer_for_headers(&self, headers: &HeaderMap) -> Result<String, IssuerError> {
        match &self.issuer_mode {
            IssuerMode::Static(issuer) => Ok(issuer.to_string()),
            IssuerMode::FromHost {
                scheme,
                trust_forwarded_headers,
            } => {
                let host = if *trust_forwarded_headers {
                    match Self::first_header_value(headers, "x-forwarded-host")? {
                        Some(host) => host,
                        None => Self::first_header_value(headers, "host")?.ok_or(IssuerError)?,
                    }
                } else {
                    Self::first_header_value(headers, "host")?.ok_or(IssuerError)?
                };

                let scheme = if *trust_forwarded_headers {
                    match Self::first_header_value(headers, "x-forwarded-proto")? {
                        Some(proto) => proto,
                        None => scheme.to_string(),
                    }
                } else {
                    scheme.to_string()
                };

                let host = Self::validate_host(&host)?;
                let scheme = Self::validate_scheme(&scheme)?;

                Ok(format!("{scheme}://{host}"))
            }
        }
    }

    pub fn openid_config_for_headers(&self, headers: &HeaderMap) -> Result<Value, IssuerError> {
        if let Some(config) = &self.static_openid_config {
            return Ok((**config).clone());
        }

        let issuer = self.issuer_for_headers(headers)?;

        Ok(json!({
            "issuer": issuer,
            "jwks_uri": format!("{issuer}/.well-known/jwks.json"),
        }))
    }

    fn first_header_value(headers: &HeaderMap, name: &str) -> Result<Option<String>, IssuerError> {
        let Some(value) = headers.get(name) else {
            return Ok(None);
        };

        let value = value.to_str().map_err(|_| IssuerError)?;
        let first = value.split(',').next().unwrap_or_default().trim();

        Ok(Some(first.to_string()))
    }

    fn validate_scheme(scheme: &str) -> Result<String, IssuerError> {
        let scheme = scheme.trim().to_ascii_lowercase();

        match scheme.as_str() {
            "http" | "https" => Ok(scheme),
            _ => Err(IssuerError),
        }
    }

    fn validate_host(host: &str) -> Result<String, IssuerError> {
        let host = host.trim();

        if host.is_empty()
            || host
                .chars()
                .any(|ch| matches!(ch, '/' | '\\' | '?' | '#' | '\r' | '\n'))
        {
            return Err(IssuerError);
        }

        Ok(host.to_string())
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
/// Response is pre-computed at startup for static issuers.
async fn openid_discovery(State(state): State<ServerState>, headers: HeaderMap) -> Response {
    match state.openid_config_for_headers(&headers) {
        Ok(config) => Json(config).into_response(),
        Err(err) => err.into_response(),
    }
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
async fn sign_default(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Json(claims): Json<Value>,
) -> Response {
    let issuer = match state.issuer_for_headers(&headers) {
        Ok(issuer) => issuer,
        Err(err) => return err.into_response(),
    };

    sign_with_algorithm(state, KeySignAlgorithm::RS256, claims, issuer).await
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
    headers: HeaderMap,
    Path(algorithm_str): Path<String>,
    Json(claims): Json<Value>,
) -> Response {
    use std::str::FromStr;

    match KeySignAlgorithm::from_str(&algorithm_str) {
        Ok(algorithm) => {
            let issuer = match state.issuer_for_headers(&headers) {
                Ok(issuer) => issuer,
                Err(err) => return err.into_response(),
            };

            sign_with_algorithm(state, algorithm, claims, issuer).await
        }
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
    issuer: String,
) -> Response {
    if let Some(claims_obj) = claims.as_object_mut() {
        if !claims_obj.contains_key("iss") {
            claims_obj.insert("iss".to_string(), json!(issuer));
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn fixture_path(name: &str) -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join(name)
    }

    fn dynamic_state(scheme: &str, trust_forwarded_headers: bool) -> ServerState {
        let rsa_fixture = fixture_path("rsa_2048.pem");
        let ecdsa_p256_fixture = fixture_path("ecdsa_p256.pem");
        let ecdsa_p384_fixture = fixture_path("ecdsa_p384.pem");
        let ecdsa_p521_fixture = fixture_path("ecdsa_p521.pem");
        let rsa_key = RsaPrivateKey::from_pem_file(&rsa_fixture).unwrap();
        let ecdsa_p256_key = EcdsaPrivateKey::from_pem_file(&ecdsa_p256_fixture).unwrap();
        let ecdsa_p384_key = EcdsaPrivateKey::from_pem_file(&ecdsa_p384_fixture).unwrap();
        let ecdsa_p521_key = EcdsaPrivateKey::from_pem_file(&ecdsa_p521_fixture).unwrap();

        ServerState::new(
            IssuerMode::FromHost {
                scheme: Arc::from(scheme),
                trust_forwarded_headers,
            },
            vec![KeySignAlgorithm::RS256, KeySignAlgorithm::ES256],
            rsa_key,
            ecdsa_p256_key,
            ecdsa_p384_key,
            ecdsa_p521_key,
        )
    }

    #[test]
    fn test_dynamic_issuer_requires_host_header() {
        let state = dynamic_state("http", false);
        let headers = HeaderMap::new();

        assert_eq!(state.issuer_for_headers(&headers), Err(IssuerError));
    }

    #[test]
    fn test_dynamic_issuer_rejects_invalid_host() {
        let state = dynamic_state("http", false);
        let mut headers = HeaderMap::new();
        headers.insert("host", "tenant-a.test/path".parse().unwrap());

        assert_eq!(state.issuer_for_headers(&headers), Err(IssuerError));
    }

    #[test]
    fn test_dynamic_issuer_uses_forwarded_header_first_values() {
        let state = dynamic_state("http", true);
        let mut headers = HeaderMap::new();
        headers.insert("host", "internal.local".parse().unwrap());
        headers.insert(
            "x-forwarded-host",
            "tenant-a.test, proxy.local".parse().unwrap(),
        );
        headers.insert("x-forwarded-proto", "https, http".parse().unwrap());

        assert_eq!(
            state.issuer_for_headers(&headers).unwrap(),
            "https://tenant-a.test"
        );
    }

    #[test]
    fn test_dynamic_issuer_falls_back_to_configured_scheme() {
        let state = dynamic_state("https", true);
        let mut headers = HeaderMap::new();
        headers.insert("host", "tenant-c.test".parse().unwrap());

        assert_eq!(
            state.issuer_for_headers(&headers).unwrap(),
            "https://tenant-c.test"
        );
    }

    #[test]
    fn test_static_openid_config_is_cached() {
        let rsa_fixture = fixture_path("rsa_2048.pem");
        let ecdsa_p256_fixture = fixture_path("ecdsa_p256.pem");
        let ecdsa_p384_fixture = fixture_path("ecdsa_p384.pem");
        let ecdsa_p521_fixture = fixture_path("ecdsa_p521.pem");
        let rsa_key = RsaPrivateKey::from_pem_file(&rsa_fixture).unwrap();
        let ecdsa_p256_key = EcdsaPrivateKey::from_pem_file(&ecdsa_p256_fixture).unwrap();
        let ecdsa_p384_key = EcdsaPrivateKey::from_pem_file(&ecdsa_p384_fixture).unwrap();
        let ecdsa_p521_key = EcdsaPrivateKey::from_pem_file(&ecdsa_p521_fixture).unwrap();
        let state = ServerState::new(
            IssuerMode::Static(Arc::from("http://localhost:3000")),
            vec![KeySignAlgorithm::RS256, KeySignAlgorithm::ES256],
            rsa_key,
            ecdsa_p256_key,
            ecdsa_p384_key,
            ecdsa_p521_key,
        );

        let config = state.openid_config_for_headers(&HeaderMap::new()).unwrap();
        assert_eq!(config.get("issuer").unwrap(), "http://localhost:3000");
        assert_eq!(
            config.get("jwks_uri").unwrap(),
            "http://localhost:3000/.well-known/jwks.json"
        );
    }

    #[cfg(not(feature = "headless"))]
    #[test]
    fn test_dynamic_html_uses_runtime_origin_and_omits_default_iss() {
        let state = dynamic_state("https", true);

        assert!(state
            .cached_html
            .contains("const IS_DYNAMIC_ISSUER = true;"));
        assert!(state
            .cached_html
            .contains("const endpoint = algorithm ? `/sign/${algorithm}` : '/sign';"));
        assert!(state.cached_html.contains("if (!IS_DYNAMIC_ISSUER) {"));
        assert!(!state.cached_html.contains("\"iss\": \"https://{host}\""));
    }

    #[cfg(not(feature = "headless"))]
    #[test]
    fn test_static_html_keeps_static_issuer_defaults() {
        let rsa_fixture = fixture_path("rsa_2048.pem");
        let ecdsa_p256_fixture = fixture_path("ecdsa_p256.pem");
        let ecdsa_p384_fixture = fixture_path("ecdsa_p384.pem");
        let ecdsa_p521_fixture = fixture_path("ecdsa_p521.pem");
        let rsa_key = RsaPrivateKey::from_pem_file(&rsa_fixture).unwrap();
        let ecdsa_p256_key = EcdsaPrivateKey::from_pem_file(&ecdsa_p256_fixture).unwrap();
        let ecdsa_p384_key = EcdsaPrivateKey::from_pem_file(&ecdsa_p384_fixture).unwrap();
        let ecdsa_p521_key = EcdsaPrivateKey::from_pem_file(&ecdsa_p521_fixture).unwrap();
        let state = ServerState::new(
            IssuerMode::Static(Arc::from("https://issuer.example")),
            vec![KeySignAlgorithm::RS256, KeySignAlgorithm::ES256],
            rsa_key,
            ecdsa_p256_key,
            ecdsa_p384_key,
            ecdsa_p521_key,
        );

        assert!(state
            .cached_html
            .contains("const IS_DYNAMIC_ISSUER = false;"));
        assert!(state
            .cached_html
            .contains("const STATIC_ISSUER = 'https://issuer.example';"));
        assert!(state
            .cached_html
            .contains("initialClaims.iss = STATIC_ISSUER;"));
    }
}
