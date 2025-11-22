use std::env::consts;

use crate::RouterState;
use jsonwebtoken::{encode, Algorithm, Header};
use poem::{
    handler,
    web::{Data, Json},
    Request,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GenericClaims {
    #[serde(flatten)]
    pub data: Map<String, Value>,
}

impl GenericClaims {
    pub fn has_issuer(&self) -> bool {
        self.data.contains_key("iss")
    }

    pub fn set_issuer(&mut self, issuer: String) {
        self.data.insert("iss".to_string(), Value::String(issuer));
    }
}

pub fn get_hostname_and_scheme(req: &Request) -> String {
    let host = req
        .headers()
        .get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    let scheme = req
        .headers()
        .get("x-forwarded-proto")
        .and_then(|h| h.to_str().ok())
        .or_else(|| {
            req.headers()
                .get("x-forwarded-scheme")
                .and_then(|h| h.to_str().ok())
        })
        .unwrap_or("http");

    format!("{}://{}", scheme, host)
}

#[handler]
pub fn response_index() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "arch": consts::ARCH,
        "name": "jwkserve",
        "os": consts::OS,
        "status": "running",
        "version": env!("CARGO_PKG_VERSION")
    }))
}

#[handler]
pub fn response_jwks(state: Data<&RouterState>) -> Json<serde_json::Value> {
    let signing_key = serde_json::json!({
        "kid": state.key.generate_kid(),
        "kty": "RSA",
        "alg": "RS256",
        "use": "sig",
        "n": state.key.generate_n(),
        "e": state.key.generate_e(),
    });

    Json(serde_json::json!({
        "keys": vec![signing_key],
    }))
}

#[handler]
pub fn response_openid(req: &Request) -> Json<serde_json::Value> {
    let issuer = get_hostname_and_scheme(req);

    Json(serde_json::json!({
        "issuer": issuer,
        "jwks_uri": format!("{}/.well-known/jwks.json", issuer)
    }))
}

#[handler]
pub fn response_sign(
    state: Data<&RouterState>,
    req: Json<GenericClaims>,
    request: &Request,
) -> Json<serde_json::Value> {
    let mut claims = req.0;

    if !claims.has_issuer() {
        claims.set_issuer(get_hostname_and_scheme(request));
    }

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(state.key.generate_kid().to_string());

    let token = encode(&header, &claims.data, state.key.encoding_key())
        .expect("Failed to encode JWT");

    Json(serde_json::json!({ "token": token }))
}
