use std::env::consts;

use crate::RouterState;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use poem::{
    handler,
    web::{Data, Json},
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
pub fn response_openid(state: Data<&RouterState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "issuer": state.issuer,
        "jwks_uri": format!("{}/.well-known/jwks.json", state.issuer)
    }))
}

#[handler]
pub fn response_sign(
    state: Data<&RouterState>,
    req: Json<GenericClaims>,
) -> Json<serde_json::Value> {
    let mut claims = req.0;

    if !claims.has_issuer() {
        claims.set_issuer(state.issuer.clone());
    }

    let encoding_key = EncodingKey::from_rsa_pem(state.key.to_pkcs8_pem().as_bytes())
        .expect("Failed to create encoding key");

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(state.key.generate_kid());

    let token = encode(&header, &claims.data, &encoding_key).expect("Failed to encode JWT");

    Json(serde_json::json!({ "token": token }))
}
