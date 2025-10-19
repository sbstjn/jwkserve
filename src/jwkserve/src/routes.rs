use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use poem::{
    handler,
    web::{Data, Json},
};
use serde::{Deserialize, Serialize};
use std::env::consts;

use crate::{jwks::JsonWebKeySet, RouterState};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ResponseIndex {
    pub arch: String,
    pub name: String,
    pub os: String,
    pub status: String,
    pub version: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ResponseOpenIDConfiguration {
    pub issuer: String,
    pub jwks_uri: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub iss: String,
    pub nbf: i64,
    pub sub: String,
}

#[handler]
pub fn response_sign(
    state: Data<&std::sync::Arc<RouterState>>,
    req: Json<Claims>,
) -> poem::Result<poem::web::Json<serde_json::Value>> {
    let mut claims = req.0;
    claims.iss = state.issuer.clone();

    let encoding_key = EncodingKey::from_rsa_pem(state.key_store.to_pkcs8_pem().as_bytes())
        .expect("Failed to create encoding key");

    let mut header = Header::new(Algorithm::RS256);
    let kid = state.key_store.generate_kid();
    header.kid = Some(kid);

    let token = encode(&header, &claims, &encoding_key).expect("Failed to encode JWT");

    Ok(poem::web::Json(serde_json::json!({ "token": token })))
}

#[handler]
pub fn response_index() -> Json<ResponseIndex> {
    Json(ResponseIndex {
        arch: consts::ARCH.to_string(),
        name: "jwkserve".to_string(),
        os: consts::OS.to_string(),
        status: "running".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

#[handler]
pub fn response_jwks(
    state: Data<&std::sync::Arc<RouterState>>,
) -> poem::Result<Json<JsonWebKeySet>> {
    Ok(Json(JsonWebKeySet::from_key_store(&state.key_store)))
}

#[handler]
pub fn response_openid(
    state: Data<&std::sync::Arc<RouterState>>,
) -> Json<ResponseOpenIDConfiguration> {
    Json(ResponseOpenIDConfiguration {
        issuer: state.issuer.clone(),
        jwks_uri: format!("{}/.well-known/jwks.json", state.issuer),
    })
}
