use poem::{
    get,
    middleware::{AddData, Tracing},
    post, EndpointExt, Result, Route,
};
use std::{io::Error, sync::Arc};

use crate::key::KeyStore;
use crate::routes::{response_index, response_jwks, response_openid, response_sign};

pub mod jwks;
pub mod key;
pub mod routes;

pub struct Router {
    pub poem: poem::middleware::TracingEndpoint<
        poem::middleware::AddDataEndpoint<Route, Arc<RouterState>>,
    >,
}

#[derive(Clone)]
pub struct RouterState {
    pub issuer: String,
    pub key_store: KeyStore,
}

impl Router {
    pub async fn with_state(state: RouterState) -> Result<Self, Error> {
        let state = Arc::new(state);

        let router = Route::new()
            .at("/", get(response_index))
            .at("/.well-known/jwks.json", get(response_jwks))
            .at("/.well-known/openid-configuration", get(response_openid))
            .at("/sign", post(response_sign))
            .with(AddData::new(state))
            .with(Tracing);

        Ok(Self { poem: router })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::KeyStore;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use rsa::pkcs8::EncodePublicKey;
    use tokio::sync::OnceCell;

    static SHARED_ROUTER: OnceCell<Router> = OnceCell::const_new();

    async fn get_shared_router() -> &'static Router {
        SHARED_ROUTER
            .get_or_init(|| async {
                let state = RouterState {
                    issuer: "https://test.example.com".to_string(),
                    key_store: KeyStore::new(),
                };
                Router::with_state(state).await.unwrap()
            })
            .await
    }

    // Simplified basic tests - reduced maintenance overhead
    #[test]
    fn test_router_state_basic() {
        let state = RouterState {
            issuer: "https://test.example.com".to_string(),
            key_store: KeyStore::new(),
        };
        assert_eq!(state.issuer, "https://test.example.com");
        assert!(!state.key_store.generate_kid().is_empty());

        // Test clone works
        let cloned = state.clone();
        assert_eq!(state.issuer, cloned.issuer);
    }

    #[tokio::test]
    async fn test_router_basic_functionality() {
        let router = get_shared_router().await;
        let client = poem::test::TestClient::new(&router.poem);

        let res = client.get("/").send().await;
        assert_eq!(res.0.status(), 200);

        let res = client.get("/.well-known/jwks.json").send().await;
        assert_eq!(res.0.status(), 200);

        let res = client.get("/.well-known/openid-configuration").send().await;
        assert_eq!(res.0.status(), 200);
    }

    #[tokio::test]
    async fn test_router_get_openid_configuration() {
        let router = get_shared_router().await;
        let client = poem::test::TestClient::new(&router.poem);

        let resp = client.get("/.well-known/openid-configuration").send().await;
        assert_eq!(resp.0.status(), 200);

        let body = resp.0.into_body().into_string().await;
        assert!(body.is_ok());

        let body = body.unwrap();
        assert!(!body.is_empty());

        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(json.is_object());

        assert_eq!(
            json.get("issuer").unwrap().as_str().unwrap(),
            "https://test.example.com"
        );

        assert_eq!(
            json.get("jwks_uri").unwrap().as_str().unwrap(),
            "https://test.example.com/.well-known/jwks.json"
        );
    }

    #[tokio::test]
    async fn test_router_get_jwks() {
        let router = get_shared_router().await;
        let client = poem::test::TestClient::new(&router.poem);

        let resp = client.get("/.well-known/jwks.json").send().await;
        assert_eq!(resp.0.status(), 200);

        let body = resp.0.into_body().into_string().await;
        assert!(body.is_ok());

        let body = body.unwrap();
        assert!(!body.is_empty());

        let json: serde_json::Value = serde_json::from_str(&body).unwrap();

        assert!(json.is_object());
        assert!(json.get("keys").is_some());
        assert_eq!(json.get("keys").unwrap().as_array().unwrap().len(), 1);

        let key = json
            .get("keys")
            .unwrap()
            .as_array()
            .unwrap()
            .first()
            .unwrap();

        assert_eq!(key.get("alg").unwrap().as_str().unwrap(), "RS256");
        assert_eq!(key.get("use").unwrap().as_str().unwrap(), "sig");
    }

    #[tokio::test]
    async fn test_router_sign() {
        let router = get_shared_router().await;
        let client = poem::test::TestClient::new(&router.poem);

        let claims = serde_json::json!({
            "aud": "my-app",
            "exp": 1735689600,
            "iat": 1704067200,
            "iss": "wrong-issuer",
            "nbf": 1704067200,
            "sub": "user-12345"
        });

        let resp = client
            .post("/sign")
            .header("Content-Type", "application/json")
            .body(serde_json::to_string(&claims).unwrap())
            .send()
            .await;

        assert_eq!(resp.0.status(), 200);

        let body = resp.0.into_body().into_string().await;
        assert!(body.is_ok());

        let body = body.unwrap();
        assert!(!body.is_empty());

        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(json.is_object());
        assert!(json.get("token").is_some());

        let token = json.get("token").unwrap().as_str().unwrap();
        assert!(!token.is_empty());

        // Verify the token has the correct structure (header.payload.signature)
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);

        // Decode and verify the payload contains the correct issuer (overridden by the server)
        let payload = parts[1];
        let decoded_payload = URL_SAFE_NO_PAD
            .decode(payload)
            .expect("Should be valid base64");

        // The issuer should be overridden to the server's issuer
        let payload_json: serde_json::Value = serde_json::from_slice(&decoded_payload).unwrap();
        assert_eq!(
            payload_json.get("iss").unwrap().as_str().unwrap(),
            "https://test.example.com"
        );
    }

    #[tokio::test]
    async fn test_router_sign_full_jwks_validation() {
        let router = get_shared_router().await;
        let client = poem::test::TestClient::new(&router.poem);

        // Step 1: Create a signed token via the /sign endpoint
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let claims = serde_json::json!({
            "aud": "my-app",
            "exp": now + 3600, // 1 hour from now
            "iat": now,
            "iss": "wrong-issuer", // This will be overridden by the server
            "nbf": now,
            "sub": "user-12345"
        });

        let sign_resp = client
            .post("/sign")
            .header("Content-Type", "application/json")
            .body(serde_json::to_string(&claims).unwrap())
            .send()
            .await;

        assert_eq!(sign_resp.0.status(), 200);

        let sign_body = sign_resp.0.into_body().into_string().await.unwrap();
        let sign_json: serde_json::Value = serde_json::from_str(&sign_body).unwrap();
        let token = sign_json.get("token").unwrap().as_str().unwrap();

        // Step 2: Fetch the JWKS from the /.well-known/jwks.json endpoint
        let jwks_resp = client.get("/.well-known/jwks.json").send().await;
        assert_eq!(jwks_resp.0.status(), 200);

        let jwks_body = jwks_resp.0.into_body().into_string().await.unwrap();
        let jwks_json: serde_json::Value = serde_json::from_str(&jwks_body).unwrap();

        // Step 3: Extract the public key from JWKS
        let keys = jwks_json.get("keys").unwrap().as_array().unwrap();
        assert_eq!(keys.len(), 1);

        let key = &keys[0];
        let kid = key.get("kid").unwrap().as_str().unwrap();
        let n = key.get("n").unwrap().as_str().unwrap();
        let e = key.get("e").unwrap().as_str().unwrap();

        // Step 4: Build RSA public key from JWKS components
        let n_bytes = URL_SAFE_NO_PAD.decode(n).expect("Should be valid base64");
        let e_bytes = URL_SAFE_NO_PAD.decode(e).expect("Should be valid base64");

        let n_bigint = rsa::BigUint::from_bytes_be(&n_bytes);
        let e_bigint = rsa::BigUint::from_bytes_be(&e_bytes);

        let public_key =
            rsa::RsaPublicKey::new(n_bigint, e_bigint).expect("Should create valid public key");

        // Step 5: Convert to PEM format for jsonwebtoken validation
        let public_key_pem = public_key
            .to_public_key_pem(rsa::pkcs1::LineEnding::LF)
            .expect("Should convert to PEM");

        // Step 6: Validate the token using jsonwebtoken
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.set_audience(&["my-app"]);
        validation.validate_exp = true;
        validation.validate_nbf = true;

        let token_data = jsonwebtoken::decode::<serde_json::Value>(
            token,
            &jsonwebtoken::DecodingKey::from_rsa_pem(public_key_pem.as_bytes()).unwrap(),
            &validation,
        );

        if let Err(e) = &token_data {
            println!("Token validation error: {:?}", e);
            println!("Public key PEM: {}", public_key_pem);
            println!("Token: {}", token);
        }

        assert!(token_data.is_ok());
        let token_data = token_data.unwrap();

        // Step 7: Verify token claims
        let token_claims = token_data.claims;
        assert_eq!(
            token_claims.get("iss").unwrap().as_str().unwrap(),
            "https://test.example.com"
        );

        // Step 8: Verify token header contains correct kid
        assert_eq!(token_data.header.kid, Some(kid.to_string()));
    }
}
