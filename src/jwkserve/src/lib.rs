use crate::handler::{response_index, response_jwks, response_openid, response_sign};
use crate::key::Key;
use poem::{
    get,
    middleware::{AddData, Tracing},
    post, EndpointExt, Route,
};

pub mod handler;
pub mod key;

pub struct Router {
    pub poem:
        poem::middleware::TracingEndpoint<poem::middleware::AddDataEndpoint<Route, RouterState>>,
}

#[derive(Clone)]
pub struct RouterState {
    pub issuer: String,
    pub key: Key,
}

impl Router {
    pub fn with_state(state: RouterState) -> Self {
        let router = Route::new()
            .at("/", get(response_index))
            .at("/.well-known/jwks.json", get(response_jwks))
            .at("/.well-known/openid-configuration", get(response_openid))
            .at("/protocol/openid-connect/certs", get(response_jwks))
            .at("/sign", post(response_sign))
            .with(AddData::new(state))
            .with(Tracing);

        Self { poem: router }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test endpoints
    #[tokio::test]
    async fn test_endpoints() {
        let router = Router::with_state(RouterState {
            issuer: "https://test.example.com".to_string(),
            key: crate::key::Key::new(),
        });

        let client = poem::test::TestClient::new(&router.poem);

        // index endpoint returns system info
        let resp = client.get("/").send().await;
        assert_eq!(resp.0.status(), 200);
        let json: serde_json::Value = resp.0.into_body().into_json().await.unwrap();
        assert_eq!(json["name"], "jwkserve");
        assert_eq!(json["status"], "running");

        // jwks endpoint returns key
        let resp = client.get("/.well-known/jwks.json").send().await;
        assert_eq!(resp.0.status(), 200);
        let json: serde_json::Value = resp.0.into_body().into_json().await.unwrap();
        assert_eq!(json["keys"].as_array().unwrap().len(), 1);
        assert_eq!(json["keys"][0]["kty"], "RSA");
        assert_eq!(json["keys"][0]["alg"], "RS256");

        // openid endpoint returns config
        let resp = client.get("/.well-known/openid-configuration").send().await;
        assert_eq!(resp.0.status(), 200);
        let json: serde_json::Value = resp.0.into_body().into_json().await.unwrap();
        assert_eq!(json["issuer"], "https://test.example.com");
        assert_eq!(
            json["jwks_uri"],
            "https://test.example.com/.well-known/jwks.json"
        );

        // sign endpoint works with empty claims
        let resp = client
            .post("/sign")
            .header("Content-Type", "application/json")
            .body("{}")
            .send()
            .await;
        assert_eq!(resp.0.status(), 200);
        let json: serde_json::Value = resp.0.into_body().into_json().await.unwrap();
        assert!(json["token"].is_string());
    }
}
