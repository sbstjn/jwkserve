//! HTTP endpoint contract tests
//!
//! Validates that jwkserve's HTTP endpoints return correct status codes,
//! response structures, and handle various request patterns properly.

mod common;

use common::TestServer;
use jwkserve::KeySignAlgorithm;
use serde_json::json;

#[tokio::test]
async fn test_openid_discovery_endpoint() {
    let server = TestServer::spawn(2048, vec![KeySignAlgorithm::RS256])
        .await
        .expect("Failed to spawn server");

    let config = server
        .fetch_openid_config()
        .await
        .expect("Failed to fetch OpenID config");

    assert_eq!(
        config.get("issuer").expect("Missing issuer field"),
        &server.issuer
    );

    let jwks_uri = config
        .get("jwks_uri")
        .expect("Missing jwks_uri field")
        .as_str()
        .expect("jwks_uri is not a string");
    assert_eq!(jwks_uri, format!("{}/.well-known/jwks.json", server.issuer));
}

#[tokio::test]
async fn test_jwks_endpoint_structure() {
    let server = TestServer::spawn(
        2048,
        vec![
            KeySignAlgorithm::RS256,
            KeySignAlgorithm::RS384,
            KeySignAlgorithm::RS512,
        ],
    )
    .await
    .expect("Failed to spawn server");

    let jwks = server.fetch_jwks().await.expect("Failed to fetch JWKS");

    let keys = jwks
        .get("keys")
        .expect("Missing keys field")
        .as_array()
        .expect("Keys is not an array");
    assert_eq!(keys.len(), 3);

    for (i, alg) in ["RS256", "RS384", "RS512"].iter().enumerate() {
        let key = &keys[i];
        assert_eq!(key.get("kty").expect("Missing kty field"), "RSA");
        assert_eq!(key.get("use").expect("Missing use field"), "sig");
        assert_eq!(key.get("alg").expect("Missing alg field"), alg);
        assert!(key.get("kid").is_some(), "Missing kid field");
        assert!(key.get("n").is_some(), "Missing n field");
        assert!(key.get("e").is_some(), "Missing e field");
    }
}

#[tokio::test]
async fn test_sign_endpoint_default() {
    let server = TestServer::spawn(2048, vec![KeySignAlgorithm::RS256])
        .await
        .expect("Failed to spawn server");

    let claims = json!({"sub": "user", "exp": 9999999999_i64});

    // Test default /sign endpoint (should use RS256)
    let token = server
        .sign_jwt(claims, None)
        .await
        .expect("Failed to sign with default endpoint");

    // Verify it's RS256
    use common::decode_jwt_header;
    let header = decode_jwt_header(&token).expect("Failed to decode header");
    assert_eq!(header.alg, jsonwebtoken::Algorithm::RS256);
}

#[tokio::test]
async fn test_sign_endpoint_rsa_variants() {
    let server = TestServer::spawn(
        2048,
        vec![
            KeySignAlgorithm::RS256,
            KeySignAlgorithm::RS384,
            KeySignAlgorithm::RS512,
        ],
    )
    .await
    .expect("Failed to spawn server");

    let claims = json!({"sub": "user", "exp": 9999999999_i64});

    // Test /sign/rsa/256
    let token_256 = server
        .sign_jwt(claims.clone(), Some("RS256"))
        .await
        .expect("Failed to sign with RS256");
    assert!(!token_256.is_empty());

    // Test /sign/rsa/384
    let token_384 = server
        .sign_jwt(claims.clone(), Some("RS384"))
        .await
        .expect("Failed to sign with RS384");
    assert!(!token_384.is_empty());

    // Test /sign/rsa/512
    let token_512 = server
        .sign_jwt(claims, Some("RS512"))
        .await
        .expect("Failed to sign with RS512");
    assert!(!token_512.is_empty());
}

#[tokio::test]
async fn test_sign_endpoint_ecdsa_variants() {
    let server = TestServer::spawn(
        2048,
        vec![
            KeySignAlgorithm::ES256,
            KeySignAlgorithm::ES384,
            KeySignAlgorithm::ES512,
        ],
    )
    .await
    .expect("Failed to spawn server");

    let claims = json!({"sub": "user", "exp": 9999999999_i64});

    // Test /sign/ecdsa/256
    let token_256 = server
        .sign_jwt(claims.clone(), Some("ES256"))
        .await
        .expect("Failed to sign with ES256");
    assert!(!token_256.is_empty());

    // Test /sign/ecdsa/384
    let token_384 = server
        .sign_jwt(claims.clone(), Some("ES384"))
        .await
        .expect("Failed to sign with ES384");
    assert!(!token_384.is_empty());

    // Test /sign/ecdsa/521
    let token_512 = server
        .sign_jwt(claims, Some("ES512"))
        .await
        .expect("Failed to sign with ES512");
    assert!(!token_512.is_empty());
}

#[tokio::test]
async fn test_remote_jwks_verification() {
    let server = TestServer::spawn(2048, vec![KeySignAlgorithm::RS256])
        .await
        .expect("Failed to spawn server");

    let claims = json!({"sub": "remote-test", "exp": 9999999999_i64});

    let token = server
        .sign_jwt(claims, Some("RS256"))
        .await
        .expect("Failed to sign token");

    // Fetch JWKS from remote server endpoint
    let client = reqwest::Client::new();
    let jwks_url = format!("{}/.well-known/jwks.json", server.base_url);
    let remote_jwks: serde_json::Value = client
        .get(&jwks_url)
        .send()
        .await
        .expect("Failed to fetch remote JWKS")
        .json()
        .await
        .expect("Failed to parse remote JWKS");

    // Verify token using remote JWKS
    use common::verify_token;
    let verified_claims =
        verify_token(&token, &remote_jwks).expect("Failed to verify token using remote JWKS");

    assert_eq!(
        verified_claims.get("sub").expect("Missing sub claim"),
        "remote-test"
    );
}
