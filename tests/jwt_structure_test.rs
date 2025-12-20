//! JWT token structure validation tests
//!
//! Validates that JWTs produced by jwkserve have correct structure:
//! proper headers, claim handling, and kid-to-JWKS consistency.

mod common;

use common::{decode_jwt_header, verify_token, TestServer};
use jwkserve::KeySignAlgorithm;
use serde_json::json;

#[tokio::test]
async fn test_jwt_header_kid_present() {
    let server = TestServer::spawn(2048, vec![KeySignAlgorithm::RS256])
        .await
        .expect("Failed to spawn server");

    let jwks = server.fetch_jwks().await.expect("Failed to fetch JWKS");
    let keys = jwks.get("keys").unwrap().as_array().unwrap();
    let jwks_kid = keys[0]
        .get("kid")
        .expect("JWKS key missing kid")
        .as_str()
        .unwrap();

    // Sign a token
    let claims = json!({"sub": "test", "exp": 9999999999_i64});
    let token = server
        .sign_jwt(claims, None)
        .await
        .expect("Failed to sign token");

    // Decode JWT header
    let header = decode_jwt_header(&token).expect("Failed to decode header");
    let jwt_kid = header.kid.expect("JWT header missing kid field");

    // Assert kid matches exactly
    assert_eq!(
        jwt_kid, jwks_kid,
        "JWT header kid must match JWKS kid exactly"
    );

    // Verify token can be validated
    verify_token(&token, &jwks).expect("Failed to verify token with matching kid");
}

#[tokio::test]
async fn test_jwt_header_algorithm_matches() {
    let server = TestServer::spawn(2048, vec![KeySignAlgorithm::RS384])
        .await
        .expect("Failed to spawn server");

    let claims = json!({"sub": "test", "exp": 9999999999_i64});
    let token = server
        .sign_jwt(claims, Some("RS384"))
        .await
        .expect("Failed to sign token");

    let header = decode_jwt_header(&token).expect("Failed to decode header");
    assert_eq!(
        header.alg,
        jsonwebtoken::Algorithm::RS384,
        "JWT header alg must match requested algorithm"
    );
}

#[tokio::test]
async fn test_issuer_auto_injection() {
    let server = TestServer::spawn(2048, vec![KeySignAlgorithm::RS256])
        .await
        .expect("Failed to spawn server");

    let claims_without_iss = json!({"sub": "user", "exp": 9999999999_i64});

    let token = server
        .sign_jwt(claims_without_iss, None)
        .await
        .expect("Failed to sign");

    let jwks = server.fetch_jwks().await.expect("Failed to fetch JWKS");
    let verified_claims = verify_token(&token, &jwks).expect("Failed to verify");

    assert_eq!(
        verified_claims
            .get("iss")
            .expect("Missing iss claim")
            .as_str()
            .expect("Issuer is not a string"),
        server.issuer,
        "Issuer should be auto-injected"
    );
}

#[tokio::test]
async fn test_issuer_preservation() {
    let server = TestServer::spawn(2048, vec![KeySignAlgorithm::RS256])
        .await
        .expect("Failed to spawn server");

    let custom_issuer = "https://custom-issuer.com";
    let claims_with_iss = json!({
        "sub": "user",
        "iss": custom_issuer,
        "exp": 9999999999_i64
    });

    let token = server
        .sign_jwt(claims_with_iss, None)
        .await
        .expect("Failed to sign");

    let jwks = server.fetch_jwks().await.expect("Failed to fetch JWKS");
    let verified_claims = verify_token(&token, &jwks).expect("Failed to verify");

    assert_eq!(
        verified_claims
            .get("iss")
            .expect("Missing iss claim")
            .as_str()
            .expect("Issuer is not a string"),
        custom_issuer,
        "Custom issuer should be preserved"
    );
}

#[tokio::test]
async fn test_custom_claims_preserved() {
    let server = TestServer::spawn(2048, vec![KeySignAlgorithm::RS256])
        .await
        .expect("Failed to spawn server");

    let claims = json!({
        "sub": "user123",
        "exp": 9999999999_i64,
        "custom_claim": "test-value",
        "roles": ["admin", "user"],
        "nested": {
            "field": "value"
        }
    });

    let token = server
        .sign_jwt(claims.clone(), None)
        .await
        .expect("Failed to sign");

    let jwks = server.fetch_jwks().await.expect("Failed to fetch JWKS");
    let verified_claims = verify_token(&token, &jwks).expect("Failed to verify");

    assert_eq!(
        verified_claims
            .get("custom_claim")
            .expect("Missing custom_claim"),
        "test-value"
    );
    assert_eq!(
        verified_claims
            .get("roles")
            .expect("Missing roles claim")
            .as_array()
            .expect("Roles is not an array")
            .len(),
        2
    );
    assert_eq!(
        verified_claims
            .get("nested")
            .expect("Missing nested claim")
            .get("field")
            .expect("Missing nested.field"),
        "value"
    );
}
