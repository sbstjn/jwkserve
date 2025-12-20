//! Error handling and validation tests
//!
//! Validates that jwkserve properly handles error conditions:
//! invalid inputs, oversized payloads, malformed requests, and algorithm mismatches.

mod common;

use common::{verify_token, TestServer};
use jwkserve::KeySignAlgorithm;
use serde_json::json;

#[tokio::test]
async fn test_oversized_payload_rejected() {
    let server = TestServer::spawn(2048, vec![KeySignAlgorithm::RS256])
        .await
        .expect("Failed to spawn server");

    // Create a payload larger than 1MB limit
    let large_string = "x".repeat(2 * 1024 * 1024); // 2MB
    let claims = json!({"sub": "user", "data": large_string, "exp": 9999999999_i64});

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/sign", server.base_url))
        .json(&claims)
        .send()
        .await
        .expect("Failed to send request");

    // Should be rejected due to body size limit
    assert_eq!(
        response.status(),
        reqwest::StatusCode::PAYLOAD_TOO_LARGE,
        "Should return 413 for oversized payload"
    );
}

#[tokio::test]
async fn test_malformed_json_rejected() {
    let server = TestServer::spawn(2048, vec![KeySignAlgorithm::RS256])
        .await
        .expect("Failed to spawn server");

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/sign", server.base_url))
        .header("content-type", "application/json")
        .body("{invalid json")
        .send()
        .await
        .expect("Failed to send request");

    // Should be rejected due to invalid JSON
    assert_eq!(
        response.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "Should return 400 for malformed JSON"
    );
}

#[tokio::test]
async fn test_invalid_algorithm_rejected() {
    let server = TestServer::spawn(2048, vec![KeySignAlgorithm::RS256])
        .await
        .expect("Failed to spawn server");

    let claims = json!({"sub": "user", "exp": 9999999999_i64});
    let client = reqwest::Client::new();

    // Try to sign with invalid algorithm
    let response = client
        .post(format!("{}/sign/INVALID", server.base_url))
        .json(&claims)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "Should return 400 for invalid algorithm"
    );

    let error_response: serde_json::Value = response.json().await.expect("Failed to parse error");
    assert!(
        error_response
            .get("error")
            .and_then(|e| e.as_str())
            .unwrap_or("")
            .contains("is not supported"),
        "Error message should mention unsupported algorithm"
    );
}

#[tokio::test]
async fn test_none_algorithm_rejected() {
    let server = TestServer::spawn(2048, vec![KeySignAlgorithm::ES256])
        .await
        .expect("Failed to spawn server");

    let claims = json!({"sub": "user", "exp": 9999999999_i64});
    let client = reqwest::Client::new();

    // Try to sign with "none" algorithm (security risk per RFC 8725)
    let response = client
        .post(format!("{}/sign/none", server.base_url))
        .json(&claims)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "Should return 400 for 'none' algorithm"
    );

    let error_response: serde_json::Value = response.json().await.expect("Failed to parse error");
    let error_msg = error_response
        .get("error")
        .and_then(|e| e.as_str())
        .unwrap_or("");

    assert!(
        error_msg.contains("'none' algorithm is rejected"),
        "Error message should mention 'none' algorithm rejection, got: {}",
        error_msg
    );
    assert!(
        error_msg.contains("RFC 8725"),
        "Error message should reference RFC 8725, got: {}",
        error_msg
    );
}

#[tokio::test]
async fn test_algorithm_mismatch_verification_fails() {
    // Server only exposes RS256 in JWKS
    let server = TestServer::spawn(2048, vec![KeySignAlgorithm::RS256])
        .await
        .expect("Failed to spawn server");

    // Sign with RS384 (not in JWKS)
    let claims = json!({"sub": "user", "exp": 9999999999_i64});
    let token = server
        .sign_jwt(claims, Some("RS384"))
        .await
        .expect("Signing should work with any algorithm");

    let jwks = server.fetch_jwks().await.expect("Failed to fetch JWKS");

    // Verification should fail - no RS384 key in JWKS
    let result = verify_token(&token, &jwks);
    assert!(
        result.is_err(),
        "Should fail to verify RS384 token when JWKS only has RS256"
    );
}

#[tokio::test]
async fn test_tampered_signature_fails_verification() {
    let server = TestServer::spawn(2048, vec![KeySignAlgorithm::RS256])
        .await
        .expect("Failed to spawn server");

    let claims = json!({"sub": "user", "exp": 9999999999_i64});
    let token = server.sign_jwt(claims, None).await.expect("Failed to sign");

    // Tamper with the signature
    let parts: Vec<&str> = token.split('.').collect();
    let tampered_token = format!("{}.{}.INVALID_SIGNATURE", parts[0], parts[1]);

    let jwks = server.fetch_jwks().await.expect("Failed to fetch JWKS");

    let result = verify_token(&tampered_token, &jwks);
    assert!(
        result.is_err(),
        "Should fail to verify token with tampered signature"
    );
}
