mod common;

use common::{decode_jwt_header, verify_token, TestServer};
use jwkserve::{key::RsaPrivateKey, KeySignAlgorithm};
use serde_json::json;

#[tokio::test]
async fn test_key_generation() {
    // Test that key generation works correctly
    let key = RsaPrivateKey::generate(2048).expect("Failed to generate 2048-bit key");
    assert_eq!(key.size_bits(), 2048);

    // Verify the generated key works with the server
    let server = TestServer::spawn_with_key(vec![KeySignAlgorithm::RS256], key)
        .await
        .expect("Failed to spawn server with generated key");

    let claims = json!({"sub": "test-gen", "exp": 9999999999_i64});
    let token = server
        .sign_jwt(claims, None)
        .await
        .expect("Failed to sign with generated key");

    let jwks = server.fetch_jwks().await.expect("Failed to fetch JWKS");
    verify_token(&token, &jwks).expect("Failed to verify token from generated key");
}

#[tokio::test]
async fn test_sign_and_verify_rs256_2048() {
    let server = TestServer::spawn(2048, vec![KeySignAlgorithm::RS256])
        .await
        .expect("Failed to spawn server");

    let claims = json!({
        "sub": "user123",
        "aud": "test-app",
        "exp": 9999999999_i64
    });

    let token = server
        .sign_jwt(claims.clone(), None)
        .await
        .expect("Failed to sign token");

    let jwks = server.fetch_jwks().await.expect("Failed to fetch JWKS");

    // Verify kid exists in JWT header
    let header = decode_jwt_header(&token).expect("Failed to decode JWT header");
    assert!(header.kid.is_some(), "JWT header must contain 'kid' field");

    // Verify the kid matches a key in JWKS
    let header_kid = header.kid.as_ref().unwrap();
    let keys = jwks.get("keys").unwrap().as_array().unwrap();
    let matching_key = keys.iter().find(|k| {
        k.get("kid")
            .and_then(|v| v.as_str())
            .map(|kid| kid == header_kid)
            .unwrap_or(false)
    });
    assert!(
        matching_key.is_some(),
        "JWT kid '{}' must exist in JWKS",
        header_kid
    );

    let verified_claims = verify_token(&token, &jwks).expect("Failed to verify token");

    assert_eq!(
        verified_claims.get("sub").expect("Missing sub claim"),
        "user123"
    );
    assert_eq!(
        verified_claims.get("aud").expect("Missing aud claim"),
        "test-app"
    );
    assert_eq!(
        verified_claims.get("iss").expect("Missing iss claim"),
        &server.issuer,
        "Issuer should be auto-injected"
    );
}

#[tokio::test]
async fn test_sign_and_verify_rs384_2048() {
    let server = TestServer::spawn(2048, vec![KeySignAlgorithm::RS384])
        .await
        .expect("Failed to spawn server");

    let claims = json!({"sub": "user456", "exp": 9999999999_i64});

    let token = server
        .sign_jwt(claims, Some("RS384"))
        .await
        .expect("Failed to sign with RS384");

    let jwks = server.fetch_jwks().await.expect("Failed to fetch JWKS");

    let verified_claims = verify_token(&token, &jwks).expect("Failed to verify RS384 token");

    assert_eq!(
        verified_claims.get("sub").expect("Missing sub claim"),
        "user456"
    );
}

#[tokio::test]
async fn test_sign_and_verify_rs512_2048() {
    let server = TestServer::spawn(2048, vec![KeySignAlgorithm::RS512])
        .await
        .expect("Failed to spawn server");

    let claims = json!({"sub": "user789", "exp": 9999999999_i64});

    let token = server
        .sign_jwt(claims, Some("RS512"))
        .await
        .expect("Failed to sign with RS512");

    let jwks = server.fetch_jwks().await.expect("Failed to fetch JWKS");

    let verified_claims = verify_token(&token, &jwks).expect("Failed to verify RS512 token");

    assert_eq!(
        verified_claims.get("sub").expect("Missing sub claim"),
        "user789"
    );
}

#[tokio::test]
#[ignore = "Large key test - run with: cargo test -- --ignored"]
async fn test_large_key_3072() {
    let server = TestServer::spawn(3072, vec![KeySignAlgorithm::RS256])
        .await
        .expect("Failed to spawn server with 3072-bit key");

    let claims = json!({"sub": "user-3072", "exp": 9999999999_i64});
    let token = server.sign_jwt(claims, None).await.expect("Failed to sign");

    let jwks = server.fetch_jwks().await.expect("Failed to fetch JWKS");
    verify_token(&token, &jwks).expect("Failed to verify with 3072-bit key");
}

#[tokio::test]
#[ignore = "Large key test - run with: cargo test -- --ignored"]
async fn test_large_key_4096() {
    let server = TestServer::spawn(4096, vec![KeySignAlgorithm::RS256])
        .await
        .expect("Failed to spawn server with 4096-bit key");

    let claims = json!({"sub": "user-4096", "exp": 9999999999_i64});
    let token = server.sign_jwt(claims, None).await.expect("Failed to sign");

    let jwks = server.fetch_jwks().await.expect("Failed to fetch JWKS");
    verify_token(&token, &jwks).expect("Failed to verify with 4096-bit key");
}

#[tokio::test]
async fn test_multiple_algorithms_same_key() {
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
    assert_eq!(keys.len(), 3, "Should have 3 keys (one per algorithm)");

    // Verify each algorithm works and has correct kid
    for alg in ["RS256", "RS384", "RS512"] {
        let claims = json!({"sub": format!("user-{}", alg), "exp": 9999999999_i64});

        let token = server
            .sign_jwt(claims, Some(alg))
            .await
            .unwrap_or_else(|_| panic!("Failed to sign with {alg}"));

        // Verify JWT header has kid
        let header = decode_jwt_header(&token)
            .unwrap_or_else(|_| panic!("Failed to decode header for {alg}"));
        assert!(
            header.kid.is_some(),
            "JWT header must contain 'kid' field for {alg}"
        );

        // Verify kid ends with algorithm suffix
        let header_kid = header.kid.as_ref().unwrap();
        assert!(
            header_kid.ends_with(&format!("-{}", alg)),
            "kid '{}' must end with '-{}' for algorithm {}",
            header_kid,
            alg,
            alg
        );

        verify_token(&token, &jwks).unwrap_or_else(|_| panic!("Failed to verify {alg} token"));
    }
}

#[tokio::test]
async fn test_algorithm_mismatch() {
    // Server only exposes RS256 in JWKS
    let server = TestServer::spawn(2048, vec![KeySignAlgorithm::RS256])
        .await
        .expect("Failed to spawn server");

    // Sign with RS384 (not in JWKS but still supported for testing)
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
async fn test_issuer_override() {
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
async fn test_openid_discovery() {
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
async fn test_jwks_structure() {
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
async fn test_kid_consistency() {
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
async fn test_tampered_signature_fails() {
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

#[tokio::test]
async fn test_invalid_algorithm() {
    let server = TestServer::spawn(2048, vec![KeySignAlgorithm::RS256])
        .await
        .expect("Failed to spawn server");

    let claims = json!({"sub": "user", "exp": 9999999999_i64});
    let client = reqwest::Client::new();

    // Try to sign with invalid RSA size
    let response = client
        .post(format!("{}/sign/rsa/999", server.base_url))
        .json(&claims)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "Should return 400 for invalid RSA size"
    );

    let error_response: serde_json::Value = response.json().await.expect("Failed to parse error");
    assert!(
        error_response
            .get("error")
            .and_then(|e| e.as_str())
            .unwrap_or("")
            .contains("invalid RSA size"),
        "Error message should mention invalid RSA size"
    );
}

#[tokio::test]
async fn test_oversized_payload() {
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
async fn test_malformed_json() {
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
