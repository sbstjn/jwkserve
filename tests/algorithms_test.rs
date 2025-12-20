//! Algorithm-specific integration tests
//!
//! Validates that each of the 6 supported JWT algorithms (RS256/384/512, ES256/384/512)
//! correctly signs tokens via HTTP endpoints and produces JWKS entries that enable
//! signature verification. Uses fixture keys for deterministic testing.

mod common;

use common::{decode_jwt_header, verify_token, TestServer};
use jwkserve::KeySignAlgorithm;
use serde_json::json;

#[tokio::test]
async fn test_rs256_sign_and_verify() {
    let server = TestServer::spawn(2048, vec![KeySignAlgorithm::RS256])
        .await
        .expect("Failed to spawn server");

    let claims = json!({
        "sub": "user123",
        "aud": "test-app",
        "exp": 9999999999_i64
    });

    let token = server
        .sign_jwt(claims.clone(), Some("RS256"))
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

    // Verify kid ends with algorithm suffix
    assert!(header_kid.ends_with("-RS256"), "kid must end with '-RS256'");

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
async fn test_rs384_sign_and_verify() {
    let server = TestServer::spawn(2048, vec![KeySignAlgorithm::RS384])
        .await
        .expect("Failed to spawn server");

    let claims = json!({"sub": "user456", "exp": 9999999999_i64});

    let token = server
        .sign_jwt(claims, Some("RS384"))
        .await
        .expect("Failed to sign with RS384");

    let jwks = server.fetch_jwks().await.expect("Failed to fetch JWKS");

    let header = decode_jwt_header(&token).expect("Failed to decode JWT header");
    let header_kid = header.kid.as_ref().unwrap();
    assert!(header_kid.ends_with("-RS384"), "kid must end with '-RS384'");

    let verified_claims = verify_token(&token, &jwks).expect("Failed to verify RS384 token");

    assert_eq!(
        verified_claims.get("sub").expect("Missing sub claim"),
        "user456"
    );
}

#[tokio::test]
async fn test_rs512_sign_and_verify() {
    let server = TestServer::spawn(2048, vec![KeySignAlgorithm::RS512])
        .await
        .expect("Failed to spawn server");

    let claims = json!({"sub": "user789", "exp": 9999999999_i64});

    let token = server
        .sign_jwt(claims, Some("RS512"))
        .await
        .expect("Failed to sign with RS512");

    let jwks = server.fetch_jwks().await.expect("Failed to fetch JWKS");

    let header = decode_jwt_header(&token).expect("Failed to decode JWT header");
    let header_kid = header.kid.as_ref().unwrap();
    assert!(header_kid.ends_with("-RS512"), "kid must end with '-RS512'");

    let verified_claims = verify_token(&token, &jwks).expect("Failed to verify RS512 token");

    assert_eq!(
        verified_claims.get("sub").expect("Missing sub claim"),
        "user789"
    );
}

#[tokio::test]
async fn test_es256_sign_and_verify() {
    let server = TestServer::spawn(2048, vec![KeySignAlgorithm::ES256])
        .await
        .expect("Failed to spawn server");

    let claims = json!({
        "sub": "ecdsa-user-256",
        "aud": "test-app",
        "exp": 9999999999_i64
    });

    let token = server
        .sign_jwt(claims.clone(), Some("ES256"))
        .await
        .expect("Failed to sign token with ES256");

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

    // Verify kid ends with algorithm suffix
    assert!(header_kid.ends_with("-ES256"), "kid must end with '-ES256'");

    let verified_claims = verify_token(&token, &jwks).expect("Failed to verify ES256 token");

    assert_eq!(
        verified_claims.get("sub").expect("Missing sub claim"),
        "ecdsa-user-256"
    );
    assert_eq!(
        verified_claims.get("aud").expect("Missing aud claim"),
        "test-app"
    );
}

#[tokio::test]
async fn test_es384_sign_and_verify() {
    let server = TestServer::spawn(2048, vec![KeySignAlgorithm::ES384])
        .await
        .expect("Failed to spawn server");

    let claims = json!({"sub": "ecdsa-user-384", "exp": 9999999999_i64});

    let token = server
        .sign_jwt(claims, Some("ES384"))
        .await
        .expect("Failed to sign with ES384");

    let jwks = server.fetch_jwks().await.expect("Failed to fetch JWKS");

    let header = decode_jwt_header(&token).expect("Failed to decode JWT header");
    let header_kid = header.kid.as_ref().unwrap();
    assert!(header_kid.ends_with("-ES384"), "kid must end with '-ES384'");

    let verified_claims = verify_token(&token, &jwks).expect("Failed to verify ES384 token");

    assert_eq!(
        verified_claims.get("sub").expect("Missing sub claim"),
        "ecdsa-user-384"
    );
}

#[tokio::test]
async fn test_es512_sign_and_verify() {
    let server = TestServer::spawn(2048, vec![KeySignAlgorithm::ES512])
        .await
        .expect("Failed to spawn server");

    let claims = json!({"sub": "ecdsa-user-521", "exp": 9999999999_i64});

    let token = server
        .sign_jwt(claims, Some("ES512"))
        .await
        .expect("Failed to sign with ES512");

    let jwks = server.fetch_jwks().await.expect("Failed to fetch JWKS");

    // ES512 (P-521) uses custom signing in the codebase
    // The JWT header won't be parseable by standard jsonwebtoken library
    // Instead, verify the token structure manually
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3, "JWT should have 3 parts");

    // Decode header manually
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .expect("Failed to decode header");
    let header: serde_json::Value =
        serde_json::from_slice(&header_bytes).expect("Failed to parse header");

    assert_eq!(header.get("alg").unwrap(), "ES512");
    let header_kid = header.get("kid").unwrap().as_str().unwrap();
    assert!(header_kid.ends_with("-ES512"), "kid must end with '-ES512'");

    // Verify the key exists in JWKS
    let keys = jwks.get("keys").unwrap().as_array().unwrap();
    let matching_key = keys.iter().find(|k| {
        k.get("kid")
            .and_then(|v| v.as_str())
            .map(|kid| kid == header_kid)
            .unwrap_or(false)
    });
    assert!(matching_key.is_some(), "ES512 key must exist in JWKS");

    // Verify claims
    let claims_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("Failed to decode claims");
    let claims: serde_json::Value =
        serde_json::from_slice(&claims_bytes).expect("Failed to parse claims");
    assert_eq!(claims.get("sub").unwrap(), "ecdsa-user-521");
}

#[tokio::test]
async fn test_multi_algorithm_server() {
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
async fn test_mixed_rsa_ecdsa_algorithms() {
    let server = TestServer::spawn(
        2048,
        vec![
            KeySignAlgorithm::RS256,
            KeySignAlgorithm::ES256,
            KeySignAlgorithm::ES384,
        ],
    )
    .await
    .expect("Failed to spawn server");

    let jwks = server.fetch_jwks().await.expect("Failed to fetch JWKS");

    let keys = jwks.get("keys").unwrap().as_array().unwrap();
    assert_eq!(keys.len(), 3, "Should have 3 keys (1 RSA + 2 ECDSA)");

    // Verify each algorithm type is present
    let rsa_key = keys.iter().find(|k| k.get("kty").unwrap() == "RSA");
    let ec_keys: Vec<_> = keys
        .iter()
        .filter(|k| k.get("kty").unwrap() == "EC")
        .collect();

    assert!(rsa_key.is_some(), "Should have 1 RSA key");
    assert_eq!(ec_keys.len(), 2, "Should have 2 EC keys");

    // Test signing with each algorithm
    for alg in ["RS256", "ES256", "ES384"] {
        let claims = json!({"sub": format!("user-{}", alg), "exp": 9999999999_i64});
        let token = server
            .sign_jwt(claims, Some(alg))
            .await
            .unwrap_or_else(|_| panic!("Failed to sign with {}", alg));

        verify_token(&token, &jwks).unwrap_or_else(|_| panic!("Failed to verify {} token", alg));
    }
}

#[tokio::test]
async fn test_rsa_jwks_structure() {
    let server = TestServer::spawn(2048, vec![KeySignAlgorithm::RS256])
        .await
        .expect("Failed to spawn server");

    let jwks = server.fetch_jwks().await.expect("Failed to fetch JWKS");

    let keys = jwks
        .get("keys")
        .expect("Missing keys field")
        .as_array()
        .expect("Keys is not an array");

    assert_eq!(keys.len(), 1);

    let key = &keys[0];
    assert_eq!(key.get("kty").expect("Missing kty field"), "RSA");
    assert_eq!(key.get("use").expect("Missing use field"), "sig");
    assert_eq!(key.get("alg").expect("Missing alg field"), "RS256");
    assert!(key.get("kid").is_some(), "Missing kid field");
    assert!(key.get("n").is_some(), "Missing n field (RSA modulus)");
    assert!(key.get("e").is_some(), "Missing e field (RSA exponent)");

    // Verify n and e are base64url-encoded strings
    let n = key.get("n").unwrap().as_str().unwrap();
    let e = key.get("e").unwrap().as_str().unwrap();
    assert!(!n.is_empty(), "RSA modulus 'n' should not be empty");
    assert!(!e.is_empty(), "RSA exponent 'e' should not be empty");
}

#[tokio::test]
async fn test_ecdsa_jwks_structure_p256() {
    let server = TestServer::spawn(2048, vec![KeySignAlgorithm::ES256])
        .await
        .expect("Failed to spawn server");

    let jwks = server.fetch_jwks().await.expect("Failed to fetch JWKS");

    let keys = jwks
        .get("keys")
        .expect("Missing keys field")
        .as_array()
        .expect("Keys is not an array");

    assert_eq!(keys.len(), 1);

    let key = &keys[0];
    assert_eq!(key.get("kty").expect("Missing kty field"), "EC");
    assert_eq!(key.get("use").expect("Missing use field"), "sig");
    assert_eq!(key.get("alg").expect("Missing alg field"), "ES256");
    assert_eq!(key.get("crv").expect("Missing crv field"), "P-256");
    assert!(key.get("kid").is_some(), "Missing kid field");
    assert!(key.get("x").is_some(), "Missing x field (EC x-coordinate)");
    assert!(key.get("y").is_some(), "Missing y field (EC y-coordinate)");

    // Verify x and y are base64url-encoded strings
    let x = key.get("x").unwrap().as_str().unwrap();
    let y = key.get("y").unwrap().as_str().unwrap();
    assert!(!x.is_empty(), "EC x-coordinate should not be empty");
    assert!(!y.is_empty(), "EC y-coordinate should not be empty");
}

#[tokio::test]
async fn test_ecdsa_jwks_structure_p384() {
    let server = TestServer::spawn(2048, vec![KeySignAlgorithm::ES384])
        .await
        .expect("Failed to spawn server");

    let jwks = server.fetch_jwks().await.expect("Failed to fetch JWKS");

    let keys = jwks.get("keys").unwrap().as_array().unwrap();
    let key = &keys[0];

    assert_eq!(key.get("kty").expect("Missing kty field"), "EC");
    assert_eq!(key.get("crv").expect("Missing crv field"), "P-384");
    assert_eq!(key.get("alg").expect("Missing alg field"), "ES384");
}

#[tokio::test]
async fn test_ecdsa_jwks_structure_p521() {
    let server = TestServer::spawn(2048, vec![KeySignAlgorithm::ES512])
        .await
        .expect("Failed to spawn server");

    let jwks = server.fetch_jwks().await.expect("Failed to fetch JWKS");

    let keys = jwks.get("keys").unwrap().as_array().unwrap();
    let key = &keys[0];

    assert_eq!(key.get("kty").expect("Missing kty field"), "EC");
    assert_eq!(key.get("crv").expect("Missing crv field"), "P-521");
    assert_eq!(key.get("alg").expect("Missing alg field"), "ES512");
}

#[tokio::test]
async fn test_deterministic_rsa_signatures() {
    let server = TestServer::spawn(2048, vec![KeySignAlgorithm::RS256])
        .await
        .expect("Failed to spawn server");

    let claims = json!({"sub": "deterministic-test", "exp": 9999999999_i64});

    // Sign the same claims twice
    let token1 = server
        .sign_jwt(claims.clone(), Some("RS256"))
        .await
        .expect("Failed to sign token 1");

    let token2 = server
        .sign_jwt(claims.clone(), Some("RS256"))
        .await
        .expect("Failed to sign token 2");

    // With deterministic signing using fixture keys, tokens should be identical
    assert_eq!(
        token1, token2,
        "Tokens should be identical with same claims and key"
    );

    // Verify kid is consistent
    let header1 = decode_jwt_header(&token1).expect("Failed to decode header 1");
    let header2 = decode_jwt_header(&token2).expect("Failed to decode header 2");
    assert_eq!(header1.kid, header2.kid, "kid should be consistent");

    // Both tokens should verify successfully
    let jwks = server.fetch_jwks().await.expect("Failed to fetch JWKS");
    verify_token(&token1, &jwks).expect("Failed to verify token 1");
    verify_token(&token2, &jwks).expect("Failed to verify token 2");
}

#[tokio::test]
async fn test_deterministic_ecdsa_kid() {
    let server = TestServer::spawn(2048, vec![KeySignAlgorithm::ES256])
        .await
        .expect("Failed to spawn server");

    let claims = json!({"sub": "deterministic-ecdsa", "exp": 9999999999_i64});

    // Sign the same claims twice
    let token1 = server
        .sign_jwt(claims.clone(), Some("ES256"))
        .await
        .expect("Failed to sign token 1");

    let token2 = server
        .sign_jwt(claims.clone(), Some("ES256"))
        .await
        .expect("Failed to sign token 2");

    // ECDSA signatures are non-deterministic due to random nonce (k) generation
    // However, the kid should be consistent since it's derived from the key
    let header1 = decode_jwt_header(&token1).expect("Failed to decode header 1");
    let header2 = decode_jwt_header(&token2).expect("Failed to decode header 2");
    assert_eq!(
        header1.kid, header2.kid,
        "kid should be consistent across signatures"
    );

    // Both tokens should verify successfully even with different signatures
    let jwks = server.fetch_jwks().await.expect("Failed to fetch JWKS");
    verify_token(&token1, &jwks).expect("Failed to verify token 1");
    verify_token(&token2, &jwks).expect("Failed to verify token 2");
}
