//! Base64URL encoding/decoding utilities
//!
//! Centralized Base64URL operations following RFC 4648.
//! Uses URL-safe alphabet without padding as required by JWT specifications.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

/// Encode bytes to Base64URL string
///
/// # Arguments
/// * `bytes` - Raw bytes to encode
///
/// # Returns
/// Base64URL-encoded string without padding
pub(crate) fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decode Base64URL string to bytes
///
/// # Arguments
/// * `input` - Base64URL-encoded string to decode
///
/// # Returns
/// Decoded bytes or error if invalid Base64URL
pub(crate) fn decode(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    URL_SAFE_NO_PAD.decode(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let data = b"Hello, World!";
        let encoded = encode(data);
        let decoded = decode(&encoded).expect("decode should succeed");
        assert_eq!(data, decoded.as_slice());
    }

    #[test]
    fn test_encode_empty() {
        let data = b"";
        let encoded = encode(data);
        assert_eq!(encoded, "");
    }

    #[test]
    fn test_decode_empty() {
        let decoded = decode("").expect("empty string should decode");
        assert_eq!(decoded, Vec::<u8>::new());
    }

    #[test]
    fn test_encode_no_padding() {
        // Base64URL should not include padding characters
        let data = b"test";
        let encoded = encode(data);
        assert!(!encoded.contains('='));
    }

    #[test]
    fn test_decode_invalid() {
        // Invalid Base64URL characters
        let result = decode("!!!invalid!!!");
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_with_padding_fails() {
        // Standard base64 with padding should fail for URL_SAFE_NO_PAD
        let result = decode("SGVsbG8=");
        assert!(result.is_err());
    }
}
