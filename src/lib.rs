pub mod commands;
pub mod errors;
pub mod key;
pub mod router;

use clap::ValueEnum;
use key::EcdsaCurve;

/// Cryptographic key type
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyType {
    Rsa,
    Ecdsa,
}

#[derive(ValueEnum, Clone, Debug, PartialEq, Eq, Hash)]
pub enum KeySignAlgorithm {
    #[value(name = "RS256")]
    RS256,
    #[value(name = "RS384")]
    RS384,
    #[value(name = "RS512")]
    RS512,
    #[value(name = "ES256")]
    ES256,
    #[value(name = "ES384")]
    ES384,
    #[value(name = "ES512")]
    ES512,
}

impl KeySignAlgorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RS256 => "RS256",
            Self::RS384 => "RS384",
            Self::RS512 => "RS512",
            Self::ES256 => "ES256",
            Self::ES384 => "ES384",
            Self::ES512 => "ES512",
        }
    }

    /// Get the key type required for this algorithm
    pub fn key_type(&self) -> KeyType {
        match self {
            Self::RS256 | Self::RS384 | Self::RS512 => KeyType::Rsa,
            Self::ES256 | Self::ES384 | Self::ES512 => KeyType::Ecdsa,
        }
    }

    /// Get the ECDSA curve for this algorithm (if applicable)
    ///
    /// Returns None for RSA algorithms
    pub fn curve(&self) -> Option<EcdsaCurve> {
        match self {
            Self::ES256 => Some(EcdsaCurve::P256),
            Self::ES384 => Some(EcdsaCurve::P384),
            Self::ES512 => Some(EcdsaCurve::P521),
            _ => None,
        }
    }
}

impl std::str::FromStr for KeySignAlgorithm {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "RS256" => Ok(Self::RS256),
            "RS384" => Ok(Self::RS384),
            "RS512" => Ok(Self::RS512),
            "ES256" => Ok(Self::ES256),
            "ES384" => Ok(Self::ES384),
            "ES512" => Ok(Self::ES512),
            _ => Err(format!(
                "unsupported algorithm: {s}. Valid algorithms: RS256, RS384, RS512, ES256, ES384, ES512"
            )),
        }
    }
}

impl std::fmt::Display for KeySignAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display_trait() {
        assert_eq!(format!("{}", KeySignAlgorithm::RS256), "RS256");
        assert_eq!(format!("{}", KeySignAlgorithm::RS384), "RS384");
        assert_eq!(format!("{}", KeySignAlgorithm::RS512), "RS512");
        assert_eq!(format!("{}", KeySignAlgorithm::ES256), "ES256");
        assert_eq!(format!("{}", KeySignAlgorithm::ES384), "ES384");
        assert_eq!(format!("{}", KeySignAlgorithm::ES512), "ES512");
    }

    #[test]
    fn test_key_type() {
        assert_eq!(KeySignAlgorithm::RS256.key_type(), KeyType::Rsa);
        assert_eq!(KeySignAlgorithm::RS384.key_type(), KeyType::Rsa);
        assert_eq!(KeySignAlgorithm::RS512.key_type(), KeyType::Rsa);
        assert_eq!(KeySignAlgorithm::ES256.key_type(), KeyType::Ecdsa);
        assert_eq!(KeySignAlgorithm::ES384.key_type(), KeyType::Ecdsa);
        assert_eq!(KeySignAlgorithm::ES512.key_type(), KeyType::Ecdsa);
    }

    #[test]
    fn test_curve() {
        assert_eq!(KeySignAlgorithm::RS256.curve(), None);
        assert_eq!(KeySignAlgorithm::RS384.curve(), None);
        assert_eq!(KeySignAlgorithm::RS512.curve(), None);
        assert_eq!(KeySignAlgorithm::ES256.curve(), Some(EcdsaCurve::P256));
        assert_eq!(KeySignAlgorithm::ES384.curve(), Some(EcdsaCurve::P384));
        assert_eq!(KeySignAlgorithm::ES512.curve(), Some(EcdsaCurve::P521));
    }
}
