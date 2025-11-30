pub mod commands;
pub mod errors;
pub mod key;
pub mod router;

use clap::ValueEnum;

#[derive(ValueEnum, Clone, Debug, PartialEq, Eq)]
pub enum KeySignAlgorithm {
    #[value(name = "RS256")]
    RS256,
    #[value(name = "RS384")]
    RS384,
    #[value(name = "RS512")]
    RS512,
}

impl KeySignAlgorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RS256 => "RS256",
            Self::RS384 => "RS384",
            Self::RS512 => "RS512",
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
            _ => Err(format!(
                "unsupported algorithm: {s}. Valid algorithms: RS256, RS384, RS512"
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
    }
}
