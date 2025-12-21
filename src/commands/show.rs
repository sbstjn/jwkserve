use std::path::PathBuf;

use clap::Args;

use crate::{
    errors::JWKServeError,
    key::{EcdsaPrivateKey, RsaPrivateKey},
};

#[derive(Args)]
pub struct ArgsShow {
    /// Path to PEM-encoded RSA or ECDSA private key file
    #[arg(short, long = "key", value_name = "FILE")]
    pub key_file: PathBuf,

    /// Extract and display public key instead of private key
    #[arg(long)]
    pub public: bool,
}

pub async fn handle_show(args: &ArgsShow) -> color_eyre::Result<()> {
    // Try RSA first, then ECDSA
    let output = if let Ok(key) = RsaPrivateKey::from_pem_file(&args.key_file) {
        if args.public {
            key.to_public_pem().map_err(JWKServeError::KeyError)?
        } else {
            key.to_pem().map_err(JWKServeError::KeyError)?
        }
    } else if let Ok(key) = EcdsaPrivateKey::from_pem_file(&args.key_file) {
        if args.public {
            key.to_public_pem().map_err(JWKServeError::KeyError)?
        } else {
            key.to_pem().map_err(JWKServeError::KeyError)?
        }
    } else {
        return Err(
            JWKServeError::KeyError(crate::key::KeyError::FailedToDecode {
                key_type: "RSA or ECDSA".to_string(),
            })
            .into(),
        );
    };

    println!("{output}");
    Ok(())
}
