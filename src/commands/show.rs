use std::path::PathBuf;

use clap::Args;

use crate::{errors::JWKServeError, key::RsaPrivateKey};

#[derive(Args)]
pub struct ArgsShow {
    /// Path to PEM-encoded RSA private key file
    #[arg(short, long = "key", value_name = "FILE")]
    pub key_file: PathBuf,

    /// Extract and display public key instead of private key
    #[arg(long)]
    pub public: bool,
}

pub async fn handle_show(args: &ArgsShow) -> color_eyre::Result<()> {
    let key = RsaPrivateKey::from_pem_file(&args.key_file).map_err(JWKServeError::RsaKeyError)?;

    let output = if args.public {
        key.to_public_pem().map_err(JWKServeError::RsaKeyError)?
    } else {
        key.to_pem().map_err(JWKServeError::RsaKeyError)?
    };

    println!("{output}");
    Ok(())
}
