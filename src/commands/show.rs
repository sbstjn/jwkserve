use std::io::Write;
use std::path::PathBuf;

use base64::{engine::general_purpose::STANDARD, Engine};
use clap::{Args, ValueEnum};

use crate::{
    errors::JWKServeError,
    key::{EcdsaPrivateKey, RsaPrivateKey},
};

#[derive(ValueEnum, Clone, Debug)]
pub enum KeyFormat {
    /// PEM format (textual)
    #[value(name = "pem")]
    Pem,
    /// DER format (raw binary)
    #[value(name = "der")]
    Der,
    /// DER format (base64-encoded, safe for terminal output)
    #[value(name = "der-base64")]
    DerBase64,
}

#[derive(Args)]
pub struct ArgsShow {
    /// Path to PEM-encoded RSA or ECDSA private key file
    #[arg(short, long = "key", value_name = "FILE")]
    pub key_file: PathBuf,

    /// Extract and display public key instead of private key
    #[arg(long)]
    pub public: bool,

    /// Output format (pem, der, or der-base64)
    #[arg(long, default_value = "pem", value_name = "FORMAT")]
    pub format: KeyFormat,
}

pub async fn handle_show(args: &ArgsShow) -> color_eyre::Result<()> {
    match args.format {
        KeyFormat::Pem => {
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
        }
        KeyFormat::Der => {
            let der_bytes = if let Ok(key) = RsaPrivateKey::from_pem_file(&args.key_file) {
                if args.public {
                    key.to_public_der().map_err(JWKServeError::KeyError)?
                } else {
                    key.to_der().map_err(JWKServeError::KeyError)?
                }
            } else if let Ok(key) = EcdsaPrivateKey::from_pem_file(&args.key_file) {
                if args.public {
                    key.to_public_der().map_err(JWKServeError::KeyError)?
                } else {
                    key.to_der().map_err(JWKServeError::KeyError)?
                }
            } else {
                return Err(
                    JWKServeError::KeyError(crate::key::KeyError::FailedToDecode {
                        key_type: "RSA or ECDSA".to_string(),
                    })
                    .into(),
                );
            };

            // Output raw binary DER (use with redirection: > file.der)
            std::io::stdout()
                .write_all(&der_bytes)
                .map_err(|e| JWKServeError::IoError {
                    path: PathBuf::from("<stdout>"),
                    source: e,
                })?;
        }
        KeyFormat::DerBase64 => {
            let der_bytes = if let Ok(key) = RsaPrivateKey::from_pem_file(&args.key_file) {
                if args.public {
                    key.to_public_der().map_err(JWKServeError::KeyError)?
                } else {
                    key.to_der().map_err(JWKServeError::KeyError)?
                }
            } else if let Ok(key) = EcdsaPrivateKey::from_pem_file(&args.key_file) {
                if args.public {
                    key.to_public_der().map_err(JWKServeError::KeyError)?
                } else {
                    key.to_der().map_err(JWKServeError::KeyError)?
                }
            } else {
                return Err(
                    JWKServeError::KeyError(crate::key::KeyError::FailedToDecode {
                        key_type: "RSA or ECDSA".to_string(),
                    })
                    .into(),
                );
            };

            // Base64-encode DER for safe terminal output
            let base64_der = STANDARD.encode(&der_bytes);
            println!("{base64_der}");
        }
    }

    Ok(())
}
