use std::path::PathBuf;

use clap::{Args, ValueEnum};

use crate::{
    commands::show_output_or_save,
    errors::JWKServeError,
    key::{EcdsaCurve, RsaPrivateKey},
};

#[derive(ValueEnum, Clone, Debug)]
pub enum KeygenType {
    #[value(name = "rsa")]
    Rsa,
    #[value(name = "ecdsa")]
    Ecdsa,
}

#[derive(ValueEnum, Clone, Debug)]
pub enum KeygenSize {
    #[value(name = "2048")]
    Rsa2048,
    #[value(name = "3072")]
    Rsa3072,
    #[value(name = "4096")]
    Rsa4096,
}

#[derive(ValueEnum, Clone, Debug)]
pub enum KeygenCurve {
    #[value(name = "256")]
    P256,
    #[value(name = "384")]
    P384,
    #[value(name = "521")]
    P521,
}

impl From<KeygenCurve> for EcdsaCurve {
    fn from(curve: KeygenCurve) -> Self {
        match curve {
            KeygenCurve::P256 => EcdsaCurve::P256,
            KeygenCurve::P384 => EcdsaCurve::P384,
            KeygenCurve::P521 => EcdsaCurve::P521,
        }
    }
}

#[derive(Args)]
pub struct ArgsKeygen {
    /// Key type (RSA or ECDSA)
    #[arg(short = 't', long = "type", default_value = "rsa", value_name = "TYPE")]
    pub key_type: KeygenType,

    /// RSA key size in bits (only for RSA keys)
    #[arg(short, long, value_name = "BITS")]
    pub size: Option<KeygenSize>,

    /// ECDSA curve (only for ECDSA keys)
    #[arg(short, long, value_name = "CURVE")]
    pub curve: Option<KeygenCurve>,

    /// Output file (default: stdout)
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,
}

pub fn handle_keygen(args: &ArgsKeygen) -> color_eyre::Result<()> {
    use crate::key::EcdsaPrivateKey;

    match args.key_type {
        KeygenType::Rsa => {
            // Validate RSA parameters
            let size = args.size.as_ref().ok_or_else(|| {
                color_eyre::eyre::eyre!(
                    "RSA key generation requires --size parameter. Use: --size 2048, --size 3072, or --size 4096"
                )
            })?;

            if args.curve.is_some() {
                return Err(color_eyre::eyre::eyre!(
                    "RSA key generation does not accept --curve parameter. Did you mean to use --type ecdsa?"
                ));
            }

            let bits = match size {
                KeygenSize::Rsa2048 => 2048,
                KeygenSize::Rsa3072 => 3072,
                KeygenSize::Rsa4096 => 4096,
            };

            let key = RsaPrivateKey::generate(bits).map_err(JWKServeError::KeyError)?;
            let output = key.to_pem().map_err(JWKServeError::KeyError)?;

            show_output_or_save(args.output.as_ref(), &output)?;
        }
        KeygenType::Ecdsa => {
            // Validate ECDSA parameters
            let curve = args.curve.as_ref().ok_or_else(|| {
                color_eyre::eyre::eyre!(
                    "ECDSA key generation requires --curve parameter. Use: --curve 256, --curve 384, or --curve 521"
                )
            })?;

            if args.size.is_some() {
                return Err(color_eyre::eyre::eyre!(
                    "ECDSA key generation does not accept --size parameter. Did you mean to use --type rsa?"
                ));
            }

            let ecdsa_curve: EcdsaCurve = curve.clone().into();
            let key = EcdsaPrivateKey::generate(ecdsa_curve).map_err(JWKServeError::KeyError)?;
            let output = key.to_pem().map_err(JWKServeError::KeyError)?;

            show_output_or_save(args.output.as_ref(), &output)?;
        }
    }

    Ok(())
}
