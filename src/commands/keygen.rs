use std::path::PathBuf;

use clap::{Args, ValueEnum};

use crate::{commands::show_output_or_save, errors::JWKServeError, key::RsaPrivateKey};

#[derive(ValueEnum, Clone, Debug)]
pub enum KeygenSize {
    #[value(name = "2048")]
    Rsa2048,
    #[value(name = "3072")]
    Rsa3072,
    #[value(name = "4096")]
    Rsa4096,
}

#[derive(Args)]
pub struct ArgsKeygen {
    /// RSA key size in bits
    #[arg(short, long, default_value = "2048", value_name = "BITS")]
    pub size: KeygenSize,

    /// Output file (default: stdout)
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,
}

pub fn handle_keygen(args: &ArgsKeygen) -> color_eyre::Result<()> {
    let bits = match args.size {
        KeygenSize::Rsa2048 => 2048,
        KeygenSize::Rsa3072 => 3072,
        KeygenSize::Rsa4096 => 4096,
    };

    let key = RsaPrivateKey::generate(bits).map_err(JWKServeError::RsaKeyError)?;
    let output = key.to_pem().map_err(JWKServeError::RsaKeyError)?;

    show_output_or_save(args.output.as_ref(), &output)?;

    Ok(())
}
