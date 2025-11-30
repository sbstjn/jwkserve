use clap::{Parser, Subcommand};

use jwkserve::commands::{
    keygen::{handle_keygen, ArgsKeygen},
    serve::{handle_serve, ArgsServe},
    show::{handle_show, ArgsShow},
    verify::{handle_verify, ArgsVerify},
};

#[derive(Parser)]
#[command(
    name = "jwkserve",
    about = "A CLI tool for serving JWKS files and generating keys",
    author = "jwkserve contributors",
    version = env!("CARGO_PKG_VERSION"),
    propagate_version = true
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Serve JWKS endpoint with JWT signing capabilities
    Serve(ArgsServe),

    /// Generate RSA cryptographic keys for JWT signing
    Keygen(ArgsKeygen),

    /// Display RSA key from private key file (public or private)
    Show(ArgsShow),

    /// Verify JWT token by fetching JWKS from issuer
    Verify(ArgsVerify),
}

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    // Initialize color-eyre for better error reporting
    color_eyre::install()?;

    // Initialize tracing subscriber with env filter and improved formatting
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("debug")),
        )
        .with_target(false)
        .compact()
        .init();

    let cli = Cli::parse();

    match &cli.command {
        Commands::Keygen(args) => handle_keygen(args)?,
        Commands::Serve(args) => handle_serve(args).await?,
        Commands::Show(args) => handle_show(args).await?,
        Commands::Verify(args) => handle_verify(args).await?,
    }

    Ok(())
}
