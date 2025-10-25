use jwkserve::{key::Key, Router, RouterState};
use poem::{listener::TcpListener, Server};
use std::{env, io::Error};
use tokio::signal;

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_thread_ids(false)
        .with_thread_names(false)
        .init();

    let host: String = match env::var("APP_HOST") {
        Ok(host) => host,
        Err(_) => "0.0.0.0".to_string(),
    };

    let port: String = match env::var("APP_PORT") {
        Ok(port) => port,
        Err(_) => "3000".to_string(),
    };

    let key: Key = match env::var("KEY_FILE") {
        Ok(key_path) => Key::from_file(&key_path),
        Err(_) => Key::new(),
    };

    let router_state = RouterState { key };

    let router = Router::with_state(router_state);

    Server::new(TcpListener::bind(format!("{host}:{port}")))
        .name("jwkserve".to_string())
        .run_with_graceful_shutdown(
            router.poem,
            async move {
                let _ = signal::ctrl_c().await;
            },
            None,
        )
        .await
}
