# JWKServe

A fake authentication service to speed up local development for JWT consumers.

This library is the core of [jwkserve-cli](https://crates.io/crates/jwkserve-cli). Use this library if you need a `poem` router that acts as an JWT / JWKS compatible authentication server.

```rust
use jwkserve::{key::Key, Router, RouterState};
use poem::{listener::TcpListener, Server};
use std::io::Error;
use tokio::signal;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let router_state = RouterState {
        issuer: format!("http://0.0.0.0:3000"),
        key: Key::new(),
    };

    let router = Router::with_state(router_state);

    Server::new(TcpListener::bind(format!("0.0.0.0:3000")))
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
```

Of course, you can use this with the `poem` test client as well:

```rust
let client = poem::test::TestClient::new(&router.poem);

let claims = serde_json::json!({
    "iss": "http://localhost:3000",
    "custom_field": "preserved"
});

let resp = client
    .post("/sign")
    .header("Content-Type", "application/json")
    .body(serde_json::to_string(&claims).unwrap())
    .send()
    .await;

let body = resp.0.into_body().into_string().await.unwrap();
let json: serde_json::Value = serde_json::from_str(&body).unwrap();
let token = json.get("token").unwrap().as_str().unwrap();
```

Now you can easily test you JWT authentication and authorization; including a full JWKS request flow.