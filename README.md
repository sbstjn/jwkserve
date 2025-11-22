# JWKServe

[![crates.io](https://img.shields.io/crates/v/jwkserve-cli.svg)](https://crates.io/crates/jwkserve-cli)
[![Docker Image Version](https://img.shields.io/docker/v/sbstjn/jwkserve?label=docker&color=%231D63ED)](https://hub.docker.com/repository/docker/sbstjn/jwkserve)
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE.md)
[![CI](https://github.com/sbstjn/jwkserve/actions/workflows/release.yml/badge.svg)](https://github.com/sbstjn/jwkserve/actions/workflows/release.yml)
[![CI](https://github.com/sbstjn/jwkserve/actions/workflows/build.yml/badge.svg)](https://github.com/sbstjn/jwkserve/actions/workflows/build.yml)

> A fake authentication service to speed up local development for JWT consumers.

**Use Case:** When building applications with a JWT authentication based on JWKS, it can be annoying to run real integration tests, especially locally or in pipelines, because it involves the usage of an existing identity provider. Using `jwkserve` you can easily generate JWT access tokens (for any combination of claims) and serve the JWKS relevant URL endpoints for easy integration.

Dedicated README files are available for:

* [jwkserve-cli](./src/jwkserve-cli/README.md)
* [jwkserve](./src/jwkserve/README.md)

Also available as [sbstjn/jwkserve on DockerHub](https://hub.docker.com/repository/docker/sbstjn/jwkserve/general).

## Common JWKS Flow

When validating a JWT access token using JWKS per [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519) and [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517):

* Verify the token contains two period separators
* Split the token into `Header.Payload.Signature` values
* Base64 decode `Header`, `Payload`, and `Signature`
* Use `kid` in `Header` object as reference for needed key
* Use `iss` in `Payload` to fetch the Discovery Endpoint at `/.well-known/openid-configuration`
* Parse JSON structure and use `jwks_uri` property as location for public keys
* Fetch the provided JWKS Endpoint (usually at `/.well-known/jwks.json`)
* Parse JSON structure and retrieve key with `kid` from JWT `Header`

When writing automated tests for authentication and authorization flows, requiring a real identity provider adds complexity. `jwkserve` serves the needed endpoints and allows easy generation of generic claims and token structures.

## Installation

```bash
# Install jwkserve binary
$ > cargo install jwkserve-cli

# Install jwkserve Library
$ > cargo add jwkserve

# Download jwkserve container
$ > docker pull sbstjn/jwkserve:latest
```

## Usage

Configure your backend to allow access tokens from `jwkserve`'s issuer (hostname and port). Then generate valid JWT access tokens:

```bash
$ > curl -X POST http://localhost:3000/sign \
    -H "Content-Type: application/json" \
    -d '{
        "aud": "my-app",
        "exp": 1735689600,
        "iat": 1704067200,
        "iss": "http://localhost:3000",
        "nbf": 1704067200,
        "sub": "user-12345"
    }'

{"token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUz …"}
```

`jwkserve` is a token vending machine that signs any payload as a valid JWT access token. This speeds up writing integration tests, especially in complex scenarios with different custom claims.

To enable the needed JWKS flow, `jwkserve` is serving two endpoints:

```bash
# OpenID Discovery Endpoint
$ > curl http://localhost:3000/.well-known/openid-configuration

{
  "issuer": "http://localhost:3000",
  "jwks_uri": "http://localhost:3000/.well-known/jwks.json"
}

# JWKS Key
$ > curl http://localhost:3000/.well-known/jwks.json

{
  "keys": [
    {
      "alg": "RS256",
      "e": "AQAB",
      "kid": "vB_ZfJ5y5E5PPMBUyaZxoPcmKxgaclK6ImLI-YkheEs",
      "kty": "RSA",
      "n": "2x2LkXrzc2DLo7tytA0ZfBq4KWpctpe67SWL7gcfDfG7mlKXTd6Rg05Hts8i7gLPCKb-iFKpm57n …",
      "use": "sig"
    }
  ]
}
```

On startup, `jwkserve` generates a new random key; if you need a persistent public key, you can pass a **PKCS8 .pem file** via `KEY_FILE` environment variable. More about this on the [jwkserve-cli README.md file](./src/jwkserve-cli/README.md).

## Build

You can build arm and x86 binaries:

```bash
# Build ARM
$ > cargo zigbuild --release -p jwkserve-cli --manifest-path ./src/Cargo.toml \
    --target aarch64-unknown-linux-gnu

# Build X86
$ > cargo zigbuild --release -p jwkserve-cli --manifest-path ./src/Cargo.toml \
    --target x86_64-unknown-linux-gnu
```

Build a multiarch Docker container:

```bash
# Docker Build
$ > docker build \
    --platform linux/arm64 --build-arg ARCH=arm64v8/ \
    -f Dockerfile . \
    -t jwkserve:latest
```

## Container

Run the container:

```bash
$ > docker run -it \
    -e APP_PORT=3000 \
    -p 4000:3000 \
    jwkserve:latest
```

### Docker Compose

Use `jwkserve` with Docker Compose:

```yaml
services:
  jwkserve:
    image: sbstjn/jwkserve:latest
    container_name: jwkserve
    ports:
      - 3000:3000
```

## Code Coverage

```bash
$ > cargo +nightly tarpaulin \
    --verbose --all-features --workspace --timeout 120 \
    --manifest-path ./src/Cargo.toml \
    --out xml
```
