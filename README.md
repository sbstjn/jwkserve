# JWKServe

[![crates.io](https://img.shields.io/crates/v/jwkserve.svg)](https://crates.io/crates/jwkserve)
[![Docker Image Version](https://img.shields.io/docker/v/sbstjn/jwkserve?label=docker&color=%231D63ED)](https://hub.docker.com/repository/docker/sbstjn/jwkserve)
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE.md)
[![CI](https://github.com/sbstjn/jwkserve/actions/workflows/release.yml/badge.svg)](https://github.com/sbstjn/jwkserve/actions/workflows/release.yml)
[![CI](https://github.com/sbstjn/jwkserve/actions/workflows/build.yml/badge.svg)](https://github.com/sbstjn/jwkserve/actions/workflows/build.yml)

> A fake authentication service to speed up local development for JWT consumers.

**Use Case:** When building applications with JWT authentication based on JWKS, it can be annoying to run real integration tests, especially locally or in pipelines, because it involves using an existing identity provider. Using `jwkserve` you can easily generate JWT access tokens (for any combination of claims) and serve the JWKS relevant URL endpoints for easy integration.

Available as [sbstjn/jwkserve on DockerHub](https://hub.docker.com/repository/docker/sbstjn/jwkserve/general).

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
$ > cargo install jwkserve

# OR: Download jwkserve container
$ > docker pull sbstjn/jwkserve:latest
```

## Usage

Basically, `jwkserve` is a token vending machine that signs any payload as a valid JWT access token. This speeds up writing integration tests, especially in complex scenarios with different custom claims. 

Depending on the installation path, you can use the binary:

```bash
# Use local binary
$ > jwkserve serve

INFO Starting jwkserve
INFO Generating new RSA-2048 key
INFO RSA key size: 2048 bits
INFO Server listening on 0.0.0.0:3000 for issuer http://localhost:3000
INFO Supported algorithms: [RS256]
```

or use the provided Docker container:

```bash
# Use docker container
$ > docker run -it \
    -p 3000:3000 \
    sbstjn/jwkserve:latest

INFO Starting jwkserve
INFO Generating new RSA-2048 key
INFO RSA key size: 2048 bits
INFO Server listening on 0.0.0.0:3000 for issuer http://localhost:3000
INFO Supported algorithms: [RS256]
```

Now, you can generate valid JWT access tokens:

```bash
$ > curl -X POST http://localhost:3000/sign \
    -H "Content-Type: application/json" \
    -d '{
        "aud": "my-app",
        "exp": 1735689600,
        "iat": 1704067200,
        "nbf": 1704067200,
        "sub": "user-12345"
    }'

{"token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUz …"}
```

### JWKS Flow

To enable the needed JWKS flow, `jwkserve` is serving two endpoints:

```bash
# OpenID Discovery Endpoint
$ > curl http://localhost:3000/.well-known/openid-configuration

{
  "issuer": "http://localhost:3000",
  "authorization_endpoint": "http://localhost:3000/authorize",
  "token_endpoint": "http://localhost:3000/token",
  "jwks_uri": "http://localhost:3000/.well-known/jwks.json",
  "response_types_supported": ["id_token", "token", "code"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "scopes_supported": ["openid", "profile", "email"],
  "claims_supported": ["sub", "iss", "aud", "exp", "iat", "name", "email"]
}

# JWKS Key
$ > curl http://localhost:3000/.well-known/jwks.json

{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "vB_ZfJ5y5E5PPMBUyaZxoPcmKxgaclK6ImLI-YkheEs-RS256",
      "alg": "RS256",
      "n": "2x2LkXrzc2DLo7tytA0ZfBq4KWpctpe67SWL7gcfDfG7mlKXTd6Rg05Hts8i7gLPCKb-iFKpm57n …",
      "e": "AQAB"
    }
  ]
}
```

### Custom RSA Key

By default, `serve` generates a new temporary RSA-2048 key on startup (~2s). For instant startup, use a persisted key:

```bash
# Generate key once, also available as key size 3072 and 4096
$ > jwkserve keygen --size 2048 --output key.pem

# Use pre-generated key (instant startup)
$ > jwkserve serve --key key.pem
```

For development, the test folder includes some fixtures:

```bash
$ > jwkserve serve --key tests/fixtures/example_2048.pem
```

### Custom Algorithm

When serving JWKS files, you can configure RS256, RS384, RS512 as supported algorithms:

```bash
# Use only RS256 by default
$ > jwkserve serve

# Use RS256 and RS512
$ > jwkserve serve --algorithm RS256 --algorithm RS512
```

The `/sign` endpoint for generating tokens supports signing algorithms as well. For flexible usage, signing is always possible using all three algorithms.

```bash
$ > curl -X POST http://localhost:3000/sign/RS384 \
    -H "Content-Type: application/json" \
    -d '{
        "aud": "my-app",
        "exp": 1735689600,
        "iat": 1704067200,
        "nbf": 1704067200,
        "sub": "user-12345"
    }'

{"token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUz …"}
```

## Build

You can build arm and x86 binaries:

```bash
# Build ARM
$ > cargo zigbuild --release --target aarch64-unknown-linux-gnu

# Build X86
$ > cargo zigbuild --release --target x86_64-unknown-linux-gnu
```

Build a Docker container:

```bash
# Docker build for ARM
$ > docker build \
    --platform linux/arm64 \
    -f Dockerfile . \
    -t jwkserve:latest
```

## Container

Run the container:

```bash
$ > docker run -it \
    -p 4000:3000 \
    jwkserve:latest
```

### Docker Compose

Use `jwkserve` with Docker Compose:

```yaml
services:
  jwkserve:
    image: sbstjn/jwkserve
    container_name: jwkserve
    ports:
      - "3000:3000"
    command: ["jwkserve", "serve", "--bind", "0.0.0.0"]
```

## Code Coverage

```bash
$ > cargo +nightly tarpaulin \
    --verbose --all-features --workspace --timeout 120 \
    --out xml
```
