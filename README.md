# JWKServe

> A fake authentication service to speed up local development for JWT consumers.

**Use Case:** When building applications with a JWT authentication based on JWKS, it can be annoying to run real integration tests, especially locally or in pipelines, because it involves the usage of an existing identity provider. Using `jwkserve` you can easily generate JWT access tokens (for any combination of claims) and serve the JWKS relevant URL endpoints for easy integration.

Dedicated README files are available for:

* [jwkserve-cli](./src/jwkserve-cli/README.md)
* [jwkserve](./src/jwkserve/README.md)

Also available as [sbstjn/jwkserve on DockerHub](https://hub.docker.com/repository/docker/sbstjn/jwkserve/general).

## Common JWKS Flow

Assuming, you are writing a backend application and need to validate a JWT access token using JWKS, this is what you need to do when receiving a JWT access token:

* Verify the token contains two period separators, and
* Split the token into `Header.Payload.Signature` values.
* Base64 decode `Header`, `Payload`, and `Signature` , then
* Use `kid` in `Header` object as reference for needed key.
* Use `iss` in `Payload` to fetch the Discovery Endpoint at `/.well-known/openid-configuration` , then
* Parse JSON structure and use `jwks_uri` property as location for public keys.
* Fetch the provided JWKS Endpoint (usually at `/.well-known/jwks.json`), and
* Parse JSON structure and retrieve key with `kid` from JWT `Header` .

When writing automated tests for valid or invalid authentication (and maybe authorization) flows, it can become quite annoying to always have a __real__ identity provider in place. That's where `jwkserve` comes in handy: `jwkserve` serves the needed endpoints and allows easy generation of generic claims and token structures.

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

Regardless of how you use `jwkserve` , you need to know its used hostname and port. You need to configure your backend to allow access tokens from this issuer (in whatever your existing logic for this is hopefully already in place) and then, you can generate valid JWT access tokens:

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

In general, `jwkserve` is a token vending machine and blindly signs any payload as a valid JWT access token. This speeds up the process of writing integration tests in easy and especially complex scenarios with custom claims.

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

You can build and multiarch docker container:

```bash
# Docker Build
$ > docker build \
    --platform linux/arm64 --build-arg ARCH=arm64v8/ \
    -f Dockerfile . \
    -t jwkserve:latest
```

## Container

After building locally, you can run the container,

```bash
$ > docker run -it \
    -e APP_PORT=3000 \
    -e WEB_ISSUER=http://localhost:4000 \
    -p 4000:3000 \
    jwkserve:latest
```

### Docker Compose

You can use `jwkserve` with docker compose as well:

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