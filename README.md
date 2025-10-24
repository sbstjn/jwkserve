# JWKServe

> A fake authentication service to speed up local development for JWT consumers.

This simple HTTP server provides several endpoints for JWT development:

- `GET /` - Health check and service status
- `GET /.well-known/openid-configuration` - OpenID Connect discovery
- `GET /.well-known/jwks.json` - JSON Web Key Set
- `POST /sign` - Generate JWT tokens

## Quick Start

```bash
# Start the service
$ > APP_HOST=127.0.0.1 APP_PORT=3000 jwkserve

# In another terminal, test the endpoints
$ > curl http://127.0.0.1:3000/
$ > curl http://127.0.0.1:3000/.well-known/jwks.json
$ > curl http://127.0.0.1:3000/.well-known/openid-configuration
```

## API Reference

```json
// .well-known/openid-configuration

{
  "issuer": "http://127.0.0.1:3000",
  "jwks_uri": "http://127.0.0.1:3000/.well-known/jwks.json"
}
```

```json
// .well-known/jwks.json

{
  "keys": [
    {
      "kid": "pY72ZDcX8onWVKe-uzjlL5KibL1QHdkv1Qg0VFu7jx8",
      "kty": "RSA",
      "alg": "RS256",
      "use": "sig",
      "n": "w7-oH4kc2uELhZR9dnHAuwa6vM …",
      "e": "AQAB"
    }
  ]
}
```

## Token Generation

When having `jwkserve` running, you can generate a JWT with matching signature using curl e.g.

```bash
$ > curl -X POST http://127.0.0.1:3000/sign \
    -H "Content-Type: application/json" \
    -d '{
        "aud": "my-app",
        "exp": 1735689600,
        "iat": 1704067200,
        "iss": "my-issuer",
        "nbf": 1704067200,
        "sub": "user-12345"
    }'

{"token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUz …"}
```

> **Note:** If the `iss` field is not set in your request, it will be automatically added matching the `WEB_ISSUER` envionment variable.

## Configuration

You can configure the service using environment variables:

- `APP_HOST` - HTTP listener host (default: `0.0.0.0`)
- `APP_PORT` - HTTP listener port (default: `3000`)
- `KEY_FILE` - Path to existing PKCS8 private key file (optional)
- `WEB_ISSUER` - HTTP address for issuer (default: `http://${APP_HOST}:${APP_PORT}`)

On start, the binary will generate a random 2048-bit RSA private key if no `KEY_FILE` is provided.


```bash
# Basic usage
$ > APP_PORT=3000 jwkserve

# With custom host and existing key
$ > KEY_FILE=fixtures/test-key-pkcs8.pem \
    HOST=127.0.0.1 PORT=3000 \
    jwkserve
```

## Build

```bash
# Build ARM
$ > cargo zigbuild --release -p service --manifest-path ./src/Cargo.toml \
    --target aarch64-unknown-linux-gnu

# Build X86
$ > cargo zigbuild --release -p service --manifest-path ./src/Cargo.toml \
    --target x86_64-unknown-linux-gnu

# Docker Build
$ > docker build \
    --platform linux/arm64 --build-arg ARCH=arm64v8/ \
    -f Dockerfile . \
    -t jwkserve:latest

$ > docker run -it \
    -e APP_PORT=3000 \
    -e WEB_ISSUER=http://localhost:4000 \
    -p 4000:3000 \
    jwkserve:latest
```

### Development

```bash
# Run Clippy
$ > cargo clippy \
    --manifest-path ./src/Cargo.toml \
    --fix
```

## Run

```bash
$ > docker run -it \
    -p 3000:3000 \
    sbstjn/jwkserve:latest
```

### Docker Compose

```yaml
services:
  jwkserve:
    image: sbstjn/jwkserve:latest
    container_name: jwkserve
    ports:
      - 3000:3000
```