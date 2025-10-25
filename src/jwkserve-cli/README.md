# JWKServe CLI

A fake authentication service to speed up local development for JWT consumers.

This HTTP server provides several endpoints for JWT development:

- `GET /` - Health check and service status
- `GET /.well-known/openid-configuration` - OpenID Connect discovery
- `GET /.well-known/jwks.json` - JSON Web Key Set
- `POST /sign` - Generate JWT tokens

Also available as [sbstjn/jwkserve on DockerHub](https://hub.docker.com/repository/docker/sbstjn/jwkserve/general) for easy usage. See [jwkserve](https://crates.io/crates/jwkserve) for the library; contribution is possible via [sbstjn/jwkserve on GitHub](https://github.com/sbstjn/jwkserve).

## Installation

```bash
$ > cargo install jwkserve-cli
```

## Quick Start

```bash
# Start the service
$ > jwkserve

# In another terminal, test the endpoints
$ > curl http://localhost:3000/
$ > curl http://localhost:3000/.well-known/jwks.json
$ > curl http://localhost:3000/.well-known/openid-configuration
```

## Token Generation

When having `jwkserve` running, you can generate a JWT with matching signature using curl e.g.

```bash
$ > curl -X POST http://localhost:3000/sign \
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

> **Note:** If the `iss` field is not set in your request, it will be automatically added matching the `WEB_ISSUER` environment variable.

## Configuration

You can configure the service using environment variables:

- `APP_HOST` - HTTP listener host (default: `0.0.0.0`)
- `APP_PORT` - HTTP listener port (default: `3000`)
- `KEY_FILE` - Path to existing PKCS8 private key file (optional)
- `WEB_ISSUER` - HTTP address for issuer (default: `http://${APP_HOST}:${APP_PORT}`)

On start, the binary will generate a random 2048-bit RSA private key if no `KEY_FILE` is provided.

```bash
# Basic usage
$ > jwkserve

# With custom host and existing key
$ > KEY_FILE=fixtures/test-key-pkcs8.pem \
    jwkserve
```
