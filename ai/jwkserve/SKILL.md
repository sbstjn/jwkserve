---
name: jwkserve-api
description: Interact with jwkserve to obtain or verify JWTs via OpenID discovery and JWKS. Use when generating test JWTs, calling jwkserve.com or a local jwkserve instance, or when the user mentions JWKS, JWT signing, or fake auth for development.
---

# jwkserve API

## When to use

Apply this skill when:

- Generating test or development JWTs without a real identity provider
- Writing integration tests that need JWKS-based JWT verification
- Calling jwkserve.com or a local jwkserve server from curl, scripts, or application code
- User mentions JWKS, JWT signing, OpenID discovery, or fake auth for local development

## Base URL

| Environment | Base URL |
|-------------|---------|
| Production | `https://jwkserve.com` |
| Local (default bind) | `http://127.0.0.1:3000` |
| Local (e.g. Docker with `--bind 0.0.0.0`) | `http://localhost:3000` |

Use a single configurable base URL (env var or constant) in code; substitute for the examples below.

## Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/.well-known/openid-configuration` | GET | Returns issuer and `jwks_uri` (OpenID discovery) |
| `/.well-known/jwks.json` | GET | Returns public keys (JWK set) for JWT verification |
| `/sign` | POST | Sign JSON claims with RS256; body = arbitrary JSON object |
| `/sign/{algorithm}` | POST | Sign with given algorithm (see below) |

**Algorithms** (path parameter case-insensitive): RS256, RS384, RS512, ES256, ES384, ES512.

**Sign request**: `Content-Type: application/json`. Body: any JSON object (JWT claims). If `iss` is omitted, the server sets it to the server issuer URL.

**Sign responses**:

- 200: `{ "token": "<jwt-string>" }`
- 400: `{ "error": "<message>" }` (e.g. unsupported algorithm)
- 500: `{ "error": "<message>" }` (e.g. signing failure)

**Limits**: Request body ≤ 1 MiB.

## Examples

### OpenID discovery

```bash
curl -s "https://jwkserve.com/.well-known/openid-configuration"
```

Example response: `{"issuer":"https://jwkserve.com","jwks_uri":"https://jwkserve.com/.well-known/jwks.json"}`

### JWKS (public keys)

```bash
curl -s "https://jwkserve.com/.well-known/jwks.json"
```

Returns a `keys` array of JWK objects (e.g. `kty`, `alg`, `kid`, `n`, `e` for RSA).

### Sign (default RS256)

```bash
curl -s -X POST "https://jwkserve.com/sign" \
  -H "Content-Type: application/json" \
  -d '{"sub":"user-123","exp":9999999999}'
```

Response: `{"token":"eyJ..."}`

### Sign with explicit algorithm

```bash
curl -s -X POST "https://jwkserve.com/sign/ES256" \
  -H "Content-Type: application/json" \
  -d '{"sub":"user-123","aud":"my-app","exp":9999999999,"iat":1704067200}'
```

### Quick one-liner (RS256, minimal claims)

```bash
curl -s -X POST https://jwkserve.com/sign -H "Content-Type: application/json" -d '{"sub":"user1","exp":9999999999}'
```

### Local server

Replace base URL with `http://127.0.0.1:3000` or `http://localhost:3000` when using a local instance (`jwkserve serve` or Docker).
