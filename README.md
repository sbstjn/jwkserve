# JWKServe

> A fake authentication service to speed up local development for JWT consumers.

**Use Case:** When building applications with an JWT authentication based on JWKS, it can be annoying to run real integration tests, especially locally or in pipelines, because it involves the usage of an existing identity provider. Using `jwkserve` you can easily generate JWT access tokens (for any combination of claims) and serve the JWKS relevant URL endpoints for easy integration.

Dedicated README files are available for:

* [jwkserve-cli](./src/jwkserve-cli/README.md)
* [jwkserve](./src/jwkserve/README.md)

Also available as [sbstjn/jwkserve on DockerHub](https://hub.docker.com/repository/docker/sbstjn/jwkserve/general).

## Installation

```bash
# Install jwkserve binary
$ > cargo install jwkserve-cli

# Install jwkserve Library
$ > cargo add jwkserve

# Download jwkserve container
$ > docker pull sbstjn/jwkserve:latest
```

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

Afer building locally, you can run the container,

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