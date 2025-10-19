#!/bin/bash

# Build ARM
cargo zigbuild --release -p jwkserve-cli --manifest-path ./src/Cargo.toml \
    --target aarch64-unknown-linux-gnu

# Build X86
cargo zigbuild --release -p jwkserve-cli --manifest-path ./src/Cargo.toml \
    --target x86_64-unknown-linux-gnu

# Docker Build
docker build \
    --platform linux/arm64 --build-arg ARCH=arm64v8/ \
    -f Dockerfile . \
    -t jwkserve:latest