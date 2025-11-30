FROM amazonlinux:2023 AS base

ARG TARGETARCH

RUN --mount=type=bind,source=./target/aarch64-unknown-linux-gnu/release,target=/mnt/arm \
    --mount=type=bind,source=./target/x86_64-unknown-linux-gnu/release,target=/mnt/x86 \
    if [ "$TARGETARCH" = "arm64" ] && [ -f /mnt/arm/jwkserve ]; then \
      cp /mnt/arm/jwkserve /usr/local/bin/jwkserve; \
    elif [ "$TARGETARCH" != "arm64" ] && [ -f /mnt/x86/jwkserve ]; then \
      cp /mnt/x86/jwkserve /usr/local/bin/jwkserve; \
    else \
      echo "Error: No service binary found for architecture!" >&2; \
      exit 1; \
    fi && \
    chmod +x /usr/local/bin/jwkserve

# Default version
FROM base AS default

ENV RUST_LOG=debug

CMD ["jwkserve", "serve", "--port", "3000", "--bind", "0.0.0.0"]