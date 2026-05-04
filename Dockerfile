FROM alpine:3.23.4 AS builder

ARG TARGETARCH

RUN apk add --no-cache \
      build-base \
      ca-certificates \
      cargo \
      cmake \
      perl \
      rust

WORKDIR /app
COPY . .

RUN --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/root/.cargo/git \
    --mount=type=cache,target=/app/target \
    set -eux; \
    case "$TARGETARCH" in \
      arm64) prebuilt_binary="target/aarch64-unknown-linux-musl/release/jwkserve" ;; \
      amd64) prebuilt_binary="target/x86_64-unknown-linux-musl/release/jwkserve" ;; \
      *) echo "Unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    if [ -f "$prebuilt_binary" ]; then \
      cp "$prebuilt_binary" /tmp/jwkserve; \
    elif [ -f Cargo.toml ]; then \
      cargo build --release --locked; \
      cp target/release/jwkserve /tmp/jwkserve; \
    else \
      echo "Error: no source files or prebuilt binary found for architecture $TARGETARCH" >&2; \
      exit 1; \
    fi; \
    chmod +x /tmp/jwkserve

FROM alpine:3.23.4 AS default

RUN apk add --no-cache \
      ca-certificates \
      libgcc \
      libstdc++

COPY --from=builder /tmp/jwkserve /usr/local/bin/jwkserve
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENV RUST_LOG=info

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["serve", "--port", "3000", "--bind", "0.0.0.0"]
