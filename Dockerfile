FROM amazonlinux:2023 AS builder

ARG TARGETARCH

ENV CARGO_HOME=/root/.cargo \
    PATH=/root/.cargo/bin:$PATH

RUN dnf install -y \
      ca-certificates \
      cmake \
      gcc \
      gcc-c++ \
      make \
      perl-core \
    && dnf clean all

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --profile minimal --default-toolchain stable

WORKDIR /app
COPY . .

RUN --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/root/.cargo/git \
    --mount=type=cache,target=/app/target \
    set -eux; \
    case "$TARGETARCH" in \
      arm64) prebuilt_binary="target/aarch64-unknown-linux-gnu/release/jwkserve" ;; \
      amd64) prebuilt_binary="target/x86_64-unknown-linux-gnu/release/jwkserve" ;; \
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

FROM amazonlinux:2023 AS default

COPY --from=builder /tmp/jwkserve /usr/local/bin/jwkserve
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENV RUST_LOG=info

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["serve", "--port", "3000", "--bind", "0.0.0.0"]
