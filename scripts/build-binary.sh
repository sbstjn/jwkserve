#!/bin/bash

# Build ARM
cargo zigbuild --release \
    --target aarch64-unknown-linux-gnu

# Build X86
cargo zigbuild --release \
    --target x86_64-unknown-linux-gnu
