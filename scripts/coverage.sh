#!/bin/bash

cargo +nightly tarpaulin \
    --verbose --all-features --workspace --timeout 120 \
    --out xml