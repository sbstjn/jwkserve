#!/bin/bash

docker build \
    --platform linux/arm64 \
    -f Dockerfile . \
    -t jwkserve:latest