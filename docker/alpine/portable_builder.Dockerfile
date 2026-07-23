# syntax=docker/dockerfile:1.7

FROM alpine:latest@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS builder

RUN apk add --no-cache \
    bash \
    binutils \
    build-base \
    cargo \
    clang \
    file \
    git \
    linux-headers \
    lld \
    musl-dev \
    python3 \
    rust

WORKDIR /workspace
COPY . /workspace

ENV PKTHERE_PORTABLE_NATIVE_CONTAINER=1

RUN --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/root/.cargo/git \
    --mount=type=cache,target=/workspace/target \
    python3 -m docker.alpine.portable_build aarch64 \
    --backend native-container \
    --evidence-dir /artifacts/evidence \
    --output /artifacts/alpine

FROM scratch AS export
COPY --from=builder /artifacts/ /
