# syntax=docker/dockerfile:1.7

FROM rust:1.97.1-alpine@sha256:3c38f3f82c2f3d73da3b38e18d279393a04cb43ddded0e35088a8c3324d40900 AS builder

RUN apk add --no-cache \
    bash \
    binutils \
    build-base \
    clang \
    file \
    git \
    linux-headers \
    lld \
    musl-dev \
    python3

WORKDIR /workspace
COPY . /workspace

ENV PKTHERE_PORTABLE_NATIVE_CONTAINER=1
ARG PORTABLE_ARCHITECTURE=aarch64

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/workspace/target \
    python3 -m docker.alpine.portable_build "${PORTABLE_ARCHITECTURE}" \
    --backend native-container \
    --evidence-dir /artifacts/evidence \
    --output /artifacts/alpine

FROM scratch AS export
COPY --from=builder /artifacts/ /
