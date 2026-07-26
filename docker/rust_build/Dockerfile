# syntax=docker/dockerfile:1.7

ARG RUST_IMAGE=rust:1.97.1-alpine@sha256:3c38f3f82c2f3d73da3b38e18d279393a04cb43ddded0e35088a8c3324d40900
ARG BUILD_PROFILE=portable
ARG TARGET_CPU=generic

# ---------- Toolchain (cached) ----------
FROM ${RUST_IMAGE} AS toolchain
RUN apk add --no-cache \
    bash \
    binutils \
    build-base \
    clang \
    file \
    findutils \
    git \
    linux-headers \
    lld \
    musl-dev
ARG BUILD_PROFILE
ARG TARGET_CPU
WORKDIR /src
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
ENV CC=clang \
    CXX=clang++ \
    PKTHERE_BUILD_PROFILE=${BUILD_PROFILE} \
    PKTHERE_TARGET_CPU=${TARGET_CPU} \
    RUSTFLAGS="-C linker=clang -C link-arg=-fuse-ld=lld -C link-arg=-Wno-unused-command-line-argument -C target-feature=+crt-static -C target-cpu=${TARGET_CPU}"

RUN case "$PKTHERE_BUILD_PROFILE" in \
    portable) \
    test "$PKTHERE_TARGET_CPU" = generic || { \
    echo "portable builds require TARGET_CPU=generic" >&2; \
    exit 1; \
    } \
    ;; \
    cpu_tuned) \
    test "$PKTHERE_TARGET_CPU" != generic || { \
    echo "cpu_tuned builds require an explicit non-generic TARGET_CPU" >&2; \
    exit 1; \
    } \
    ;; \
    *) \
    echo "BUILD_PROFILE must be portable or cpu_tuned" >&2; \
    exit 1; \
    ;; \
    esac \
    && rustc --print cfg -C "target-cpu=$PKTHERE_TARGET_CPU" >/tmp/target-cpu-cfg

# ---------- Build ----------
FROM toolchain AS builder
ARG TARGETARCH
WORKDIR /src/repo
COPY . /src/repo

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/repo/target \
    case "$TARGETARCH" in \
    arm64) rust_target=aarch64-unknown-linux-musl ;; \
    amd64) rust_target=x86_64-unknown-linux-musl ;; \
    *) echo "unsupported build architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac \
    && cargo build --locked --release --target "$rust_target" -p pkthere --bin pkthere \
    && install -D -m 0755 "target/$rust_target/release/pkthere" /artifacts/pkthere \
    && printf '%s\n' "$rust_target" > /artifacts/evidence-rust-target.txt

# ---------- Verify linked static ELF ----------
RUN mkdir -p /artifacts/evidence \
    && case "$(cat /etc/apk/arch)" in \
    aarch64) expected_machine='AArch64' ;; \
    x86_64) expected_machine='Advanced Micro Devices X86-64' ;; \
    *) echo "unsupported build architecture: $(cat /etc/apk/arch)" >&2; exit 1 ;; \
    esac \
    && printf 'build_profile=%s\ntarget_cpu=%s\n' \
    "$PKTHERE_BUILD_PROFILE" \
    "$PKTHERE_TARGET_CPU" \
    > /artifacts/evidence/build-profile.txt \
    && mv /artifacts/evidence-rust-target.txt /artifacts/evidence/rust-target.txt \
    && rustc -vV > /artifacts/evidence/rustc.txt \
    && cargo -V > /artifacts/evidence/cargo.txt \
    && file /artifacts/pkthere \
    | tee /artifacts/evidence/pkthere-file.txt \
    && readelf -hW /artifacts/pkthere \
    | tee /artifacts/evidence/pkthere-elf-header.txt \
    && readelf -lW /artifacts/pkthere \
    | tee /artifacts/evidence/pkthere-program-headers.txt \
    && readelf -dW /artifacts/pkthere \
    2>&1 | tee /artifacts/evidence/pkthere-dynamic.txt \
    && grep -Eq "^[[:space:]]*Machine:[[:space:]]*$expected_machine[[:space:]]*$" \
    /artifacts/evidence/pkthere-elf-header.txt \
    && grep -Eq 'statically linked|static-pie linked' \
    /artifacts/evidence/pkthere-file.txt \
    && ! grep -Eq '(^|[[:space:]])INTERP([[:space:]]|$)' \
    /artifacts/evidence/pkthere-program-headers.txt \
    && ! grep -Fq '(NEEDED)' \
    /artifacts/evidence/pkthere-dynamic.txt

# ---------- Export ----------
FROM scratch AS export
COPY --from=builder /artifacts/ /out/
