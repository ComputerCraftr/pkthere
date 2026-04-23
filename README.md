# pkthere forwarder

Single-client L4 forwarder for UDP and ICMP (IPv4/IPv6) with a configurable idle timeout.<br>
Bind once, drop privileges, and forward traffic between a single local client and an upstream host.

- Locks to the first client (SocketAddr) that sends a packet (either UDP or ICMP Echo).
- Forwards client->upstream and upstream->client.
- Uses the listener socket for replies so the client always sees the same source port.
- If no traffic is seen for --timeout-secs (default 10), either:
  - drop: drop the locked client and accept a new one
  - exit: exit the program (status 0)

Protocols and behaviors:

- **UDP**: forwards datagrams unchanged and preserves source ports.
- **ICMP Echo**: adds payload to request/reply, supports both v4 and v6.
- **Platform ICMP sockets**: Linux and Android may use ICMP DGRAM sockets for collapsed-ID cases. Windows does not use ICMP DGRAM; it uses RAW ICMP sockets for forwarding and a separate capture path where packet capture is required.
- **Connected/unconnected modes**: `--debug-client-unconnected` leaves the client socket unconnected for diagnostics, while `--debug-upstream-unconnected` leaves the upstream socket unconnected and always sends via `send_to`.
- **Targeted debug logging**: repeat `--debug-log WHAT` for `drops`, `handshake`, `handles`, `packets`, or `packet-dump`.
- **Payload limits**: enforce MTU-like behavior with `--max-payload`.
- **Stats**: periodic JSON lines show aggregate per-direction byte/packet counts and latency metrics. The `worker_flows` array provides per-worker details including locked status and client addresses.

Notable CLI options:

- `--max-payload N` – drop packets larger than `N` bytes.
- `--debug-client-unconnected` – leave the locked client socket unconnected (useful for relock or diagnostics).
- `--debug-upstream-unconnected` – leave the upstream socket unconnected and always send via `send_to`.
- `--debug-fast-stats` – shorten the stats cadence for tests or debugging.
- `--debug-force-raw-icmp-wildcard-upstream` – test-only override that forces RAW for wildcard `--there ICMP:host:0` while keeping DGRAM-like collapsed/no-disjoint ID semantics.
- `--debug-log WHAT` – enable one debug category per flag; repeat for multiple categories. `handshake` emits structured reply-ID lifecycle transitions. `packet-dump` emits correlated receive/admission/disposition JSON with bounded hex bytes. Structured diagnostics use schema `2`; order records across stdout/stderr by `diagnostic_sequence`.
- `--icmp-handshake-timeout-secs N` – expire a pending reply-ID handshake after `N` seconds; defaults to `--timeout-secs`.
- `--stats-interval-mins N` – periodic JSON stats interval (0 disables stats thread).
- `--icmp-sync-pps N` – global total best-effort ICMP sync request target in packets/s.
- `--reresolve-secs N` / `--reresolve-mode WHAT` – periodically re-resolve upstream, listener, both, or neither.
- `--debug-reresolve-address-file PATH` – test-only revisioned JSON address source. It is inactive unless explicitly supplied and accepts only strictly increasing complete revisions via atomic file replacement.
- `--user/--group NAME` (Unix) – drop privileges after binding low ports.

Worker flow modes:

- `shared-flow` keeps one global locked flow shared across all worker pairs.
- `single-flow` keeps worker-pair-local locked flows and worker-pair-local ICMP sync state.
- `single-flow` is still valid with `--workers 1`, but it has no distribution benefit there.

Dynamic `:0` semantics:

- `--here UDP:host:0` binds an ephemeral local UDP port.
- `--there UDP:host:port` means a fixed remote UDP destination port.
- `--there UDP:host:port --there-source-id 0` requests a kernel ephemeral upstream UDP source port; a nonzero `--there-source-id` binds that source port when supported.
- `--here ICMP:host:0` enables wildcard-learn ICMP listening.
- Endpoint IDs are part of `UDP:host:id` and `ICMP:host:id`. For ICMP, that endpoint ID is the Echo destination/listen ID. `--here-source-id`/`--there-source-id` are logical sender endpoint IDs carried in tunnel packets and used for flow identity. `--here-reply-id`/`--there-reply-id` are local destination endpoints advertised only by session-control negotiation.
- For upstreams, `--there ICMP:host:9999 --there-source-id 40000 --there-reply-id 40001` sends as logical `40000 -> 9999` and negotiates replies back to `40001`.
- For listeners, `--here ICMP:host:9999 --here-source-id 7777` listens on `9999` and sends replies from logical source `7777`; the advertised reply destination defaults to the listen ID unless `--here-reply-id` is supplied.
- Explicit `0` for source or reply requests wildcard negotiation/generation. Omitted source/reply uses the normal realized local endpoint ID.
- The ICMP shim negotiates reply destination IDs only in session-control frames. User payload packets carry the sender source ID after the reply route is negotiated. The Echo identifier remains the hop-local destination ID. RAW/wildcard-capable sockets can preserve disjoint IDs; fixed DGRAM sockets may use the compact source-equals-Echo-ID form and reject unsupported disjoint reply negotiation with a clear error.
- On Linux, `--there ICMP:host:0` normally uses an ICMP DGRAM socket when no disjoint reply route is required; the kernel-assigned ICMP ID is the concrete local reply endpoint used in negotiation.
- `--debug-force-raw-icmp-wildcard-upstream` is reserved for raw integration topologies where DGRAM self-echo behavior is not equivalent to talking to a pkthere RAW wildcard listener; it uses RAW transport but one concrete local/remote ICMP ID like a no-disjoint DGRAM wildcard socket.
- Nonzero ICMP listen/remote IDs remain fixed listener/peer IDs (on Linux/Android, requesting a fixed nonzero ICMP ID forces the use of privileged raw sockets).
- Policy-driven unconnected modes also exist:
  - FreeBSD timeout-drop forces the client/listener side unconnected.
  - Windows raw ICMP upstream forces the upstream side unconnected.

Re-resolve behavior:

- `--reresolve-mode upstream` is the default; `listen`, `both`, and `none` are also supported.
- `--icmp-sync-pps` is a global total budget shared across all workers and flows, not a per-worker multiplier.

## Build

- `cargo build --release` builds for the current host operating system and architecture. On Apple Silicon, it produces a macOS AArch64 executable, not a Linux executable.
- Release builds use `opt-level=3`, fat LTO, and one codegen unit.
- Portable Linux-musl builds never enable native CPU tuning implicitly. The Python portable builder uses Rust's target baseline; the container-native portable profile deliberately uses `TARGET_CPU=generic`.
- Build scripts do not probe the network or runtime socket capabilities. Platform socket behavior is measured by runtime reality tests.

Choose the build path based on the host:

- **Apple Silicon local build**: use the container-native `linux/arm64` builder.
- **Independent CI cross-build**: use the pinned Cross backend.
- **x86_64 Linux host**: use the host `musl-gcc` builder.

### Portable AArch64 Linux-musl

Build the statically linked AArch64 artifact through the pinned Cross/Docker backend:

```bash
python3 -m docker.alpine.portable_build aarch64 \
  --evidence-dir cross-artifacts
```

The executable is written to:

```text
target/aarch64-unknown-linux-musl/release/pkthere
```

The command requires Docker, the pinned `cross` version used by CI, `file`, and GNU `readelf`.

### Portable x86_64 Linux-musl

Build the x86_64 artifact with the host musl toolchain:

```bash
python3 -m docker.alpine.portable_build x86_64 \
  --evidence-dir docker-artifacts
```

This requires:

- the `x86_64-unknown-linux-musl` Rust target;
- a compatible `musl-gcc`;
- `file` and GNU `readelf`.

### Container-native Linux-musl build

The checked-in Rust builder can produce a static musl executable for the container architecture. On Apple Silicon with a Linux/ARM64 Docker-compatible builder, such as Docker Desktop or Colima:

```bash
docker buildx build \
  --platform linux/arm64 \
  --file docker/rust_build/Dockerfile \
  --target export \
  --output type=local,dest=.artifacts/rust_build_portable \
  .
```

The default `portable` profile requires `TARGET_CPU=generic`. To produce an explicitly non-portable executable tuned for the CPU features exposed to the build container:

```bash
docker buildx build \
  --platform linux/arm64 \
  --file docker/rust_build/Dockerfile \
  --target export \
  --build-arg BUILD_PROFILE=cpu_tuned \
  --build-arg TARGET_CPU=native \
  --output type=local,dest=.artifacts/rust_build_cpu_tuned \
  .
```

The tuned executable may not run on other ARMv8 systems. The exported `out/evidence/build-profile.txt` records the selected profile and CPU.

### Artifact verification

Both `python3 -m docker.alpine.portable_build` and the `export` target in `docker/rust_build/Dockerfile` do the following:

- clear ambient Rust, compiler, and linker flags;
- perform a final linked release build;
- verify the expected ELF machine type;
- reject a `PT_INTERP` dynamic interpreter;
- reject `DT_NEEDED` shared-library dependencies;
- require `file` to identify a static or static-PIE executable.

A successful linker exit alone is not treated as proof of a portable static artifact.

### Host-only CPU tuning

For a local, non-distributable build, native CPU tuning may be enabled explicitly:

```bash
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

- Do not combine `target-cpu=native` with `--target`.
- Do not use it for portable or distributable artifacts.
- Inside Docker, Cross, Colima, or another virtual machine, `native` means the CPU features exposed to that guest, not the full host CPU.

Run examples:

- `./target/release/pkthere --here UDP:0.0.0.0:5354 --there UDP:1.1.1.1:53`
- `./target/release/pkthere --here UDP:0.0.0.0:5354 --there UDP:one.one.one.one:53 --timeout-secs 45 --on-timeout drop`
- `./target/release/pkthere --here UDP:0.0.0.0:5354 --there UDP:[2606:4700:4700::1001]:53 --on-timeout exit`
- `./target/release/pkthere --here UDP:127.0.0.1:0 --there UDP:1.1.1.1:53`
- `./target/release/pkthere --here ICMP:0.0.0.0:1234 --there ICMP:8.8.8.8:33434 --debug-log drops --debug-log handles`
- `./target/release/pkthere --here ICMP:0.0.0.0:0 --there UDP:1.1.1.1:53`
- `./target/release/pkthere --here UDP:127.0.0.1:5354 --there ICMP:8.8.8.8:0`

## Running RAW ICMP Tests Locally

Privileged tests require an isolated executable because a later Cargo build can overwrite a binary and remove its capabilities.

On Linux, grant only `CAP_NET_RAW` and run the shared test runner, which selects the supported privileged tests exactly:

```bash
cargo build --release
cp target/release/pkthere target/release/pkthere-priv
sudo setcap cap_net_raw+ep target/release/pkthere-priv

PKTHERE_ALLOW_RAW_ICMP=1 \
  TEST_APP_BIN=target/release/pkthere-priv \
  python3 .github/scripts/ci_test_runner.py native \
    --log native_tests_linux.log
```

macOS does not support Linux file capabilities. Use setuid only on the isolated test copy, then run privileged socket reality:

```bash
cargo build --release
cp target/release/pkthere target/release/pkthere-priv
sudo chown root target/release/pkthere-priv
sudo chmod u+s target/release/pkthere-priv

PKTHERE_ALLOW_RAW_ICMP=1 \
  TEST_APP_BIN=target/release/pkthere-priv \
  python3 .github/scripts/ci_test_runner.py raw-reality \
    --log raw_reality_macos.log
```

`PKTHERE_ALLOW_RAW_ICMP=1` is an explicit request to run privileged tests supported by the current platform. macOS supports privileged RAW sockets, but its loopback RAW input exposes reflected Echo Replies rather than locally emitted requests, so same-host pure-RAW forwarding topologies are not enabled there. The socket-reality test still exercises macOS RAW socket setup, receive layout, and policy.

## Tests

Run the normal workspace test suite:

```bash
cargo test --workspace --lib --bins --tests
cargo test --workspace --doc
```

Run formatting and lint checks:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Run source and architecture policy tests directly:

```bash
cargo test --test policy -- --nocapture
```

Useful focused targets:

- CLI validation: `cargo test --test cli`
- Integration matrix: `cargo test --test integration`
- Worker modes: `cargo test --test worker_modes`
- Stress tests: `cargo test --test stress`

Privileged RAW ICMP tests require an isolated privileged executable as described above.
