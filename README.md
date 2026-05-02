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
- **Connected/unconnected modes**: `--debug-client-no-connect` leaves the client socket unconnected for diagnostics, while `--debug-upstream-no-connect` leaves the upstream socket unconnected and always sends via `send_to`.
- **Targeted debug logging**: repeat `--debug-log WHAT` for categories like `drops`, `handles`, or `packets`.
- **Payload limits**: enforce MTU-like behavior with `--max-payload`.
- **Stats**: periodic JSON lines show aggregate per-direction byte/packet counts and latency metrics. The `worker_flows` array provides per-worker details including locked status and client addresses.

Notable CLI options:

- `--max-payload N` – drop packets larger than `N` bytes.
- `--debug-client-no-connect` – leave the locked client socket unconnected (useful for relock or diagnostics).
- `--debug-upstream-no-connect` – leave the upstream socket unconnected and always send via `send_to`.
- `--debug-fast-stats` – shorten the stats cadence for tests or debugging.
- `--debug-log WHAT` – enable one debug category per flag; repeat for multiple categories.
- `--stats-interval-mins N` – periodic JSON stats interval (0 disables stats thread).
- `--icmp-sync-pps N` – global total best-effort ICMP sync request target in packets/s.
- `--reresolve-secs N` / `--reresolve-mode WHAT` – periodically re-resolve upstream, listener, both, or neither.
- `--user/--group NAME` (Unix) – drop privileges after binding low ports.

Worker flow modes:

- `shared-flow` keeps one global locked flow shared across all worker pairs.
- `single-flow` keeps worker-pair-local locked flows and worker-pair-local ICMP sync state.
- `single-flow` is still valid with `--workers 1`, but it has no distribution benefit there.

Dynamic `:0` semantics:

- `--here UDP:host:0` binds an ephemeral local UDP port.
- `--there UDP:host:port` still means a fixed remote UDP destination port.
- `--here ICMP:host:0` enables wildcard-learn ICMP listening and learns the peer ICMP ID on first lock.
- `--there ICMP:host:0` means a dynamic local ICMP source ID chosen by the kernel ping socket.
- Nonzero ICMP IDs remain fixed listener/peer IDs (on Linux/Android, requesting a fixed nonzero ICMP ID forces the use of privileged raw sockets).
- Policy-driven unconnected modes also exist:
  - FreeBSD timeout-drop forces the client/listener side unconnected.
  - Windows raw ICMP upstream forces the upstream side unconnected.

Re-resolve and worker behavior:

- `--reresolve-mode upstream` is the default; `listen`, `both`, and `none` are also supported.
- `shared-flow` keeps one global locked flow shared across all worker pairs.
- `single-flow` keeps worker-pair-local locked flows and worker-pair-local ICMP sync state.
- `--icmp-sync-pps` is a global total budget shared across all workers and flows, not a per-worker multiplier.

Build:

- `cargo build --release`

Run examples:

- `./target/release/pkthere --here UDP:0.0.0.0:5354 --there UDP:1.1.1.1:53`
- `./target/release/pkthere --here UDP:0.0.0.0:5354 --there UDP:one.one.one.one:53 --timeout-secs 45 --on-timeout drop`
- `./target/release/pkthere --here UDP:0.0.0.0:5354 --there UDP:[2606:4700:4700::1001]:53 --on-timeout exit`
- `./target/release/pkthere --here UDP:127.0.0.1:0 --there UDP:1.1.1.1:53`
- `./target/release/pkthere --here ICMP:0.0.0.0:1234 --there ICMP:8.8.8.8:33434 --debug-log drops --debug-log handles`
- `./target/release/pkthere --here ICMP:0.0.0.0:0 --there UDP:1.1.1.1:53`
- `./target/release/pkthere --here UDP:127.0.0.1:5354 --there ICMP:8.8.8.8:0`

Running Raw ICMP Tests Locally:

Integration tests require `pkthere` to have raw socket privileges (e.g. `setcap` on Linux or `setuid root` on macOS) to test fixed ICMP IDs. However, Cargo's freshness checks (triggered by code changes or environment variables like `PKTHERE_ALLOW_RAW_ICMP=1`) will overwrite the binary in `target/` and strip these privileges.

To run these tests reliably without Cargo interfering, copy the binary to an isolated name in the repository and use `TEST_APP_BIN`:

```bash
cargo build --release
cp target/release/pkthere target/release/pkthere-priv
sudo chown root target/release/pkthere-priv && sudo chmod u+s target/release/pkthere-priv
TEST_APP_BIN=target/release/pkthere-priv cargo test --release --test integration
```

Tests:

- CLI validation: `cargo test --test cli`
- Integration matrix (UDP/ICMP, IPv4/IPv6, connected/unconnected sockets, timeout watchdog, relock behavior): `cargo test --test integration`
- Stress runs: `cargo test --test stress`
