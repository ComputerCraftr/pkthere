use crate::network::localhost_addr;
use socket2::Domain;
use std::net::IpAddr;

pub const SINGLE_CLIENT_PAYLOAD_V4: &[u8] = b"hello-through-forwarder";
pub const SINGLE_CLIENT_PAYLOAD_V6: &[u8] = b"hello-through-forwarder-v6";
pub const LEGIT_PAYLOAD_1: &[u8] = b"legit-payload-1";
pub const LEGIT_PAYLOAD_2: &[u8] = b"legit-payload-2";
pub const WRONG_CLIENT_PEER_PAYLOAD: &[u8] = b"wrong-client-peer";
pub const WRONG_UPSTREAM_PEER_PAYLOAD: &[u8] = b"wrong-upstream-peer";
pub const RELOCK_PAYLOAD_A: &[u8] = b"first-client";
pub const RELOCK_PAYLOAD_B: &[u8] = b"second-client";
pub const FORWARD_ERROR_PAYLOAD_A: &[u8] = b"forward-error-client-a";
pub const FORWARD_ERROR_PAYLOAD_B: &[u8] = b"forward-error-client-b";
pub const ICMP_SYNC_PAYLOAD: &[u8] = b"x";
pub const ICMP_CADENCE_PAYLOAD: &[u8] = b"sync-timeout-check";
pub const ICMP_STRAY_PAYLOAD: &[u8] = b"stray-packet";
pub const MULTIHOP_PAYLOAD: &[u8] = b"multihop-icmp-bridge";
pub const INDEPENDENT_IDS_PAYLOAD: &[u8] = b"independent-icmp-ids";
pub const MULTI_WORKER_SHARED_PAYLOAD: &[u8] = b"multi-worker-shared-flow";
pub const MULTI_WORKER_FOLLOWUP_PAYLOAD: &[u8] = b"multi-worker-followup";
pub const MULTI_WORKER_CANDIDATE_PREFIX: &[u8] = b"multi-worker-candidate-";
pub const LIFECYCLE_ACCEPTED_PAYLOAD: &[u8] = b"hello";
pub const LIFECYCLE_OVERSIZE_PAYLOAD: &[u8] = b"hello world this is long";
pub const LIFECYCLE_PENDING_FOLLOWUP_PAYLOAD: &[u8] = b"world";

pub const WRONG_PEER_TARGET_PORT_ID: u16 = 4141;
pub const WRONG_PEER_LEGIT_PORT_ID: u16 = 1111;
pub const WRONG_PEER_STRAY_PORT_ID: u16 = 2222;

pub const QUICK_STATS_TIMEOUT_SECS: u64 = 1;
pub const REALITY_RELOCK_TIMEOUT_SECS: u64 = 2;
pub const MULTIHOP_NODE_TIMEOUT_SECS: u64 = 3;
pub const MULTI_WORKER_TIMEOUT_SECS: u64 = 3;
pub const LIFECYCLE_NODE_TIMEOUT_SECS: u64 = 3;
pub const LIFECYCLE_HANDSHAKE_TIMEOUT_SECS: u64 = 1;
pub const LIFECYCLE_DEFERRED_HANDSHAKE_TIMEOUT_SECS: u64 = 3;

pub fn localhost_ip(family: Domain) -> IpAddr {
    localhost_addr(family, 0).ip()
}

pub fn udp_loopback_arg(family: Domain, port: u16) -> String {
    format!("UDP:{}", localhost_addr(family, port))
}
