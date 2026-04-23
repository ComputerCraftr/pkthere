use pkthere_socket_policy::{SocketEvidenceKey, SocketRole};
use socket2::Domain;
use std::net::SocketAddr;

pub(super) fn socket_evidence_json(
    key: SocketEvidenceKey,
    event: &'static str,
    requested: &str,
    kernel_addr: SocketAddr,
) -> serde_json::Value {
    crate::diagnostics::stamp(serde_json::json!({
        "event": "socket_evidence",
        "action": event,
        "key": socket_evidence_key_json(key),
        "requested": requested,
        "getsockname": kernel_addr.to_string(),
    }))
}

pub(crate) fn socket_evidence_key_json(key: SocketEvidenceKey) -> serde_json::Value {
    serde_json::json!({
        "process_id": key.process_id,
        "role": match key.role {
            SocketRole::Listener => "listener",
            SocketRole::Upstream => "upstream",
        },
        "domain": if key.domain == Domain::IPV4 {
            "ipv4"
        } else if key.domain == Domain::IPV6 {
            "ipv6"
        } else {
            "other"
        },
        "socket_slot": key.socket_slot,
        "generation": key.generation,
    })
}
