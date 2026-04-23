use super::implementation::{error, parse_evidence_key};
use super::model::VerificationError;
use crate::packet_diagnostics::DiagnosticLogIndex;
use crate::socket_reality::evidence::ForwarderEvidence;
use pkthere_socket_policy::SocketRole;
use serde_json::Value;
use socket2::Domain;
use std::net::SocketAddr;

pub(super) struct ForwarderKernelObservation {
    pub(super) kernel_addr: SocketAddr,
    pub(super) source_id: u16,
    pub(super) echo_id: u16,
    pub(super) ip_header_present: bool,
    pub(super) source_metadata_present: bool,
}

pub(super) fn verify_forwarder_kernel_evidence(
    evidence: &ForwarderEvidence,
    domain: Domain,
    role: SocketRole,
) -> Result<ForwarderKernelObservation, VerificationError> {
    for process in &evidence.processes {
        let diagnostics = DiagnosticLogIndex::parse(&process.stdout, &process.stderr)
            .map_err(|message| error(format!("{} diagnostics: {message}", process.label)))?;
        if let Some(observation) = find_observation(&diagnostics, domain, role)? {
            return Ok(observation);
        }
    }
    Err(error(
        "production forwarder logs have no generation-matched disjoint-ID RAW observation",
    ))
}

fn find_observation(
    diagnostics: &DiagnosticLogIndex,
    domain: Domain,
    role: SocketRole,
) -> Result<Option<ForwarderKernelObservation>, VerificationError> {
    for dump in diagnostics.packets() {
        let Some(key_value) = dump.value.pointer("/socket/evidence_key") else {
            continue;
        };
        let key = parse_evidence_key(key_value)?;
        if key.domain != domain || key.role != role {
            continue;
        }
        let kernel_addr = dump
            .value
            .pointer("/socket/local_kernel_addr")
            .and_then(Value::as_str)
            .ok_or_else(|| error("packet dump omitted local kernel address"))?
            .parse::<SocketAddr>()
            .map_err(|parse| error(format!("invalid kernel address: {parse}")))?;
        if !same_socket_generation(diagnostics, key_value, kernel_addr) {
            continue;
        }
        let source_id = icmp_id(&dump.value, "logical_source_id");
        let echo_id = icmp_id(&dump.value, "logical_destination_id");
        let (Some(source_id), Some(echo_id)) = (source_id, echo_id) else {
            continue;
        };
        if source_id == echo_id {
            continue;
        }
        return Ok(Some(ForwarderKernelObservation {
            kernel_addr,
            source_id,
            echo_id,
            ip_header_present: dump
                .value
                .pointer("/parse/headers/ip_version")
                .is_some_and(|value| !value.is_null()),
            source_metadata_present: dump
                .value
                .pointer("/receive/socket_source")
                .is_some_and(|value| !value.is_null()),
        }));
    }
    Ok(None)
}

fn same_socket_generation(
    diagnostics: &DiagnosticLogIndex,
    key_value: &Value,
    kernel_addr: SocketAddr,
) -> bool {
    diagnostics.socket_evidence().any(|line| {
        line.value.get("key") == Some(key_value)
            && line.value.get("getsockname").and_then(Value::as_str)
                == Some(kernel_addr.to_string().as_str())
    })
}

fn icmp_id(value: &Value, field: &str) -> Option<u16> {
    value
        .pointer(&format!("/parse/headers/icmp/{field}"))
        .and_then(Value::as_u64)
        .and_then(|id| u16::try_from(id).ok())
}
