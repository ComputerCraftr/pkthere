use super::implementation::error;
use super::model::{DerivedFacts, VerificationError};
use crate::socket_reality::case::{RealityCase, RealitySocketPath};
use crate::socket_reality::evidence::{
    CallResult, DatagramBindShape, DatagramDisconnectAttempt, DatagramDisconnectEvidence,
    SocketDisconnectEvidence,
};
use pkthere_socket_policy::{
    CapabilityEvidenceId, DatagramBindPreservation, DatagramDisconnectCapability,
    DatagramPortBindCapability, SocketPlatform,
};
use pkthere_wire::SupportedProtocol;
use socket2::Type;
use std::io;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AttemptFacts {
    association_clear_supported: bool,
    reconnect_after_disconnect_supported: bool,
    stale_receive_queue_isolated: bool,
    bind: DatagramBindPreservation,
}

pub(super) fn verify_socket(
    requested: RealityCase,
    evidence: &SocketDisconnectEvidence,
) -> Result<DerivedFacts, VerificationError> {
    let attempt = require_result(&evidence.attempt, "socket disconnect attempt")?;
    if requested.socket_path == RealitySocketPath::WindowsProtocolZeroCapture {
        require_result(
            &attempt.post_bind_setup,
            "protocol-zero SIO_RCVALL and IP_HDRINCL setup",
        )?;
    }
    let bound_before = require_result(&attempt.bound_before, "bound address before connect")?;
    let connected_local = require_result(&attempt.connected_local, "connected local address")?;
    let peer_before = require_result(&attempt.peer_before, "peer before disconnect")?;
    let peer_after = require_result(
        &attempt.peer_after_disconnect,
        "peer observation after disconnect",
    )?;
    let local_after = require_result(
        &attempt.local_after_disconnect,
        "local address after disconnect",
    )?;
    let peer_after_reconnect = require_result(
        &attempt.peer_after_reconnect,
        "peer observation after reconnect",
    )?;
    let local_after_reconnect = require_result(
        &attempt.local_after_reconnect,
        "local address after reconnect",
    )?;
    let peer_inspection_supported = peer_before.is_some();
    let association_clear_supported = peer_inspection_supported && peer_after.is_none();
    let exact_local_bind_preserved = local_after == bound_before;
    let reconnect_after_disconnect_supported = attempt.reconnect_result.is_ok()
        && peer_after_reconnect.is_some()
        && local_after_reconnect == connected_local;
    Ok(DerivedFacts::SocketDisconnect {
        evidence_id: socket_disconnect_evidence_id(requested)?,
        association_clear_supported,
        exact_local_bind_preserved,
        reconnect_after_disconnect_supported,
        peer_inspection_supported,
        // Generic socket evidence does not establish queue isolation. UDP has
        // a dedicated tagged-datagram probe; ICMP relies on session admission.
        stale_receive_queue_isolated: false,
    })
}

fn socket_disconnect_evidence_id(
    requested: RealityCase,
) -> Result<CapabilityEvidenceId, VerificationError> {
    let platform = SocketPlatform::current();
    match (
        platform,
        requested.protocol,
        requested.socket_type,
        requested.socket_path,
    ) {
        (_, SupportedProtocol::UDP, Type::DGRAM, RealitySocketPath::Datagram) => {
            Ok(CapabilityEvidenceId::DatagramUdpPlatformMatrix)
        }
        (
            SocketPlatform::Linux | SocketPlatform::Android,
            SupportedProtocol::ICMP,
            Type::DGRAM,
            RealitySocketPath::Datagram,
        ) => Ok(CapabilityEvidenceId::LinuxAndroidIcmpDatagram),
        (
            SocketPlatform::Macos | SocketPlatform::Ios,
            SupportedProtocol::ICMP,
            Type::DGRAM,
            RealitySocketPath::Datagram,
        ) => Ok(CapabilityEvidenceId::DarwinIcmpDatagram),
        (
            SocketPlatform::Windows,
            SupportedProtocol::ICMP,
            Type::RAW,
            RealitySocketPath::WindowsProtocolZeroCapture,
        ) => Ok(CapabilityEvidenceId::WindowsProtocolZeroRaw),
        (
            SocketPlatform::Linux | SocketPlatform::Android,
            SupportedProtocol::ICMP,
            Type::RAW,
            RealitySocketPath::RawIcmp,
        ) => Ok(CapabilityEvidenceId::LinuxRawIcmp),
        (
            SocketPlatform::Macos | SocketPlatform::Ios,
            SupportedProtocol::ICMP,
            Type::RAW,
            RealitySocketPath::RawIcmp,
        ) => Ok(CapabilityEvidenceId::DarwinRawIcmp),
        (
            SocketPlatform::Windows,
            SupportedProtocol::ICMP,
            Type::RAW,
            RealitySocketPath::RawIcmp,
        ) => Ok(CapabilityEvidenceId::WindowsRawIcmp),
        (
            SocketPlatform::Freebsd,
            SupportedProtocol::ICMP,
            Type::RAW,
            RealitySocketPath::RawIcmp,
        ) => Ok(CapabilityEvidenceId::FreebsdRawIcmp),
        _ => Err(error(format!(
            "socket disconnect evidence has no exact platform/path identity: platform={platform:?}, case={requested:?}"
        ))),
    }
}

pub(super) fn verify(
    evidence: &DatagramDisconnectEvidence,
) -> Result<DerivedFacts, VerificationError> {
    let concrete_ephemeral = verify_shape(evidence, DatagramBindShape::ConcreteEphemeralPort)?;
    let wildcard_ephemeral = verify_shape(evidence, DatagramBindShape::WildcardEphemeralPort)?;
    let concrete_fixed = verify_shape(evidence, DatagramBindShape::ConcreteFixedPort)?;
    let wildcard_fixed = verify_shape(evidence, DatagramBindShape::WildcardFixedPort)?;
    for observed in [wildcard_ephemeral, concrete_fixed, wildcard_fixed] {
        if concrete_ephemeral.association_clear_supported != observed.association_clear_supported
            || concrete_ephemeral.reconnect_after_disconnect_supported
                != observed.reconnect_after_disconnect_supported
        {
            return Err(error(format!(
                "datagram association behavior changed by requested bind form: baseline={concrete_ephemeral:?}, observed={observed:?}"
            )));
        }
    }
    let capability = DatagramDisconnectCapability {
        association_clear_supported: concrete_ephemeral.association_clear_supported,
        reconnect_after_disconnect_supported: concrete_ephemeral
            .reconnect_after_disconnect_supported,
        stale_receive_queue_isolated: [
            concrete_ephemeral,
            wildcard_ephemeral,
            concrete_fixed,
            wildcard_fixed,
        ]
        .into_iter()
        .all(|facts| facts.stale_receive_queue_isolated),
        ephemeral_port_bind: DatagramPortBindCapability {
            concrete_bind: concrete_ephemeral.bind,
            wildcard_bind: wildcard_ephemeral.bind,
        },
        fixed_port_bind: DatagramPortBindCapability {
            concrete_bind: concrete_fixed.bind,
            wildcard_bind: wildcard_fixed.bind,
        },
    };
    Ok(DerivedFacts::DatagramDisconnect {
        attempt_count: evidence.attempts.len(),
        capability,
        syscall_error_codes: evidence
            .attempts
            .iter()
            .map(|attempt| match &attempt.disconnect_result {
                CallResult::Ok(()) => None,
                CallResult::OsError(error) => error.raw_os_error,
            })
            .collect(),
    })
}

fn verify_shape(
    evidence: &DatagramDisconnectEvidence,
    bind_shape: DatagramBindShape,
) -> Result<AttemptFacts, VerificationError> {
    let mut attempts = evidence
        .attempts
        .iter()
        .filter(|attempt| attempt.bind_shape == bind_shape);
    let first = attempts.next().ok_or_else(|| {
        error(format!(
            "datagram disconnect evidence omitted {bind_shape:?} attempts"
        ))
    })?;
    let mut expected = classify(first, &evidence.sent_bytes)?;
    for attempt in attempts {
        let observed = classify(attempt, &evidence.sent_bytes)?;
        if observed.association_clear_supported != expected.association_clear_supported
            || observed.reconnect_after_disconnect_supported
                != expected.reconnect_after_disconnect_supported
            || observed.bind != expected.bind
        {
            return Err(error(format!(
                "{bind_shape:?} datagram disconnect postconditions changed between attempts: first={expected:?}, observed={observed:?}"
            )));
        }
        // Queue isolation is a universal safety capability. Every independent
        // attempt must prove it; one retained or indeterminate datagram
        // conservatively disables same-descriptor UDP relock.
        expected.stale_receive_queue_isolated &= observed.stale_receive_queue_isolated;
    }
    Ok(expected)
}

fn classify(
    attempt: &DatagramDisconnectAttempt,
    probe_payload: &[u8],
) -> Result<AttemptFacts, VerificationError> {
    if attempt.connected_local.port() != attempt.bound_before.port() {
        return Err(error(format!(
            "connected datagram changed its initial local port: bound={}, connected={}",
            attempt.bound_before, attempt.connected_local
        )));
    }
    let peer_after = require_result(
        &attempt.peer_after_disconnect,
        "peer observation after disconnect",
    )?;
    let local_after = require_result(
        &attempt.local_after_disconnect,
        "local address after disconnect",
    )?;
    let association_clear_supported = peer_after.is_none();
    let exact_local_bind_preserved = *local_after == attempt.bound_before;
    let local_port_preserved = local_after.port() == attempt.bound_before.port();
    let original_destination_receive_supported = match &attempt.receive_after_disconnect {
        CallResult::Ok(receive) => {
            receive.bytes == probe_payload && receive.source == Some(attempt.new_peer)
        }
        CallResult::OsError(error) if error.kind == io::ErrorKind::TimedOut => false,
        CallResult::OsError(error) => {
            return Err(error_message(
                "receive after disconnect",
                error.message.as_str(),
            ));
        }
    };
    let reconnect_after_disconnect_supported = attempt.reconnect_result.is_ok()
        && matches!(
            &attempt.peer_after_reconnect,
            CallResult::Ok(peer) if *peer == attempt.new_peer
        )
        && matches!(
            &attempt.peer_received_after_reconnect,
            CallResult::Ok(bytes) if bytes == probe_payload
        );
    let stale_receive_queue_isolated = match &attempt.queue_isolation {
        CallResult::Ok(queue) => {
            let saw_fresh = queue
                .received_after_reconnect
                .iter()
                .any(|packet| packet.bytes == queue.fresh_after_reconnect);
            let saw_stale = queue.received_after_reconnect.iter().any(|packet| {
                packet.bytes == queue.queued_before_disconnect
                    || packet.bytes == queue.queued_while_gate_closed
            });
            saw_fresh && !saw_stale
        }
        CallResult::OsError(_) => false,
    };
    if attempt.reconnect_result.is_ok()
        && !matches!(&attempt.local_after_reconnect, CallResult::Ok(_))
    {
        return Err(error("successful reconnect omitted its local address"));
    }
    Ok(AttemptFacts {
        association_clear_supported,
        reconnect_after_disconnect_supported,
        stale_receive_queue_isolated,
        bind: DatagramBindPreservation {
            exact_local_bind_preserved,
            local_port_preserved,
            original_destination_receive_supported,
        },
    })
}

fn require_result<'a, T>(
    result: &'a CallResult<T>,
    operation: &str,
) -> Result<&'a T, VerificationError> {
    match result {
        CallResult::Ok(value) => Ok(value),
        CallResult::OsError(os_error) => Err(error_message(operation, os_error.message.as_str())),
    }
}

fn error_message(operation: &str, message: &str) -> VerificationError {
    error(format!("{operation} failed: {message}"))
}
