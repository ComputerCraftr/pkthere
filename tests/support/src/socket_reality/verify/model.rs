use crate::socket_reality::case::{RealityCase, RealityOperation};
use pkthere_socket_policy::{
    CapabilityEvidenceId, DatagramDisconnectCapability, IcmpChecksumMode, ResolvedSocketPolicy,
    SocketCreationFailureClass, SocketCreationPlan, SocketEvidenceKey,
};
use std::fmt;
use std::net::SocketAddr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RawIdObservation {
    MismatchObserved,
    EqualObservedButNotProofOfTrust,
    EvidenceUnavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RawConnectedFilteringEvidence {
    NotMeasured,
    KernelRejectedWrongPeer,
    KernelDeliveredWrongPeer,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RawDestinationPacketInfoEvidence {
    NotMeasured,
    MatchingInterface,
    ConflictingInterface,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DerivedFacts {
    SocketUnavailable {
        failure_class: SocketCreationFailureClass,
        raw_os_error: Option<i32>,
    },
    Datagram {
        receiver: SocketAddr,
        sender: SocketAddr,
        source_metadata: SocketAddr,
        byte_count: usize,
    },
    ConnectedFilter {
        rejected_peer_filtered: bool,
        queued_wrong_peer_source_visible: bool,
        accepted_peer_delivered: bool,
    },
    DatagramDisconnect {
        attempt_count: usize,
        capability: DatagramDisconnectCapability,
        syscall_error_codes: Vec<Option<i32>>,
    },
    SocketDisconnect {
        evidence_id: CapabilityEvidenceId,
        association_clear_supported: bool,
        exact_local_bind_preserved: bool,
        reconnect_after_disconnect_supported: bool,
        peer_inspection_supported: bool,
        stale_receive_queue_isolated: bool,
    },
    IcmpDgram {
        requested_bind_id: u16,
        requested_echo_id: u16,
        kernel_reported_echo_id: u16,
        realized_echo_id: u16,
        wire_observed_echo_id: u16,
        sequence: u16,
        byte_count: usize,
    },
    IcmpDgramSharedId {
        socket_count: usize,
        shared_echo_id: u16,
        correlated_reply_count: usize,
    },
    ReusePortFanout {
        receiver_count: usize,
        received_flow_counts: Vec<usize>,
        kernel_flow_affinity_required: bool,
    },
    ListenerOwnerReplacement {
        supported: bool,
        receiver_count: usize,
        bound_addr: Option<SocketAddr>,
        relock_owner_peer: Option<SocketAddr>,
    },
    RawReceive {
        kernel_addr: SocketAddr,
        observed_source_id: u16,
        observed_echo_id: u16,
        ip_header_present: bool,
        source_metadata_present: bool,
        ipv4_header_included: Option<bool>,
        connected_filtering: RawConnectedFilteringEvidence,
        destination_packet_info: RawDestinationPacketInfoEvidence,
        icmp_checksum_authority: IcmpChecksumMode,
        id_observation: RawIdObservation,
    },
    RawFourId {
        client_source_id: u16,
        server_destination_id: u16,
        server_source_id: u16,
        client_reply_id: u16,
        evidence_keys: Vec<SocketEvidenceKey>,
    },
    Lifecycle {
        operation: RealityOperation,
        old_key: SocketEvidenceKey,
        new_key: SocketEvidenceKey,
        observed_probe_ids: Vec<u64>,
    },
}

#[derive(Clone, Debug)]
pub struct VerifiedReality {
    pub requested: RealityCase,
    pub creation_policy: SocketCreationPlan,
    pub policy: ResolvedSocketPolicy,
    pub facts: DerivedFacts,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerificationErrorKind {
    EvidenceMismatch,
    PolicyCapabilityContradiction,
    RequiredButUnavailable,
    UnsupportedByRuntime,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationError {
    pub kind: VerificationErrorKind,
    pub message: String,
}

impl fmt::Display for VerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for VerificationError {}
