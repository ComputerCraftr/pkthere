use crate::endpoint::LogicalEndpoint;
use crate::flow_state::PendingIcmpClientLock;
use crate::net::payload::PayloadEvent;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct AdmittedWirePacket<'a> {
    pub(crate) trace: Option<crate::diagnostics::PacketTraceId>,
    pub(crate) normalized_source: Option<LogicalEndpoint>,
    pub(crate) event: PayloadEvent<'a>,
    pub(super) candidate: ClientAdmissionCandidate,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum ClientAdmissionKind {
    #[default]
    None,
    Lock,
    Negotiation,
    Reset,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct ClientAdmissionCandidate {
    kind: ClientAdmissionKind,
    candidate: Option<PendingIcmpClientLock>,
}

impl ClientAdmissionCandidate {
    pub(super) const fn none() -> Self {
        Self {
            kind: ClientAdmissionKind::None,
            candidate: None,
        }
    }

    pub(super) const fn lock(candidate: PendingIcmpClientLock) -> Self {
        Self {
            kind: ClientAdmissionKind::Lock,
            candidate: Some(candidate),
        }
    }

    pub(super) const fn negotiation(candidate: PendingIcmpClientLock) -> Self {
        Self {
            kind: ClientAdmissionKind::Negotiation,
            candidate: Some(candidate),
        }
    }

    pub(super) const fn reset(candidate: Option<PendingIcmpClientLock>) -> Self {
        Self {
            kind: ClientAdmissionKind::Reset,
            candidate,
        }
    }
}

impl AdmittedWirePacket<'_> {
    pub(crate) fn candidate_flow_key(&self) -> Option<crate::flow_key::ClientFlowKey> {
        self.candidate.candidate.map(|candidate| candidate.flow_key)
    }

    pub(crate) fn lock_candidate(&self) -> Option<PendingIcmpClientLock> {
        (self.candidate.kind == ClientAdmissionKind::Lock)
            .then_some(self.candidate.candidate)
            .flatten()
    }

    pub(crate) fn pending_negotiation(&self) -> Option<PendingIcmpClientLock> {
        (self.candidate.kind == ClientAdmissionKind::Negotiation)
            .then_some(self.candidate.candidate)
            .flatten()
    }

    pub(crate) fn reset_candidate(&self) -> Option<PendingIcmpClientLock> {
        (self.candidate.kind == ClientAdmissionKind::Reset)
            .then_some(self.candidate.candidate)
            .flatten()
    }

    pub(crate) fn unknown_session_for_reset(&self) -> bool {
        self.candidate.kind == ClientAdmissionKind::Reset
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum WirePacketRejection {
    Filtered(RejectedPacket),
    ReceiveNoise(ReceiveNoiseReason),
}

pub(crate) type WirePacketAdmission<'a> = Result<AdmittedWirePacket<'a>, WirePacketRejection>;
use super::transport::{ReceiveNoiseReason, RejectedPacket};
