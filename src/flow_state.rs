use crate::diagnostics::PacketTraceId;
use crate::flow_key::{ClientFlowKey, SocketLegFlow};
use crate::net::framing_shim::{
    ChallengeControl, PoolGeneration, RejectedFrameEvidence, ResetRequired, SessionId, SessionKey,
};
use crate::net::managed_socket::ManagedWakePair;
use crate::net::payload::BufferedPayload;
use std::collections::VecDeque;
use std::num::NonZeroU64;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

const HANDSHAKE_RETRY_BASE: Duration = Duration::from_millis(10);
const HANDSHAKE_RETRY_MAX: Duration = Duration::from_millis(500);
const MAX_HANDSHAKE_RETRY_ATTEMPTS: u32 =
    maximum_handshake_retry_attempts(crate::cli::MAX_ICMP_HANDSHAKE_TIMEOUT_SECS);
pub(crate) const MAX_CONCURRENT_SESSION_CANDIDATES: usize = 2;
const CONTROL_SEND_POOL_CAPACITY: usize = MAX_CONCURRENT_SESSION_CANDIDATES + 1;
const MAX_STATELESS_RESET_CHALLENGES: usize = 64;
const ORDINAL_RETIREMENT_WINDOW_BITS: u32 = MAX_RECEIVE_SESSION_CANDIDATES as u32;
pub(crate) const MAX_RECEIVE_SESSION_CANDIDATES: usize =
    crate::cli::MAX_ICMP_SESSION_POOL_SIZE + MAX_CONCURRENT_SESSION_CANDIDATES;
pub(crate) const MAX_DRAINING_SESSIONS: usize = crate::cli::MAX_ICMP_SESSION_POOL_SIZE;
pub(crate) const ACTIVITY_LANE_BYTES: usize = size_of::<ActivityLane>();
const OBSERVATION_PHASE_MASK: u64 = 0b11;
const OBSERVATION_POLLING: u64 = 0b01;
const OBSERVATION_OBSERVED: u64 = 0b10;
const MAX_OBSERVATION_GENERATION: u64 = u64::MAX >> 2;
const CONTROL_OBSERVATION_WORDS: usize = 16;
pub(crate) const CONTROL_OBSERVATION_LANE_BYTES: usize = size_of::<ControlObservationLane>();
const NO_MAINTENANCE_DEADLINE: u64 = u64::MAX;
pub(crate) const SESSION_MAINTENANCE_FALLBACK: Duration = Duration::from_millis(50);
const _: () = assert!(MAX_HANDSHAKE_RETRY_ATTEMPTS < u16::MAX as u32 + 1);

const fn maximum_handshake_retry_attempts(timeout_seconds: u64) -> u32 {
    let deadline_ms = timeout_seconds.saturating_mul(1_000);
    let mut elapsed_ms = 0_u64;
    let mut attempts = 0_u32;
    while elapsed_ms <= deadline_ms {
        attempts += 1;
        let uncapped_exponent = attempts.saturating_sub(1);
        let exponent = if uncapped_exponent < 6 {
            uncapped_exponent
        } else {
            6
        };
        let uncapped_delay_ms = 10_u64 << exponent;
        let delay_ms = if uncapped_delay_ms < 500 {
            uncapped_delay_ms
        } else {
            500
        };
        elapsed_ms = elapsed_ms.saturating_add(delay_ms);
    }
    attempts
}

pub(crate) struct FlowRuntimeState {
    /// Monotonic watchdog activity only. `FlowSessionState::flow` is the sole
    /// lock-state authority.
    activity_lanes: Box<[ActivityLane]>,
    /// Logical-flow generation for watchdog activity. Routine topology
    /// publication advances the flow gate epoch but must not erase the idle
    /// clock. Reset advances this generation so old-flow activity is excluded.
    activity_generation:
        crate::authority::AuthorityAtomic<crate::authority::tags::Activity, AtomicU64>,
    sessions:
        crate::authority::AuthorityMutex<crate::authority::tags::SessionControl, FlowSessionState>,
    published_admission: crate::authority::AuthorityMutex<
        crate::authority::tags::SessionControl,
        PublishedFlowSnapshot,
    >,
    control_observations: ControlObservationLanes,
    client_flow_reservation: crate::net::sock_mgr::transaction_lock::ManagerTransaction<
        crate::authority::tags::FlowReservation,
    >,
    topology: topology::FlowTopologyCoordinator,
    maintenance_epoch:
        crate::authority::AuthorityAtomic<crate::authority::tags::Maintenance, AtomicU64>,
    maintenance_epoch_exhausted:
        crate::authority::AuthorityAtomic<crate::authority::tags::Maintenance, AtomicBool>,
    maintenance_published_epoch:
        crate::authority::AuthorityAtomic<crate::authority::tags::Maintenance, AtomicU64>,
    maintenance_deadline_hint:
        crate::authority::AuthorityAtomic<crate::authority::tags::Maintenance, AtomicU64>,
    maintenance_repair_owner:
        crate::authority::AuthorityAtomic<crate::authority::tags::Maintenance, AtomicBool>,
    maintenance_publish: crate::authority::AuthorityMutex<crate::authority::tags::Maintenance, ()>,
    maintenance_origin: Instant,
    maintenance_wakes: Box<
        [crate::authority::AuthorityOnceLock<
            crate::authority::tags::Maintenance,
            Weak<MaintenanceWakeInner>,
        >],
    >,
    maintenance_wake_failures:
        crate::authority::AuthorityAtomic<crate::authority::tags::DiagnosticCounter, AtomicU64>,
}

mod observation_core;
#[cfg(all(test, loom, not(miri), not(target_env = "musl")))]
mod observation_core_loom;
#[cfg(test)]
mod observation_tests;
mod observations;
#[cfg(all(test, loom, not(miri), not(target_env = "musl")))]
mod receive_candidate_ack_loom;
mod recovery_core;
#[cfg(all(test, loom, not(miri), not(target_env = "musl")))]
mod recovery_core_loom;
mod session_lifecycles;
use observations::{ActivityLane, ControlObservationLane, ControlObservationLanes};
pub(crate) use observations::{
    ControlObservationGuard, ControlObservationReservation, ControlTransactionKey,
};

#[repr(align(128))]
struct MaintenanceWakeInner {
    pair: ManagedWakePair,
}

pub(crate) struct MaintenanceWakeRegistration {
    inner: Arc<MaintenanceWakeInner>,
}

impl MaintenanceWakeRegistration {
    pub(crate) fn receiver(&self) -> &std::net::UdpSocket {
        self.inner.pair.receiver()
    }

    pub(crate) fn drain(&self) -> std::io::Result<()> {
        self.inner.pair.drain()
    }
}

pub(crate) struct ClientFlowReservation<'a> {
    state: &'a FlowRuntimeState,
    topology: Option<FlowTopologyWriteReservation<'a>>,
    reservation: Option<
        crate::net::sock_mgr::transaction_lock::ManagerTransactionGuard<
            'a,
            crate::authority::tags::FlowReservation,
        >,
    >,
    expected_epoch: u64,
    publication_epoch: u64,
}

/// A topology phase borrowed from one live client-flow reservation.
///
/// Keeping the outer reservation borrowed prevents its FIFO token and topology
/// token from being completed, dropped, or transferred independently.
pub(crate) struct ClientFlowTopologyReservation<'reservation, 'state> {
    owner: &'reservation mut ClientFlowReservation<'state>,
    topology: topology::FlowTopologyWriteReservation<'state>,
}

mod reservation;
pub(crate) use reservation::{
    ClientFlowSocketTransitionsApplied, CommittedClientFlowTopology, PreparedClientFlowTopology,
};
mod topology;
mod topology_typestate;
#[cfg(all(test, loom, not(miri), not(target_env = "musl")))]
mod topology_typestate_loom;
#[cfg(test)]
pub(crate) use topology::FlowTopologyCoordinator;
pub(crate) use topology::{
    FLOW_READER_LANE_BYTES, FlowReaderLane, FlowTopologyError, FlowTopologyReadLease,
    FlowTopologyWriteReservation, ReleasedFlowOperationError,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FlowAuthorityError {
    Reservation(crate::net::sock_mgr::transaction_lock::ReservationError),
    Topology(FlowTopologyError),
}

impl FlowAuthorityError {
    pub(crate) const fn class(self) -> crate::runtime_support::FailureClass {
        match self {
            Self::Reservation(error) => error.class(),
            Self::Topology(error) => error.class(),
        }
    }
}

impl std::fmt::Display for FlowAuthorityError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Reservation(error) => {
                write!(
                    formatter,
                    "client-flow reservation validation failed: {error}"
                )
            }
            Self::Topology(error) => write!(formatter, "flow-topology completion failed: {error}"),
        }
    }
}

impl std::error::Error for FlowAuthorityError {}

impl From<crate::net::sock_mgr::transaction_lock::ReservationError> for FlowAuthorityError {
    fn from(error: crate::net::sock_mgr::transaction_lock::ReservationError) -> Self {
        Self::Reservation(error)
    }
}

impl From<FlowTopologyError> for FlowAuthorityError {
    fn from(error: FlowTopologyError) -> Self {
        Self::Topology(error)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum FlowMutationError<E> {
    Operation(E),
    Authority(FlowAuthorityError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecoveryPayloadRetention {
    Retained,
    AlreadyRetained,
    ActivationConfirmed,
    StaleSession,
    Occupied,
}

impl RecoveryPayloadRetention {
    pub(crate) const fn owns_recovery(self) -> bool {
        matches!(
            self,
            Self::Retained | Self::AlreadyRetained | Self::ActivationConfirmed
        )
    }
}

impl<E: std::fmt::Debug> std::fmt::Display for FlowMutationError<E> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Operation(error) => write!(formatter, "flow operation rejected: {error:?}"),
            Self::Authority(error) => error.fmt(formatter),
        }
    }
}

impl<E: std::fmt::Debug> std::error::Error for FlowMutationError<E> {}

impl<E> From<E> for FlowMutationError<E> {
    fn from(error: E) -> Self {
        Self::Operation(error)
    }
}

mod runtime;
pub(crate) use runtime::UpstreamRecoveryRequest;
mod session_authority;
use session_authority::{FlowPhase, FlowSessionState, LegSessions};

fn advance_nonwrapping_epoch(epoch: &mut u64, exhausted: &mut bool) {
    match epoch.checked_add(1) {
        Some(next) => *epoch = next,
        None => *exhausted = true,
    }
}

impl FlowSessionState {
    fn publish_upstream_pool_change(&mut self) {
        advance_nonwrapping_epoch(
            &mut self.upstream_pool.upstream_pool_epoch,
            &mut self.upstream_pool.upstream_pool_epoch_exhausted,
        );
    }

    fn has_flow_authority(&self) -> bool {
        self.authority.flow != FlowPhase::Unlocked
            || self.authority.client_flow.is_some()
            || self.authority.pending_icmp_client_lock.is_some()
            || self.client_pool.client_active_key.is_some()
            || self.upstream_pool.upstream_active_key.is_some()
            || self.authority.client_leg != LegSessions::default()
            || self.authority.upstream_leg != LegSessions::default()
    }

    fn invalidate_control_leases(&mut self) {
        advance_nonwrapping_epoch(
            &mut self.control.control_lease_epoch,
            &mut self.control.control_lease_epoch_exhausted,
        );
    }

    fn defer_peer_control(&mut self, control: DeferredPeerControl) -> bool {
        if let Some(existing) = self
            .upstream_recovery
            .upstream_deferred_peer_controls
            .iter_mut()
            .find(|existing| existing.same_control(control))
        {
            existing.retain_earliest_observation(control);
            return true;
        }
        if self
            .upstream_recovery
            .upstream_deferred_peer_controls
            .iter()
            .any(|existing| existing.same_data_identity(control))
        {
            return false;
        }
        if self.upstream_recovery.upstream_deferred_peer_controls.len()
            >= MAX_RECEIVE_SESSION_CANDIDATES
        {
            return false;
        }
        self.upstream_recovery
            .upstream_deferred_peer_controls
            .push_back(control);
        true
    }

    fn reset(&mut self) -> Option<DroppedReplyIdHandshake> {
        self.invalidate_control_leases();
        let previous = std::mem::replace(
            &mut self.control.upstream_reply_id_handshake,
            ReplyIdHandshake::NotRequired,
        );
        let dropped = match previous {
            ReplyIdHandshake::Sending {
                mut commit,
                expected_ack_destination_id,
                instance,
                started_s,
                absolute_deadline,
                attempts,
                ..
            } => {
                commit.request_reset();
                self.control.upstream_reply_id_handshake = ReplyIdHandshake::Sending {
                    commit,
                    expected_ack_destination_id,
                    instance,
                    started_s,
                    absolute_deadline,
                    attempts,
                };
                None
            }
            ReplyIdHandshake::Committing {
                mut commit,
                control,
                expected_ack_destination_id,
                instance,
                started_s,
                absolute_deadline,
                ..
            } => {
                let payload = commit.payload().unwrap_or_else(|| {
                    crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
                        "committing reply-ID handshake lost buffered payload ownership"
                    ))
                });
                let dropped = DroppedReplyIdHandshake {
                    expected_ack_destination_id,
                    instance,
                    buffered_len: payload.payload_len(),
                    buffered_trace: payload.trace(),
                };
                commit.request_reset();
                self.control.upstream_reply_id_handshake = ReplyIdHandshake::Committing {
                    commit,
                    control,
                    expected_ack_destination_id,
                    instance,
                    started_s,
                    absolute_deadline,
                };
                Some(dropped)
            }
            other => {
                self.control.upstream_reply_id_handshake = other;
                take_pending_handshake_locked(&mut self.control.upstream_reply_id_handshake)
            }
        };
        self.authority.flow = FlowPhase::Unlocked;
        self.authority.client_leg = LegSessions::default();
        self.authority.upstream_leg = LegSessions::default();
        if !self.upstream_pool.upstream_ready_sessions.is_empty() {
            self.upstream_pool.upstream_ready_sessions.clear();
            self.publish_upstream_pool_change();
        }
        self.upstream_pool.clear_reserve_handshakes();
        self.upstream_pool.clear_generation_advance();
        self.control.upstream_pending_key = None;
        self.control.upstream_pending_challenge = None;
        self.client_pool.client_active_key = None;
        self.client_pool.client_staged_generation = None;
        self.upstream_pool.upstream_active_key = None;
        self.upstream_pool.upstream_pool_generation = None;
        self.client_pool.client_retired_ordinals = OrdinalRetirementWindow::default();
        self.upstream_pool.next_session_ordinal = 1;
        self.client_pool.client_ready_sessions.clear();
        self.client_pool.next_receive_installation_order = 0;
        self.client_pool.client_generation_authorization = None;
        self.client_pool.client_draining_sessions.clear();
        self.upstream_pool.upstream_draining_sessions.clear();
        self.authority.pending_icmp_client_lock = None;
        if let Some(recovery) = self.upstream_recovery.upstream_recovery_payload.as_mut()
            && matches!(
                recovery.send.request_timeout(),
                recovery_core::RecoveryTimeoutDecision::Remove
            )
        {
            self.upstream_recovery.upstream_recovery_payload = None;
        }
        self.upstream_recovery.upstream_same_generation_fallback = None;
        self.upstream_recovery
            .upstream_deferred_peer_controls
            .clear();
        self.upstream_recovery.upstream_activation_confirmed = false;
        self.authority.client_flow = None;
        self.authority.flow_claim_generation = None;
        self.reset_recovery.client_reset_challenge = None;
        self.reset_recovery
            .stateless_client_reset_challenges
            .clear();
        self.reset_recovery.stateless_reset_response_budgets.clear();
        self.authority.sync_payload.reset();
        dropped
    }

    fn earliest_maintenance_deadline(&self) -> Option<Instant> {
        let mut earliest = None;
        let mut include = |candidate: Instant| {
            earliest = Some(earliest.map_or(candidate, |current: Instant| current.min(candidate)));
        };
        match &self.control.upstream_reply_id_handshake {
            ReplyIdHandshake::Pending {
                absolute_deadline,
                control,
                ..
            } => {
                include(*absolute_deadline);
                include(control.next_attempt());
            }
            ReplyIdHandshake::Committing {
                absolute_deadline, ..
            }
            | ReplyIdHandshake::Sending {
                absolute_deadline, ..
            } => include(*absolute_deadline),
            ReplyIdHandshake::AckedRetryable {
                absolute_deadline,
                next_attempt,
                ..
            } => {
                include(*absolute_deadline);
                include(*next_attempt);
            }
            ReplyIdHandshake::NotRequired | ReplyIdHandshake::Acked { .. } => {}
        }
        for candidate in &self.upstream_pool.upstream_reserve_handshakes {
            include(candidate.control.deadline());
            include(candidate.control.next_attempt());
        }
        if let Some(advance) = &self.upstream_pool.upstream_generation_advance {
            include(advance.control.deadline());
            include(advance.control.next_attempt());
        }
        for candidate in &self.client_pool.client_ready_sessions {
            if candidate.ready_installation_order().is_none() {
                include(candidate.absolute_deadline());
            }
        }
        if let Some(authorization) = self.client_pool.client_generation_authorization {
            include(authorization.expires_at);
        }
        for draining in self
            .client_pool
            .client_draining_sessions
            .iter()
            .chain(self.upstream_pool.upstream_draining_sessions.iter())
        {
            include(draining.expires_at);
        }
        if let Some(recovery) = &self.upstream_recovery.upstream_recovery_payload {
            include(recovery.deadline);
            if let Some(when) = recovery.send.retry_deadline() {
                include(when);
            }
        }
        if let Some(challenge) = self.reset_recovery.client_reset_challenge {
            include(challenge.expires_at);
        }
        for challenge in &self.reset_recovery.stateless_client_reset_challenges {
            include(challenge.expires_at);
        }
        if let Some(pending) = self.authority.pending_icmp_client_lock {
            include(pending.deadline);
        }
        earliest
    }
}
mod session_state;
#[cfg(test)]
use session_state::fresh_nonzero_challenge_with;
use session_state::{
    DrainingSession, GenerationAdvanceHandshake, GenerationAuthorization, OrdinalRetirementWindow,
    ReadySession, ReceiveCandidate, RecoveryPayload, ReserveReplyIdHandshake, ResetResponseBudget,
    SameGenerationFallback, StatelessResetResponseBudget, active_session_count,
    expire_draining_sessions, fresh_nonzero_challenge, global_reset_response_budget,
    inspect_existing_reset_challenge, inspect_stateless_reset_challenge, push_draining_session,
    session_admission_snapshot, upstream_data_evidence, upstream_reset_matches,
};
pub(crate) use session_state::{
    FlowAdmissionSnapshot, FlowSnapshotCache, PacketFlowSnapshot, PacketSessionAdmission,
    PublishedFlowSnapshot, RecoveryPayloadSendCompletion, RecoveryPayloadSendLease,
    RecoveryPayloadSendToken, ResetChallenge, ResetChallengeIssue, ResetRecoveryMetricsSnapshot,
    SessionAdmissionSnapshot, SessionPoolMetricsSnapshot, SessionPoolSnapshot,
    SessionPoolStateSnapshot,
};
mod sync_slot;
use sync_slot::SyncPayloadSlot;
pub(crate) use sync_slot::{SyncSendCompletion, SyncSendLease};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PendingClientControl {
    Negotiate {
        reply_id: u16,
    },
    ChallengeNegotiate {
        reply_id: u16,
        receiver_generation: Option<PoolGeneration>,
    },
}

impl PendingClientControl {
    pub(crate) const fn from_control(
        control: crate::net::framing_shim::IcmpTunnelControl,
    ) -> Option<Self> {
        match control {
            crate::net::framing_shim::IcmpTunnelControl::Negotiate(negotiation) => {
                Some(Self::Negotiate {
                    reply_id: negotiation.reply_id(),
                })
            }
            crate::net::framing_shim::IcmpTunnelControl::ChallengeNegotiate(challenge) => {
                Some(Self::ChallengeNegotiate {
                    reply_id: challenge.reply_id(),
                    receiver_generation: challenge.receiver_generation(),
                })
            }
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PendingIcmpClientLock {
    pub(crate) flow_key: ClientFlowKey,
    pub(crate) listener_flow: SocketLegFlow,
    pub(crate) session_key: Option<SessionKey>,
    pub(crate) observed_control: Option<PendingClientControl>,
    pub(crate) reset_challenge: u64,
    pub(crate) reset_evidence: Option<RejectedFrameEvidence>,
}

impl PendingIcmpClientLock {
    #[inline]
    pub(crate) const fn session_id(self) -> Option<SessionId> {
        match self.session_key {
            Some(key) => Some(key.session_id()),
            None => None,
        }
    }

    pub(crate) fn full_observed_control(
        self,
    ) -> Option<crate::net::framing_shim::IcmpTunnelControl> {
        let session_key = self.session_key?;
        match self.observed_control? {
            PendingClientControl::Negotiate { reply_id } => {
                crate::net::framing_shim::ReplyIdNegotiation::negotiate_with_key_and_challenge(
                    reply_id,
                    session_key,
                    self.reset_challenge,
                )
                .map(crate::net::framing_shim::IcmpTunnelControl::Negotiate)
            }
            PendingClientControl::ChallengeNegotiate {
                reply_id,
                receiver_generation,
            } => crate::net::framing_shim::ChallengeControl::new(
                reply_id,
                NonZeroU64::new(self.reset_challenge)?,
                receiver_generation,
                self.reset_evidence?,
                session_key,
            )
            .map(crate::net::framing_shim::IcmpTunnelControl::ChallengeNegotiate),
        }
    }
}

#[derive(Clone, Copy)]
struct TimedPendingIcmpClientLock {
    candidate: PendingIcmpClientLock,
    transaction_key: ControlTransactionKey,
    started_s: u64,
    trace: PacketTraceId,
    deadline: Instant,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ExpiredPendingIcmpClientLock {
    pub(crate) candidate: PendingIcmpClientLock,
    pub(crate) started_s: u64,
    pub(crate) trace: PacketTraceId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PendingIcmpClientLockMismatch;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PendingIcmpClientLockSet {
    Started,
    Reused,
}

enum ReplyIdHandshake {
    NotRequired,
    Pending {
        expected_ack_destination_id: u16,
        instance: u64,
        started_s: u64,
        absolute_deadline: Instant,
        payload: BufferedPayload,
        control: session_lifecycles::ControlSendCore,
    },
    Committing {
        commit: handshake::commit_core::HandshakeCommitCore<BufferedPayload>,
        control: session_lifecycles::ControlSendCore,
        expected_ack_destination_id: u16,
        instance: u64,
        started_s: u64,
        absolute_deadline: Instant,
    },
    Sending {
        commit: handshake::commit_core::HandshakeCommitCore<BufferedPayload>,
        expected_ack_destination_id: u16,
        instance: u64,
        started_s: u64,
        absolute_deadline: Instant,
        attempts: u32,
    },
    AckedRetryable {
        commit: handshake::commit_core::HandshakeCommitCore<BufferedPayload>,
        expected_ack_destination_id: u16,
        instance: u64,
        started_s: u64,
        absolute_deadline: Instant,
        next_attempt: Instant,
        attempts: u32,
    },
    Acked {
        instance: u64,
    },
}

#[derive(Clone)]
struct SentControlSequences {
    bitmap: Box<[u64; Self::WORD_COUNT]>,
}

impl SentControlSequences {
    const WORD_COUNT: usize = (u16::MAX as usize + 1) / u64::BITS as usize;

    fn insert(&mut self, sequence: u16) -> Result<(), ReplyIdHandshakeInvariantError> {
        let index = usize::from(sequence);
        let bit = 1_u64 << (index % u64::BITS as usize);
        let Some(word) = self.bitmap.get_mut(index / u64::BITS as usize) else {
            return Err(ReplyIdHandshakeInvariantError);
        };
        if *word & bit != 0 {
            return Err(ReplyIdHandshakeInvariantError);
        }
        *word |= bit;
        Ok(())
    }

    fn contains(&self, sequence: u16) -> bool {
        let index = usize::from(sequence);
        self.bitmap
            .get(index / u64::BITS as usize)
            .is_some_and(|word| *word & (1_u64 << (index % u64::BITS as usize)) != 0)
    }

    fn remove(&mut self, sequence: u16) -> bool {
        let index = usize::from(sequence);
        let bit = 1_u64 << (index % u64::BITS as usize);
        let Some(word) = self.bitmap.get_mut(index / u64::BITS as usize) else {
            return false;
        };
        let existed = *word & bit != 0;
        *word &= !bit;
        existed
    }

    fn is_empty(&self) -> bool {
        self.bitmap.iter().all(|word| *word == 0)
    }

    fn clear(&mut self) {
        self.bitmap.fill(0);
    }
}

impl Default for SentControlSequences {
    fn default() -> Self {
        Self {
            bitmap: Box::new([0; Self::WORD_COUNT]),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ClientCandidateAckLease {
    session_key: SessionKey,
    permit: session_lifecycles::ReceiveCandidateAckPermit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DeferredPeerControl {
    ResetRequired {
        control: ResetRequired,
        observed_at: Instant,
    },
    SessionActivated {
        control: crate::net::framing_shim::SessionActivated,
        observed_at: Instant,
    },
}

impl DeferredPeerControl {
    pub(crate) fn same_control(self, other: Self) -> bool {
        match (self, other) {
            (
                Self::ResetRequired { control: left, .. },
                Self::ResetRequired { control: right, .. },
            ) => left == right,
            (
                Self::SessionActivated { control: left, .. },
                Self::SessionActivated { control: right, .. },
            ) => left == right,
            _ => false,
        }
    }

    fn same_data_identity(self, other: Self) -> bool {
        match (self, other) {
            (
                Self::ResetRequired { control: left, .. },
                Self::ResetRequired { control: right, .. },
            ) => {
                left.rejected_session() == right.rejected_session()
                    && left.rejected_sequence() == right.rejected_sequence()
            }
            (
                Self::SessionActivated { control: left, .. },
                Self::SessionActivated { control: right, .. },
            ) => {
                left.session_key().session_id() == right.session_key().session_id()
                    && left.accepted_sequence() == right.accepted_sequence()
            }
            (left, right) => {
                let (left_session, left_sequence) = left.data_identity();
                let (right_session, right_sequence) = right.data_identity();
                left_session == right_session && left_sequence == right_sequence
            }
        }
    }

    fn data_identity(self) -> (SessionId, u16) {
        match self {
            Self::ResetRequired { control, .. } => {
                (control.rejected_session(), control.rejected_sequence())
            }
            Self::SessionActivated { control, .. } => (
                control.session_key().session_id(),
                control.accepted_sequence(),
            ),
        }
    }

    pub(crate) fn retain_earliest_observation(&mut self, other: Self) {
        let other_observed_at = other.observed_at();
        match self {
            Self::ResetRequired { observed_at, .. }
            | Self::SessionActivated { observed_at, .. } => {
                *observed_at = (*observed_at).min(other_observed_at);
            }
        }
    }

    fn observed_at(self) -> Instant {
        match self {
            Self::ResetRequired { observed_at, .. }
            | Self::SessionActivated { observed_at, .. } => observed_at,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ReplyIdHandshakeCommitToken {
    instance: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ReplyIdHandshakeInvariantError;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum UpstreamSessionRecovery {
    Deferred,
    Ignored,
    Recovered {
        handshake: ReplyIdHandshakeBegin,
        retired_sessions: Vec<SessionId>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReplyIdHandshakeTransitionError {
    StaleToken,
    InvalidPhase,
}

#[derive(Debug)]
pub(crate) enum HandshakeRollbackOutcome {
    Retryable,
    TimedOut { payload: BufferedPayload },
    ResetApplied { payload: BufferedPayload },
}

pub(crate) type ReplyIdPayloadSendLease =
    handshake::commit_core::HandshakePayloadLease<BufferedPayload>;
pub(crate) type ReplyIdHandshakeManagerReceipt = handshake::commit_core::HandshakeManagerReceipt;
pub(crate) type ReplyIdHandshakeActivationLease = handshake::commit_core::HandshakeActivationLease;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ReplyIdControlSendLease {
    pub(crate) expected_ack_destination_id: u16,
    pub(crate) session_key: SessionKey,
    pub(crate) session_id: SessionId,
    pub(crate) reset_challenge: u64,
    pub(crate) control: crate::net::framing_shim::IcmpTunnelControl,
    control_lease_epoch: u64,
    attempt: session_lifecycles::ControlSendAttempt,
    reserve: bool,
    generation_advance: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReplyIdControlSendCompletion {
    RetryScheduled,
    HandshakeAdvanced,
    ResetWon,
    Stale,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReplyIdControlSequenceRecord {
    Recorded,
    HandshakeAdvanced,
    ResetWon,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ReplyIdHandshakeBegin {
    Started {
        expected_ack_destination_id: u16,
        instance: u64,
        buffered_len: usize,
        buffered_trace: Option<PacketTraceId>,
    },
    PendingReused {
        expected_ack_destination_id: u16,
        instance: u64,
        started_s: u64,
        buffered_len: usize,
        buffered_trace: Option<PacketTraceId>,
        trigger_trace: Option<PacketTraceId>,
    },
    Ignored,
}

impl ReplyIdHandshakeBegin {
    #[inline]
    pub(crate) const fn should_send_control(&self) -> bool {
        matches!(self, Self::Started { .. })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReplyIdHandshakeAckIgnored {
    NoPending {
        trigger_trace: Option<PacketTraceId>,
    },
    AlreadyAcked {
        trigger_trace: Option<PacketTraceId>,
    },
    WrongDestinationId {
        expected_ack_destination_id: u16,
        buffered_trace: Option<PacketTraceId>,
        trigger_trace: Option<PacketTraceId>,
    },
    WrongInstance {
        expected_instance: u64,
        observed_instance: u64,
        buffered_trace: Option<PacketTraceId>,
        trigger_trace: Option<PacketTraceId>,
    },
    UnsentSequence {
        observed_sequence: u16,
        buffered_trace: Option<PacketTraceId>,
        trigger_trace: Option<PacketTraceId>,
    },
    CommitInProgress {
        trigger_trace: Option<PacketTraceId>,
    },
    Expired {
        buffered_trace: Option<PacketTraceId>,
        trigger_trace: Option<PacketTraceId>,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ReplyIdHandshakeAck {
    Matched {
        token: ReplyIdHandshakeCommitToken,
        instance: u64,
        expected_ack_destination_id: u16,
        buffered_len: usize,
        buffered_trace: Option<PacketTraceId>,
        trigger_trace: Option<PacketTraceId>,
    },
    ReserveReady {
        instance: u64,
        expected_ack_destination_id: u16,
        trigger_trace: Option<PacketTraceId>,
    },
    Ignored(ReplyIdHandshakeAckIgnored),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ExpiredReplyIdHandshake {
    pub(crate) expected_ack_destination_id: u16,
    pub(crate) instance: u64,
    pub(crate) started_s: u64,
    pub(crate) buffered_len: usize,
    pub(crate) buffered_trace: Option<PacketTraceId>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DroppedReplyIdHandshake {
    pub(crate) expected_ack_destination_id: u16,
    pub(crate) instance: u64,
    pub(crate) buffered_len: usize,
    pub(crate) buffered_trace: Option<PacketTraceId>,
}

mod handshake;
pub(crate) use handshake::{PreparedControlSend, PreparedReplyIdHandshake};
use handshake::{
    ack_handshake, begin_handshake, commit_handshake_session, complete_handshake_activation,
    complete_handshake_control_send, complete_handshake_send, expire_handshake,
    lease_due_handshake_control, lease_due_handshake_payload, mark_handshake_manager_published,
    poison_handshake_activation, release_handshake_send, release_unsequenced_handshake_control,
    rollback_handshake, take_pending_handshake_locked,
};

mod session_pool;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod test_support;

#[cfg(test)]
mod session_pool_tests;

#[cfg(test)]
mod recovery_tests;
