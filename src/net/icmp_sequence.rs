use crate::flow_state::SessionAdmissionSnapshot;
use crate::net::framing_shim::SessionId;
use crate::net::payload::IcmpPayloadMeta;
use std::collections::VecDeque;
use std::fmt;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

const REPLAY_WINDOW_BITS: usize = 2048;
const REPLAY_WINDOW_WORDS: usize = REPLAY_WINDOW_BITS / u64::BITS as usize;
const MAX_SEQUENCE_GENERATION: u64 = u64::MAX >> 16;
const MAX_TRACKED_TRANSMIT_SESSIONS: usize = crate::cli::MAX_ICMP_SESSION_POOL_SIZE + 3;
const MAX_TRACKED_RECEIVE_SESSIONS: usize = 1
    + crate::flow_state::MAX_RECEIVE_SESSION_CANDIDATES
    + crate::flow_state::MAX_DRAINING_SESSIONS;

const UNPUBLISHED_SEQUENCE: u32 = u32::MAX;
static NEXT_SEQUENCE_AUTHORITY_ID: crate::authority::AuthorityAtomic<
    crate::authority::tags::IdentityAllocation,
    AtomicU64,
> = crate::authority::AuthorityAtomic::new_u64(
    1,
    crate::authority::AtomicProtocolId::IdentityGeneration,
);

mod reservation;
mod send_completion;
#[cfg(all(test, loom, not(miri), not(target_env = "musl")))]
mod send_completion_loom;
mod send_completion_store;
pub(crate) use reservation::{
    OutboundDataProtocol, PreparedOutboundSession, outbound_data_reservation,
};
#[cfg(test)]
mod test_support;
#[cfg(test)]
pub(crate) use test_support::{
    publish_outbound_request_through, reserve_and_publish_outbound_request_seq,
    reserve_outbound_request_seq, reset_sequence_state, reset_sequence_state_and_seed_receive,
};

type ProductionCompletionCore = send_completion::SendCompletionCore<
    crate::authority::AuthorityAtomic<crate::authority::tags::ProtocolTransmit, AtomicU32>,
    crate::authority::AuthorityAtomic<crate::authority::tags::ProtocolTransmit, AtomicU64>,
    send_completion_store::ProductionDeferredStore,
    crate::flow_state::DeferredPeerControl,
>;

struct TransmitSequenceWindow {
    session_id: SessionId,
    latest_published_seq:
        crate::authority::AuthorityAtomic<crate::authority::tags::ProtocolTransmit, AtomicU32>,
    completion: ProductionCompletionCore,
    activation_recovery_claimed:
        crate::authority::AuthorityAtomic<crate::authority::tags::ProtocolTransmit, AtomicBool>,
}

impl TransmitSequenceWindow {
    fn new(session_id: SessionId, authority_flow: u64) -> Self {
        Self {
            session_id,
            latest_published_seq: crate::authority::AuthorityAtomic::new_u32(
                UNPUBLISHED_SEQUENCE,
                crate::authority::AtomicProtocolId::TransmitCompletion,
            ),
            completion: ProductionCompletionCore::new(
                usize::from(u16::MAX) + 1,
                crate::cli::MAX_FORWARDING_THREADS,
                |capacity| {
                    send_completion_store::production_deferred_store(capacity, authority_flow)
                },
            ),
            activation_recovery_claimed: crate::authority::AuthorityAtomic::new_bool(
                false,
                crate::authority::AtomicProtocolId::TransmitCompletion,
            ),
        }
    }

    fn allocated(&self) -> u32 {
        self.completion.allocated().unwrap_or_else(|error| {
            crate::runtime_support::publish_process_fatal(format_args!(
                "ICMP transmit allocation state is invalid: {error:?}"
            ));
            0
        })
    }

    fn status(&self) -> send_completion::TransmitSessionStatus {
        self.completion.status().unwrap_or_else(|error| {
            crate::runtime_support::publish_process_fatal(format_args!(
                "ICMP transmit session has invalid allocation status: {error:?}"
            ));
            send_completion::TransmitSessionStatus::Retired
        })
    }

    fn reserve(&self) -> Result<u16, RekeyRequired> {
        self.completion.reserve_next().map_err(|_| RekeyRequired {
            session_id: self.session_id,
        })
    }

    fn supersede(&self) {
        self.retire_completion_evidence(send_completion::TransmitSessionStatus::Superseded);
    }

    fn retire(&self) {
        self.retire_completion_evidence(send_completion::TransmitSessionStatus::Retired);
    }

    fn retire_completion_evidence(&self, status: send_completion::TransmitSessionStatus) {
        match self.completion.request_retirement(status) {
            Ok(send_completion::RetirementProgress::Complete) => {}
            Ok(send_completion::RetirementProgress::Draining) => {
                crate::runtime_support::publish_process_fatal(format_args!(
                    "ICMP send-completion retirement began before stable send permits drained"
                ));
            }
            Err(error) => {
                crate::runtime_support::publish_process_fatal(format_args!(
                    "ICMP send-completion retirement failed: {error:?}"
                ));
            }
        }
    }

    fn publish(&self, sequence: u16) {
        let sequence = u32::from(sequence);
        loop {
            let published = self.latest_published_seq.load(Ordering::Acquire);
            if published != UNPUBLISHED_SEQUENCE && published >= sequence {
                return;
            }
            if self
                .latest_published_seq
                .compare_exchange(published, sequence, Ordering::Release, Ordering::Acquire)
                .is_ok()
            {
                return;
            }
        }
    }

    fn latest_published(&self) -> Option<u16> {
        let published = self.latest_published_seq.load(Ordering::Acquire);
        (published != UNPUBLISHED_SEQUENCE).then_some(published as u16)
    }

    fn reserve_data(&self, sequence: u16) -> Result<(), RekeyRequired> {
        match self.completion.arm_send(sequence) {
            Ok(send_completion::ArmSendDisposition::Armed) => return Ok(()),
            Ok(send_completion::ArmSendDisposition::Retired(disposition)) => {
                if matches!(
                    disposition,
                    send_completion::CompletionDisposition::Apply(_)
                ) {
                    crate::runtime_support::publish_process_fatal(format_args!(
                        "retired ICMP reservation produced an invalid apply disposition"
                    ));
                }
            }
            Err(error) => {
                if error.is_internal_invariant() {
                    crate::runtime_support::publish_process_fatal(format_args!(
                        "ICMP send-completion reservation failed: {error:?}"
                    ));
                }
            }
        }
        Err(RekeyRequired {
            session_id: self.session_id,
        })
    }

    fn complete_data(
        &self,
        sequence: u16,
        sent: bool,
    ) -> Result<Option<crate::flow_state::DeferredPeerControl>, RekeyRequired> {
        let disposition = if sent {
            self.completion.complete_send_success(sequence)
        } else {
            self.completion.complete_send_failure(sequence)
        }
        .map_err(|_| RekeyRequired {
            session_id: self.session_id,
        })?;
        Ok(match disposition {
            send_completion::CompletionDisposition::Apply(control) => Some(control),
            send_completion::CompletionDisposition::None
            | send_completion::CompletionDisposition::Reject(_) => None,
        })
    }

    fn data_evidence(&self, sequence: u16) -> DataSequenceEvidenceState {
        match self.completion.evidence(sequence) {
            Ok(send_completion::SendCompletionEvidence::Sent) => DataSequenceEvidenceState::Sent,
            Ok(send_completion::SendCompletionEvidence::InFlight) => {
                DataSequenceEvidenceState::InFlight
            }
            Ok(send_completion::SendCompletionEvidence::Unknown) => {
                DataSequenceEvidenceState::Unknown
            }
            Err(error) => {
                if error.is_internal_invariant() {
                    crate::runtime_support::publish_process_fatal(format_args!(
                        "ICMP send-completion evidence failed: {error:?}"
                    ));
                }
                DataSequenceEvidenceState::Unknown
            }
        }
    }

    fn defer_control(
        &self,
        control: crate::flow_state::DeferredPeerControl,
    ) -> DeferredDataControlOutcome {
        match self
            .completion
            .observe_peer_control(control_sequence(control), control)
        {
            Ok(send_completion::ControlObservation::Deferred) => {
                DeferredDataControlOutcome::Deferred
            }
            Ok(send_completion::ControlObservation::Apply(control)) => {
                DeferredDataControlOutcome::Apply(control)
            }
            Ok(
                send_completion::ControlObservation::Reject(_)
                | send_completion::ControlObservation::Stale
                | send_completion::ControlObservation::Conflict,
            ) => DeferredDataControlOutcome::Rejected,
            Err(error) => {
                if error.is_internal_invariant() {
                    crate::runtime_support::publish_process_fatal(format_args!(
                        "ICMP send-completion control observation failed: {error:?}"
                    ));
                }
                DeferredDataControlOutcome::Rejected
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DataSequenceEvidenceState {
    Unknown,
    InFlight,
    Sent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DeferredDataControlOutcome {
    Deferred,
    Apply(crate::flow_state::DeferredPeerControl),
    Rejected,
}

fn control_sequence(control: crate::flow_state::DeferredPeerControl) -> u16 {
    match control {
        crate::flow_state::DeferredPeerControl::ResetRequired { control, .. } => {
            control.rejected_sequence()
        }
        crate::flow_state::DeferredPeerControl::SessionActivated { control, .. } => {
            control.accepted_sequence()
        }
    }
}

impl send_completion::SendCompletionAtomic
    for crate::authority::AuthorityAtomic<crate::authority::tags::ProtocolTransmit, AtomicU32>
{
    fn new(value: u32) -> Self {
        Self::new_u32(
            value,
            crate::authority::AtomicProtocolId::TransmitCompletion,
        )
    }

    fn load(&self) -> u32 {
        <crate::authority::AuthorityAtomic<
            crate::authority::tags::ProtocolTransmit,
            AtomicU32,
        >>::load(self, Ordering::Acquire)
    }

    fn compare_exchange(&self, current: u32, next: u32) -> Result<u32, u32> {
        <crate::authority::AuthorityAtomic<
            crate::authority::tags::ProtocolTransmit,
            AtomicU32,
        >>::compare_exchange(
            self,
            current,
            next,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
    }

    fn store(&self, value: u32) {
        <crate::authority::AuthorityAtomic<
            crate::authority::tags::ProtocolTransmit,
            AtomicU32,
        >>::store(self, value, Ordering::Release);
    }
}

impl send_completion::SendAllocationAtomic
    for crate::authority::AuthorityAtomic<crate::authority::tags::ProtocolTransmit, AtomicU64>
{
    fn new(value: u64) -> Self {
        Self::new_u64(
            value,
            crate::authority::AtomicProtocolId::TransmitCompletion,
        )
    }

    fn load(&self) -> u64 {
        <crate::authority::AuthorityAtomic<
            crate::authority::tags::ProtocolTransmit,
            AtomicU64,
        >>::load(self, Ordering::Acquire)
    }

    fn compare_exchange(&self, current: u64, next: u64) -> Result<u64, u64> {
        <crate::authority::AuthorityAtomic<
            crate::authority::tags::ProtocolTransmit,
            AtomicU64,
        >>::compare_exchange(
            self,
            current,
            next,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
    }
}

impl send_completion::SendCompletionControl for crate::flow_state::DeferredPeerControl {
    fn same_control(self, other: Self) -> bool {
        crate::flow_state::DeferredPeerControl::same_control(self, other)
    }

    fn retain_earliest(&mut self, other: Self) {
        self.retain_earliest_observation(other);
    }
}

impl send_completion::SendCompletionError {
    fn is_internal_invariant(self) -> bool {
        matches!(
            self,
            Self::InvalidState(_)
                | Self::InvalidAllocationState(_)
                | Self::DeferredSlotMissing
                | Self::DeferredStoreFull
        )
    }
}

struct ReceiveReplayWindow {
    session_id: SessionId,
    replay_highest: Option<u64>,
    replay_bitmap: [u64; REPLAY_WINDOW_WORDS],
}

struct TransmitSequenceState {
    generation: u64,
    transmit_sessions: Vec<Arc<TransmitSequenceWindow>>,
}

struct ReceiveSequenceState {
    generation: u64,
    receive_session_id: Option<SessionId>,
    replay_highest: Option<u64>,
    replay_bitmap: [u64; REPLAY_WINDOW_WORDS],
    draining_receive_sessions: VecDeque<ReceiveReplayWindow>,
    rejection_counters: SequenceRejectionCounters,
}

pub(crate) struct SharedIcmpSequenceState {
    authority_id: u64,
    generation:
        crate::authority::AuthorityAtomic<crate::authority::tags::ProtocolReceive, AtomicU64>,
    reply_icmp_seq:
        crate::authority::AuthorityAtomic<crate::authority::tags::ProtocolReceive, AtomicU32>,
    transmit: crate::authority::AuthorityMutex<
        crate::authority::tags::SessionControl,
        TransmitSequenceState,
    >,
    receive: crate::authority::AuthorityMutex<
        crate::authority::tags::ProtocolReceive,
        ReceiveSequenceState,
    >,
}

pub(crate) struct IcmpSequenceCache {
    pub(crate) generation: u64,
    pub(crate) reply_icmp_seq: u16,
    transmit_session: Option<Arc<TransmitSequenceWindow>>,
}

#[must_use = "reserved ICMP sequence ownership must be transferred or cancelled"]
pub(crate) struct OutboundRequestSequence<'session> {
    generation: u64,
    session_id: SessionId,
    sequence: u16,
    session: &'session TransmitSequenceWindow,
    reserved: bool,
    _authority: crate::authority::AuthorityScope<crate::authority::tags::ProtocolTransmit>,
}

pub(crate) struct OutboundReplySequence {
    sequence: u16,
    _authority: crate::authority::AuthorityScope<crate::authority::tags::ProtocolTransmit>,
}

pub(crate) struct OutboundReplyReservation<'cache> {
    shared: &'cache SharedIcmpSequenceState,
    cache: &'cache mut IcmpSequenceCache,
    session_id: SessionId,
}

impl crate::worker_support::StableProtocolReservation for OutboundReplyReservation<'_> {
    type Protocol = OutboundReplySequence;
    type Error = std::convert::Infallible;

    fn reserve(self) -> Result<Self::Protocol, Self::Error> {
        Ok(reserve_outbound_reply_seq(
            self.shared,
            self.cache,
            self.session_id,
        ))
    }
}

impl<'cache> crate::worker_support::StableProtocolReservation
    for Option<OutboundReplyReservation<'cache>>
{
    type Protocol = Option<OutboundReplySequence>;
    type Error = std::convert::Infallible;

    fn reserve(self) -> Result<Self::Protocol, Self::Error> {
        self.map(|reservation| reservation.reserve()).transpose()
    }
}

pub(crate) fn outbound_reply_reservation<'cache>(
    shared: &'cache SharedIcmpSequenceState,
    cache: &'cache mut IcmpSequenceCache,
    session_id: SessionId,
) -> OutboundReplyReservation<'cache> {
    OutboundReplyReservation {
        shared,
        cache,
        session_id,
    }
}

#[must_use = "armed ICMP data evidence must be completed or dropped as a failed send"]
pub(crate) struct ArmedOutboundDataSequence<'session> {
    session: &'session TransmitSequenceWindow,
    sequence: u16,
    armed: bool,
}

impl ArmedOutboundDataSequence<'_> {
    pub(crate) fn complete(
        mut self,
        sent: bool,
    ) -> Result<Option<crate::flow_state::DeferredPeerControl>, RekeyRequired> {
        self.armed = false;
        self.session.complete_data(self.sequence, sent)
    }
}

impl Drop for ArmedOutboundDataSequence<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        self.armed = false;
        if self.session.complete_data(self.sequence, false).is_err() {
            crate::runtime_support::publish_process_fatal(format_args!(
                "armed ICMP data evidence could not publish its failed-send disposition"
            ));
        }
    }
}

impl OutboundReplySequence {
    #[inline]
    pub(crate) const fn sequence(&self) -> u16 {
        self.sequence
    }
}

impl fmt::Debug for OutboundRequestSequence<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OutboundRequestSequence")
            .field("generation", &self.generation)
            .field("session_id", &self.session_id)
            .field("sequence", &self.sequence)
            .finish()
    }
}

impl<'session> OutboundRequestSequence<'session> {
    #[inline]
    pub(crate) fn sequence(&self) -> u16 {
        self.sequence
    }

    pub(crate) fn arm_data_evidence(
        &mut self,
    ) -> Result<ArmedOutboundDataSequence<'session>, RekeyRequired> {
        self.session.reserve_data(self.sequence)?;
        self.reserved = false;
        Ok(ArmedOutboundDataSequence {
            session: self.session,
            sequence: self.sequence,
            armed: true,
        })
    }

    fn publish(&self) {
        self.session.publish(self.sequence);
    }

    pub(crate) fn claim_activation_recovery(&self) -> Result<bool, RekeyRequired> {
        Ok(self
            .session
            .activation_recovery_claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok())
    }
}

impl Drop for OutboundRequestSequence<'_> {
    fn drop(&mut self) {
        if !self.reserved {
            return;
        }
        self.reserved = false;
        if self
            .session
            .completion
            .cancel_unexposed_reservation(self.sequence)
            .is_err()
        {
            crate::runtime_support::publish_process_fatal(format_args!(
                "reserved ICMP sequence could not publish its abandoned disposition"
            ));
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct SequenceRejectionCounters {
    pub(crate) future: u64,
    pub(crate) stale: u64,
    pub(crate) duplicate: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SequenceRangeRejection {
    Future,
    Stale,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SequenceAdmissionError {
    InactiveSession,
    WrongSession,
    FutureSync,
    StaleSync,
    StaleReplay,
    Duplicate,
}

impl fmt::Display for SequenceAdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InactiveSession => "ICMP data cannot establish a receive session",
            Self::WrongSession => {
                "ICMP tunnel frame does not belong to an active or draining receive session"
            }
            Self::FutureSync => "ICMP sync mode: future reply sequence",
            Self::StaleSync => "ICMP sync mode: stale reply sequence",
            Self::StaleReplay => "ICMP tunnel sequence is older than the replay window",
            Self::Duplicate => "duplicate ICMP tunnel sequence",
        })
    }
}

impl std::error::Error for SequenceAdmissionError {}

#[inline]
pub(crate) fn sequence_admission_error(error: &io::Error) -> Option<SequenceAdmissionError> {
    error
        .get_ref()
        .and_then(|source| source.downcast_ref::<SequenceAdmissionError>())
        .copied()
}

#[inline]
pub(crate) fn rekey_required(error: &io::Error) -> Option<RekeyRequired> {
    error
        .get_ref()
        .and_then(|source| source.downcast_ref::<RekeyRequired>())
        .copied()
}

#[inline]
fn admission_error(reason: SequenceAdmissionError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

mod state;

#[inline]
pub(crate) fn outbound_session_requires_rekey(
    shared: &SharedIcmpSequenceState,
    cache: &IcmpSequenceCache,
    session_id: SessionId,
) -> bool {
    if cache.generation == shared.generation.load(Ordering::Acquire)
        && let Some(session) = cache
            .transmit_session
            .as_ref()
            .filter(|session| session.session_id == session_id)
    {
        return session.status() != send_completion::TransmitSessionStatus::Active;
    }
    shared.outbound_session_requires_rekey(session_id)
}

mod reset;
use reset::cache_from_windows;
#[cfg(test)]
use reset::preflight_sequence_generations;
pub(crate) use reset::reset_sequence_pair_for_client_lock;

mod admission;
use admission::admit_replay_sequence_window;
pub(crate) use admission::{
    activate_receive_session, admit_inbound_sequence, register_receive_candidate,
    remember_request_seq, retain_admitted_receive_sessions, unregister_receive_candidate,
};

fn validate_range(
    state: &TransmitSequenceState,
    session_id: SessionId,
    icmp_seq: u16,
    catchup_window: usize,
) -> Result<(), SequenceRangeRejection> {
    let direct = state
        .transmit_sessions
        .iter()
        .find(|session| session.session_id == session_id);
    let request = session_id.request_session_id().and_then(|request| {
        state
            .transmit_sessions
            .iter()
            .find(|session| session.session_id == request)
    });
    let Some(latest_seq) = direct
        .or(request)
        .and_then(|session| session.latest_published())
    else {
        return Err(SequenceRangeRejection::Stale);
    };
    if icmp_seq <= latest_seq {
        let lag = usize::from(latest_seq - icmp_seq);
        return (lag <= catchup_window)
            .then_some(())
            .ok_or(SequenceRangeRejection::Stale);
    }
    Err(SequenceRangeRejection::Future)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RekeyRequired {
    pub(crate) session_id: SessionId,
}

impl std::fmt::Display for RekeyRequired {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "ICMP session {} exhausted its 16-bit sequence space; rekey required",
            self.session_id.get()
        )
    }
}

impl std::error::Error for RekeyRequired {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OutboundSessionNotInstalled {
    pub(crate) session_id: SessionId,
}

impl std::fmt::Display for OutboundSessionNotInstalled {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "ICMP transmit session {} has not been installed",
            self.session_id.get()
        )
    }
}

impl std::error::Error for OutboundSessionNotInstalled {}

/// Refreshes the worker-owned transmit-session cache before a socket I/O lane
/// is acquired. Session-window allocation is a cold publication path and must
/// never occur while the destination socket authority is held.
pub(crate) fn install_outbound_request_session(
    shared: &SharedIcmpSequenceState,
    cache: &mut IcmpSequenceCache,
    session_id: SessionId,
) -> Result<(), RekeyRequired> {
    if cache.generation == shared.generation.load(Ordering::Acquire)
        && cache
            .transmit_session
            .as_ref()
            .is_some_and(|session| session.session_id == session_id)
    {
        return Ok(());
    }
    let prepared_session = Arc::new(TransmitSequenceWindow::new(session_id, shared.authority_id));
    let mut state = crate::runtime_support::lock_authority_or_shutdown(
        &shared.transmit,
        "ICMP transmit sequence",
    );
    let session = match state
        .transmit_sessions
        .iter()
        .find(|session| session.session_id == session_id)
        .cloned()
    {
        Some(session) => session,
        None => {
            if state.transmit_sessions.len() == MAX_TRACKED_TRANSMIT_SESSIONS {
                if let Some(index) = state.transmit_sessions.iter().position(|session| {
                    session.status() != send_completion::TransmitSessionStatus::Active
                }) {
                    state.transmit_sessions.swap_remove(index).retire();
                } else {
                    return Err(RekeyRequired { session_id });
                }
            }
            let session = prepared_session;
            state.transmit_sessions.push(Arc::clone(&session));
            session
        }
    };
    cache.generation = state.generation;
    cache.transmit_session = Some(session);
    Ok(())
}

/// Refreshes a worker cache from an already installed transmit session.
/// This path never constructs protocol storage and is safe beneath a stable
/// flow permit; session construction is owned by
/// [`install_outbound_request_session`] before that permit is acquired.
pub(crate) fn load_installed_outbound_session(
    shared: &SharedIcmpSequenceState,
    cache: &mut IcmpSequenceCache,
    session_id: SessionId,
) -> Result<(), OutboundSessionNotInstalled> {
    if cache.generation == shared.generation.load(Ordering::Acquire)
        && cache
            .transmit_session
            .as_ref()
            .is_some_and(|session| session.session_id == session_id)
    {
        return Ok(());
    }
    let state = crate::runtime_support::lock_authority_or_shutdown(
        &shared.transmit,
        "ICMP transmit sequence",
    );
    let session = state
        .transmit_sessions
        .iter()
        .find(|session| session.session_id == session_id)
        .cloned()
        .ok_or(OutboundSessionNotInstalled { session_id })?;
    cache.generation = state.generation;
    cache.transmit_session = Some(session);
    Ok(())
}

/// Reserves from an already prepared worker cache. This is the only request
/// allocator used while a destination socket lane is held.
pub(crate) fn claim_prepared_outbound_session<'cache>(
    shared: &'cache SharedIcmpSequenceState,
    cache: &'cache IcmpSequenceCache,
    session_id: SessionId,
) -> Result<PreparedOutboundSession<'cache>, OutboundSessionNotInstalled> {
    let exact_session = cache
        .transmit_session
        .as_ref()
        .filter(|session| session.session_id == session_id);
    let generation = crate::atomic_core::PreparedSessionGeneration::claim(
        &shared.generation,
        cache.generation,
        exact_session.is_some(),
    )
    .ok_or(OutboundSessionNotInstalled { session_id })?;
    let session = cache
        .transmit_session
        .as_ref()
        .filter(|session| session.session_id == session_id)
        .map(Arc::as_ref)
        .ok_or(OutboundSessionNotInstalled { session_id })?;
    Ok(PreparedOutboundSession::new(
        shared, session, generation, session_id,
    ))
}

pub(crate) fn outbound_request_session_is_prepared(
    shared: &SharedIcmpSequenceState,
    cache: &IcmpSequenceCache,
    session_id: SessionId,
) -> bool {
    let generation = shared.generation.load(Ordering::Acquire);
    cache.generation == generation
        && cache
            .transmit_session
            .as_ref()
            .is_some_and(|session| session.session_id == session_id)
}

pub(crate) fn publish_outbound_request_seq(
    _shared: &SharedIcmpSequenceState,
    reservation: &OutboundRequestSequence<'_>,
) {
    reservation.publish();
}

pub(crate) fn reserve_outbound_reply_seq(
    shared: &SharedIcmpSequenceState,
    cache: &mut IcmpSequenceCache,
    session_id: SessionId,
) -> OutboundReplySequence {
    let authority = transmit_authority(shared, session_id, 1);
    let sequence = current_reply_seq(shared, cache);
    OutboundReplySequence {
        sequence,
        _authority: authority,
    }
}

fn transmit_authority(
    shared: &SharedIcmpSequenceState,
    session_id: SessionId,
    direction: u8,
) -> crate::authority::AuthorityScope<crate::authority::tags::ProtocolTransmit> {
    crate::authority::AuthorityScope::enter(crate::authority::AuthorityInstance {
        id: crate::authority::AuthorityId::ProtocolTransmit,
        flow: shared.authority_id,
        direction,
        kind: 0,
        session: session_id.get(),
    })
    .unwrap_or_else(|error| {
        crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
            "ICMP transmit authority order was violated: {error}"
        ))
    })
}

pub(crate) fn current_reply_seq(
    shared: &SharedIcmpSequenceState,
    cache: &mut IcmpSequenceCache,
) -> u16 {
    let sequence = shared.reply_icmp_seq.load(Ordering::Acquire) as u16;
    cache.generation = shared.generation.load(Ordering::Acquire);
    cache.reply_icmp_seq = sequence;
    sequence
}

#[cfg(test)]
mod tests;
