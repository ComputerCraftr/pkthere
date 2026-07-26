#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct SessionPoolSnapshot {
    pub(crate) pool: SessionPoolStateSnapshot,
    pub(crate) metrics: SessionPoolMetricsSnapshot,
    pub(crate) reset_recovery: ResetRecoveryMetricsSnapshot,
    pub(crate) maintenance_wake_failures: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReadySessionIdSnapshot {
    entries: [Option<SessionId>; crate::cli::MAX_ICMP_SESSION_POOL_SIZE],
    len: usize,
}

impl ReadySessionIdSnapshot {
    pub(super) fn from_ready_sessions(sessions: &VecDeque<ReadySession>) -> Self {
        let mut snapshot = Self::default();
        for session in sessions {
            let Some(entry) = snapshot.entries.get_mut(snapshot.len) else {
                crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
                    "ready-session diagnostics exceeded the configured pool bound"
                ));
            };
            *entry = Some(session.session_key.session_id());
            snapshot.len += 1;
        }
        snapshot
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = SessionId> + '_ {
        self.entries[..self.len].iter().filter_map(|entry| *entry)
    }
}

impl Default for ReadySessionIdSnapshot {
    fn default() -> Self {
        Self {
            entries: [None; crate::cli::MAX_ICMP_SESSION_POOL_SIZE],
            len: 0,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct SessionPoolStateSnapshot {
    pub(crate) pool_epoch: u64,
    pub(crate) pool_epoch_exhausted: bool,
    pub(crate) active: usize,
    pub(crate) client_transmit_session_id: Option<SessionId>,
    pub(crate) client_receive_session_id: Option<SessionId>,
    pub(crate) upstream_transmit_session_id: Option<SessionId>,
    pub(crate) upstream_receive_session_id: Option<SessionId>,
    pub(crate) ready: usize,
    pub(crate) negotiating: usize,
    pub(crate) draining: usize,
    pub(crate) target: usize,
    pub(crate) ready_session_ids: ReadySessionIdSnapshot,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct SessionPoolMetricsSnapshot {
    pub(crate) candidate_retry_attempts: u64,
    pub(crate) candidate_expirations: u64,
    pub(crate) candidate_negotiation_latency_ns_total: u128,
    pub(crate) candidate_negotiations_completed: u64,
    pub(crate) normal_handoffs: u64,
    pub(crate) pool_empty_stalls: u64,
    pub(crate) stale_session_evictions: u64,
    pub(crate) sparse_retirement_exhaustions: u64,
    pub(crate) generation_rollovers: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ResetRecoveryMetricsSnapshot {
    pub(crate) reset_challenges_created: u64,
    pub(crate) reset_challenges_reused: u64,
    pub(crate) reset_challenges_consumed: u64,
    pub(crate) reset_challenges_expired: u64,
    pub(crate) reset_responses_rate_limited: u64,
    pub(crate) reset_responses_accepted: u64,
    pub(crate) reset_responses_ignored: u64,
}

pub(super) struct ReserveReplyIdHandshake {
    pub(super) expected_ack_destination_id: u16,
    pub(super) session_key: SessionKey,
    pub(super) challenge: Option<ChallengeControl>,
    pub(super) started_at: Instant,
    pub(super) control: ControlSendCore,
}

pub(super) struct GenerationAdvanceHandshake {
    pub(super) current: SessionKey,
    pub(super) proposed_key: SessionKey,
    pub(super) expected_ack_destination_id: u16,
    pub(super) control: ControlSendCore,
}

impl GenerationAdvanceHandshake {
    pub(super) fn new(
        current: SessionKey,
        proposed_key: SessionKey,
        expected_ack_destination_id: u16,
        control: ControlSendCore,
    ) -> Self {
        Self {
            current,
            proposed_key,
            expected_ack_destination_id,
            control,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct GenerationAuthorization {
    pub(super) current: SessionKey,
    pub(super) proposed_generation: PoolGeneration,
    pub(super) expires_at: Instant,
}

impl ReserveReplyIdHandshake {
    pub(super) fn new(
        expected_ack_destination_id: u16,
        session_key: SessionKey,
        challenge: Option<ChallengeControl>,
        now: Instant,
        control: ControlSendCore,
    ) -> Self {
        Self {
            expected_ack_destination_id,
            session_key,
            challenge,
            started_at: now,
            control,
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct ReadySession {
    pub(super) session_key: SessionKey,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ReceiveCandidate {
    pub(super) session_key: SessionKey,
    pub(super) transaction_key: super::ControlTransactionKey,
    ack: ReceiveCandidateAckCore,
}

impl ReceiveCandidate {
    pub(super) fn negotiating(
        session_key: SessionKey,
        transaction_key: super::ControlTransactionKey,
        absolute_deadline: Instant,
    ) -> Self {
        Self {
            session_key,
            transaction_key,
            ack: ReceiveCandidateAckCore::new(absolute_deadline),
        }
    }

    pub(super) fn is_expired_negotiating(self, now: Instant) -> bool {
        self.ack.is_expired(now)
    }

    pub(super) fn is_live_at(self, observed_at: Instant) -> bool {
        self.ack.is_live_at(observed_at)
    }

    pub(super) fn is_negotiating(self) -> bool {
        self.ack.is_negotiating()
    }

    pub(super) fn is_promotable(self) -> bool {
        self.ack.is_promotable()
    }

    pub(super) fn begin_ack_send(
        &mut self,
        observed_at: Instant,
        next_installation_order: &mut u64,
    ) -> Result<
        Option<super::session_lifecycles::ReceiveCandidateAckPermit>,
        super::PendingIcmpClientLockMismatch,
    > {
        ReceiveCandidateAckTransaction::new(&mut self.ack, next_installation_order)
            .begin_send(observed_at)
    }

    pub(super) fn complete_ack_send(
        &mut self,
        permit: super::session_lifecycles::ReceiveCandidateAckPermit,
        sent: bool,
    ) -> Result<(), super::PendingIcmpClientLockMismatch> {
        self.ack.complete_send(permit, sent)
    }

    pub(super) fn ready_installation_order(self) -> Option<u64> {
        self.ack.ready_installation_order()
    }

    pub(super) const fn absolute_deadline(self) -> Instant {
        self.ack.deadline()
    }
}

#[derive(Debug)]
pub(super) struct RecoveryPayload {
    pub(super) session: SessionId,
    pub(super) sequence: u16,
    pub(super) deadline: Instant,
    pub(super) send: super::recovery_core::RecoverySendCore<BufferedPayload>,
}

pub(super) struct SameGenerationFallback {
    pub(super) original_reset: ResetRequired,
    pub(super) rejected_sessions: Vec<SessionId>,
    pub(super) attempts_remaining: usize,
    pub(super) expires_at: Instant,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct RecoveryPayloadSendToken {
    pub(super) session: SessionId,
    pub(super) attempt: u32,
}

pub(crate) type RecoveryPayloadSendLease = super::recovery_core::RecoverySendLease<BufferedPayload>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RecoveryPayloadSendCompletion {
    pub(crate) pending_reset: Option<ResetRequired>,
    pub(crate) timeout_requested: bool,
}

#[derive(Clone)]
pub(super) struct ResetResponseBudget {
    pub(super) packet_tokens: u32,
    pub(super) byte_tokens: u32,
    pub(super) packet_burst: u32,
    pub(super) packet_refill_per_second: u32,
    pub(super) byte_burst: u32,
    pub(super) byte_refill_per_second: u32,
    pub(super) last_refill: Instant,
}

pub(super) struct StatelessResetResponseBudget {
    pub(super) peer_flow: ClientFlowKey,
    pub(super) budget: ResetResponseBudget,
    pub(super) last_used: Instant,
}

impl ResetResponseBudget {
    pub(super) fn new() -> Self {
        Self::new_at(Instant::now())
    }

    pub(super) fn new_at(now: Instant) -> Self {
        let mut budget = Self::with_limits(2, 1, 512, 128);
        budget.last_refill = now;
        budget
    }

    pub(super) fn global() -> Self {
        Self::with_limits(32, 16, 8_192, 2_048)
    }

    pub(super) fn with_limits(
        packet_burst: u32,
        packet_refill_per_second: u32,
        byte_burst: u32,
        byte_refill_per_second: u32,
    ) -> Self {
        Self {
            packet_tokens: packet_burst,
            byte_tokens: byte_burst,
            packet_burst,
            packet_refill_per_second,
            byte_burst,
            byte_refill_per_second,
            last_refill: Instant::now(),
        }
    }

    pub(super) fn reserve(&mut self, now: Instant, bytes: u32) -> bool {
        let elapsed_seconds = now.saturating_duration_since(self.last_refill).as_secs();
        if elapsed_seconds != 0 {
            let elapsed = u32::try_from(elapsed_seconds).unwrap_or(u32::MAX);
            self.packet_tokens = self
                .packet_tokens
                .saturating_add(elapsed.saturating_mul(self.packet_refill_per_second))
                .min(self.packet_burst);
            self.byte_tokens = self
                .byte_tokens
                .saturating_add(elapsed.saturating_mul(self.byte_refill_per_second))
                .min(self.byte_burst);
            self.last_refill = self
                .last_refill
                .checked_add(Duration::from_secs(elapsed_seconds))
                .unwrap_or(now);
        }
        if self.packet_tokens == 0 || self.byte_tokens < bytes {
            return false;
        }
        self.packet_tokens -= 1;
        self.byte_tokens -= bytes;
        true
    }

    pub(super) fn reserve_with(
        first: &mut Self,
        second: &mut Self,
        now: Instant,
        bytes: u32,
    ) -> bool {
        let mut next_first = first.clone();
        let mut next_second = second.clone();
        if !next_first.reserve(now, bytes) || !next_second.reserve(now, bytes) {
            return false;
        }
        *first = next_first;
        *second = next_second;
        true
    }
}

pub(super) fn global_reset_response_budget() -> &'static crate::authority::AuthorityMutex<
    crate::authority::tags::ResetBudget,
    ResetResponseBudget,
> {
    static BUDGET: crate::authority::AuthorityOnceLock<
        crate::authority::tags::ResetBudget,
        crate::authority::AuthorityMutex<crate::authority::tags::ResetBudget, ResetResponseBudget>,
    > = crate::authority::AuthorityOnceLock::new();
    BUDGET.get_or_init(|| {
        crate::authority::AuthorityMutex::new(
            ResetResponseBudget::global(),
            crate::authority::AuthorityInstance {
                id: crate::authority::AuthorityId::ResetBudget,
                flow: 0,
                direction: 0,
                kind: 3,
                session: 0,
            },
        )
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ResetChallenge {
    pub(crate) peer_flow: ClientFlowKey,
    pub(crate) receiver_generation: Option<PoolGeneration>,
    pub(crate) context: RejectedFrameEvidence,
    pub(crate) challenge: NonZeroU64,
    pub(crate) expires_at: Instant,
    pub(crate) consumed: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ResetChallengeIssue {
    Created(ResetChallenge),
    Reused(ResetChallenge),
    DifferentConflictPending,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct OrdinalRetirementWindow {
    pub(super) retired_through: Option<u32>,
    pub(super) sparse: u64,
}

impl OrdinalRetirementWindow {
    pub(super) fn is_retired(self, ordinal: u32) -> bool {
        let base = self
            .retired_through
            .map_or(0, |value| value.saturating_add(1));
        if self.retired_through.is_some_and(|value| ordinal <= value) {
            return true;
        }
        let Some(offset) = ordinal.checked_sub(base) else {
            return true;
        };
        offset < ORDINAL_RETIREMENT_WINDOW_BITS && self.sparse & (1_u64 << offset) != 0
    }

    pub(super) fn retire_exact(
        &mut self,
        ordinal: u32,
    ) -> Result<(), ReplyIdHandshakeInvariantError> {
        if self.is_retired(ordinal) {
            return Ok(());
        }
        let base = self
            .retired_through
            .map_or(0, |value| value.saturating_add(1));
        let offset = ordinal
            .checked_sub(base)
            .ok_or(ReplyIdHandshakeInvariantError)?;
        if offset >= ORDINAL_RETIREMENT_WINDOW_BITS {
            return Err(ReplyIdHandshakeInvariantError);
        }
        self.sparse |= 1_u64 << offset;
        while self.sparse & 1 != 0 {
            self.sparse >>= 1;
            self.retired_through = Some(
                self.retired_through
                    .map_or(0, |value| value.saturating_add(1)),
            );
        }
        Ok(())
    }

    pub(super) fn retire_through(&mut self, ordinal: u32) {
        if self.retired_through.is_none_or(|current| ordinal > current) {
            let old_base = self
                .retired_through
                .map_or(0, |value| value.saturating_add(1));
            let shift = ordinal.saturating_add(1).saturating_sub(old_base);
            self.sparse = if shift >= u64::BITS {
                0
            } else {
                self.sparse >> shift
            };
            self.retired_through = Some(ordinal);
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct DrainingSession {
    pub(super) session_key: SessionKey,
    pub(super) expires_at: Instant,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SessionAdmissionSnapshot {
    pub(super) active: Option<SessionId>,
    pub(super) candidates: [Option<SessionId>; MAX_RECEIVE_SESSION_CANDIDATES],
    pub(super) draining: [Option<SessionId>; MAX_DRAINING_SESSIONS],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FlowAdmissionSnapshot {
    pub(crate) locked: bool,
    pub(crate) client_flow: Option<ClientFlowKey>,
    pub(crate) flow_claim_generation: Option<NonZeroU64>,
    pub(crate) pending_icmp_client_lock: Option<PendingIcmpClientLock>,
    pub(crate) pending_icmp_client_deadline: Option<Instant>,
    pub(crate) client_active_session_key: Option<SessionKey>,
    pub(crate) client_transmit_session_id: Option<SessionId>,
    pub(crate) client_receive_session_id: Option<SessionId>,
    pub(crate) upstream_receive_session_id: Option<SessionId>,
    pub(crate) upstream_transmit_session_id: Option<SessionId>,
    pub(crate) upstream_reply_id_acked: bool,
    pub(crate) upstream_handshake_deadline: Option<Instant>,
    pub(crate) client_sessions: SessionAdmissionSnapshot,
    pub(crate) upstream_sessions: SessionAdmissionSnapshot,
}

#[derive(Clone, Copy)]
pub(crate) struct PublishedFlowSnapshot {
    pub(crate) epoch: u64,
    pub(crate) admission: FlowAdmissionSnapshot,
}

pub(crate) struct FlowSnapshotCache {
    pub(super) published: Option<PublishedFlowSnapshot>,
    #[cfg(test)]
    pub(super) refreshes: usize,
}

impl FlowSnapshotCache {
    pub(crate) const fn new() -> Self {
        Self {
            published: None,
            #[cfg(test)]
            refreshes: 0,
        }
    }

    #[cfg(test)]
    pub(crate) const fn reload_count(&self) -> usize {
        self.refreshes
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PacketSessionAdmission {
    None,
    Active,
    Candidate,
    Draining,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PacketFlowSnapshot {
    pub(crate) locked: bool,
    pub(crate) client_flow: Option<ClientFlowKey>,
    pub(crate) flow_claim_generation: Option<NonZeroU64>,
    pub(crate) pending_icmp_client_lock: Option<PendingIcmpClientLock>,
    pub(crate) pending_icmp_client_deadline: Option<Instant>,
    pub(crate) client_active_session_key: Option<SessionKey>,
    pub(crate) client_transmit_session_id: Option<SessionId>,
    pub(crate) client_receive_session_id: Option<SessionId>,
    pub(crate) upstream_receive_session_id: Option<SessionId>,
    pub(crate) upstream_transmit_session_id: Option<SessionId>,
    pub(crate) upstream_reply_id_acked: bool,
    pub(crate) upstream_handshake_deadline: Option<Instant>,
    pub(crate) client_packet_session: PacketSessionAdmission,
    pub(crate) upstream_packet_session: PacketSessionAdmission,
}

impl FlowAdmissionSnapshot {
    pub(crate) fn for_packet(&self, session_id: Option<SessionId>) -> PacketFlowSnapshot {
        PacketFlowSnapshot {
            locked: self.locked,
            client_flow: self.client_flow,
            flow_claim_generation: self.flow_claim_generation,
            pending_icmp_client_lock: self.pending_icmp_client_lock,
            pending_icmp_client_deadline: self.pending_icmp_client_deadline,
            client_active_session_key: self.client_active_session_key,
            client_transmit_session_id: self.client_transmit_session_id,
            client_receive_session_id: self.client_receive_session_id,
            upstream_receive_session_id: self.upstream_receive_session_id,
            upstream_transmit_session_id: self.upstream_transmit_session_id,
            upstream_reply_id_acked: self.upstream_reply_id_acked,
            upstream_handshake_deadline: self.upstream_handshake_deadline,
            client_packet_session: self.client_sessions.classify(session_id),
            upstream_packet_session: self.upstream_sessions.classify(session_id),
        }
    }
}

impl SessionAdmissionSnapshot {
    pub(crate) const fn empty() -> Self {
        Self {
            active: None,
            candidates: [None; MAX_RECEIVE_SESSION_CANDIDATES],
            draining: [None; MAX_DRAINING_SESSIONS],
        }
    }

    #[inline]
    pub(crate) fn contains(self, session_id: SessionId) -> bool {
        self.active == Some(session_id)
            || self.candidates.contains(&Some(session_id))
            || self.draining.contains(&Some(session_id))
    }

    #[inline]
    pub(crate) fn is_candidate(self, session_id: SessionId) -> bool {
        self.candidates.contains(&Some(session_id))
    }

    #[inline]
    pub(crate) fn is_draining(self, session_id: SessionId) -> bool {
        self.draining.contains(&Some(session_id))
    }

    pub(crate) fn classify(self, session_id: Option<SessionId>) -> PacketSessionAdmission {
        let Some(session_id) = session_id else {
            return PacketSessionAdmission::None;
        };
        if self.active == Some(session_id) {
            PacketSessionAdmission::Active
        } else if self.is_candidate(session_id) {
            PacketSessionAdmission::Candidate
        } else if self.is_draining(session_id) {
            PacketSessionAdmission::Draining
        } else {
            PacketSessionAdmission::Unknown
        }
    }
}

pub(super) fn active_session_count(sessions: &FlowSessionState) -> usize {
    let mut active = [None; 4];
    let mut count = 0;
    for session_id in [
        sessions.authority.client_leg.transmit,
        sessions.authority.client_leg.receive,
        sessions.authority.upstream_leg.transmit,
        sessions.authority.upstream_leg.receive,
    ]
    .into_iter()
    .flatten()
    {
        if !active[..count].contains(&Some(session_id)) {
            active[count] = Some(session_id);
            count += 1;
        }
    }
    count
}

pub(super) fn session_admission_snapshot(
    active: Option<SessionId>,
    candidates: &[ReceiveCandidate],
    draining: &VecDeque<DrainingSession>,
) -> SessionAdmissionSnapshot {
    let mut snapshot = SessionAdmissionSnapshot::empty();
    snapshot.active = active;
    for (slot, candidate) in snapshot.candidates.iter_mut().zip(
        candidates
            .iter()
            .filter(|candidate| candidate.ready_installation_order().is_some()),
    ) {
        *slot = Some(candidate.session_key.session_id());
    }
    for (slot, session) in snapshot.draining.iter_mut().zip(draining) {
        *slot = Some(session.session_key.session_id());
    }
    snapshot
}

pub(super) fn expire_draining_sessions(sessions: &mut VecDeque<DrainingSession>, now: Instant) {
    sessions.retain(|session| now < session.expires_at);
}

pub(super) fn push_draining_session(
    sessions: &mut VecDeque<DrainingSession>,
    session_key: SessionKey,
    expires_at: Instant,
) -> bool {
    if sessions
        .iter()
        .any(|session| session.session_key == session_key)
    {
        return false;
    }
    let mut evicted = false;
    if sessions.len() == MAX_DRAINING_SESSIONS {
        let Some(earliest) = sessions
            .iter()
            .enumerate()
            .min_by_key(|(_, session)| session.expires_at)
            .map(|(index, _)| index)
        else {
            return false;
        };
        sessions.remove(earliest);
        evicted = true;
    }
    sessions.push_back(DrainingSession {
        session_key,
        expires_at,
    });
    evicted
}

pub(super) fn fresh_nonzero_challenge() -> std::io::Result<NonZeroU64> {
    fresh_nonzero_challenge_with(|bytes| getrandom::fill(bytes).map_err(|error| error.to_string()))
}

pub(super) fn fresh_nonzero_challenge_with(
    mut fill: impl FnMut(&mut [u8]) -> Result<(), String>,
) -> std::io::Result<NonZeroU64> {
    let mut bytes = [0_u8; size_of::<u64>()];
    fill(&mut bytes)
        .map_err(|error| std::io::Error::other(format!("reset challenge RNG failed: {error}")))?;
    NonZeroU64::new(u64::from_ne_bytes(bytes))
        .ok_or_else(|| std::io::Error::other("reset challenge RNG produced zero"))
}

pub(super) fn inspect_existing_reset_challenge(
    sessions: &mut FlowSessionState,
    peer_flow: ClientFlowKey,
    context: RejectedFrameEvidence,
    now: Instant,
) -> Option<ResetChallengeIssue> {
    let existing = sessions.reset_recovery.client_reset_challenge?;
    if now >= existing.expires_at || existing.consumed {
        sessions.reset_recovery.client_reset_challenge = None;
        sessions.reset_recovery.reset_challenges_expired = sessions
            .reset_recovery
            .reset_challenges_expired
            .saturating_add(1);
        return None;
    }
    if existing.peer_flow == peer_flow && existing.context == context {
        sessions.reset_recovery.reset_challenges_reused = sessions
            .reset_recovery
            .reset_challenges_reused
            .saturating_add(1);
        Some(ResetChallengeIssue::Reused(existing))
    } else {
        Some(ResetChallengeIssue::DifferentConflictPending)
    }
}

pub(super) fn inspect_stateless_reset_challenge(
    sessions: &mut FlowSessionState,
    peer_flow: ClientFlowKey,
    context: RejectedFrameEvidence,
    now: Instant,
) -> Option<ResetChallengeIssue> {
    let before = sessions
        .reset_recovery
        .stateless_client_reset_challenges
        .len();
    sessions
        .reset_recovery
        .stateless_client_reset_challenges
        .retain(|challenge| now < challenge.expires_at && !challenge.consumed);
    sessions.reset_recovery.reset_challenges_expired = sessions
        .reset_recovery
        .reset_challenges_expired
        .saturating_add(
            (before
                - sessions
                    .reset_recovery
                    .stateless_client_reset_challenges
                    .len()) as u64,
        );
    let existing = sessions
        .reset_recovery
        .stateless_client_reset_challenges
        .iter()
        .find(|challenge| challenge.peer_flow == peer_flow)
        .copied()?;
    if existing.context == context {
        sessions.reset_recovery.reset_challenges_reused = sessions
            .reset_recovery
            .reset_challenges_reused
            .saturating_add(1);
        Some(ResetChallengeIssue::Reused(existing))
    } else {
        Some(ResetChallengeIssue::DifferentConflictPending)
    }
}

pub(super) fn upstream_reset_matches(
    sessions: &FlowSessionState,
    upstream_sequences: &crate::net::icmp_sequence::SharedIcmpSequenceState,
    reset: ResetRequired,
    now: Instant,
    expected_ack_destination_id: u16,
) -> bool {
    let Some(recovery) = sessions
        .upstream_recovery
        .upstream_recovery_payload
        .as_ref()
    else {
        return false;
    };
    now < recovery.deadline
        && recovery.session == reset.rejected_session()
        && recovery.sequence == reset.rejected_sequence()
        && upstream_data_evidence(sessions, upstream_sequences, reset)
            == crate::net::icmp_sequence::DataSequenceEvidenceState::Sent
        && sessions.authority.upstream_leg.transmit == Some(recovery.session)
        && sessions.upstream_pool.upstream_active_key.is_some()
        && expected_ack_destination_id != 0
}

pub(super) fn upstream_data_evidence(
    _sessions: &FlowSessionState,
    upstream_sequences: &crate::net::icmp_sequence::SharedIcmpSequenceState,
    reset: ResetRequired,
) -> crate::net::icmp_sequence::DataSequenceEvidenceState {
    upstream_sequences.outbound_data_evidence(reset.rejected_session(), reset.rejected_sequence())
}
use super::session_lifecycles::{
    ControlSendCore, ReceiveCandidateAckCore, ReceiveCandidateAckTransaction,
};
use super::{
    BufferedPayload, ChallengeControl, ClientFlowKey, FlowSessionState, MAX_DRAINING_SESSIONS,
    MAX_RECEIVE_SESSION_CANDIDATES, NonZeroU64, ORDINAL_RETIREMENT_WINDOW_BITS,
    PendingIcmpClientLock, PoolGeneration, RejectedFrameEvidence, ReplyIdHandshakeInvariantError,
    ResetRequired, SessionId, SessionKey, VecDeque,
};
use std::time::{Duration, Instant};
