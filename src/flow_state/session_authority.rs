#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FlowPhase {
    Unlocked,
    Active,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct LegSessions {
    pub(super) transmit: Option<SessionId>,
    pub(super) receive: Option<SessionId>,
}

pub(super) struct FlowAuthorityState {
    pub(super) flow: FlowPhase,
    pub(super) client_leg: LegSessions,
    pub(super) upstream_leg: LegSessions,
    pub(super) client_flow: Option<ClientFlowKey>,
    pub(super) flow_claim_generation: Option<std::num::NonZeroU64>,
    pub(super) pending_icmp_client_lock: Option<TimedPendingIcmpClientLock>,
    pub(super) sync_payload: SyncPayloadSlot,
}

pub(super) struct SessionControlState {
    pub(super) upstream_reply_id_handshake: ReplyIdHandshake,
    pub(super) control_lease_epoch: u64,
    pub(super) control_lease_epoch_exhausted: bool,
    pub(super) upstream_pending_key: Option<SessionKey>,
    pub(super) upstream_pending_challenge: Option<ChallengeControl>,
}

pub(super) struct ClientSessionPool {
    pub(super) client_active_key: Option<SessionKey>,
    pub(super) client_staged_generation: Option<SessionKey>,
    pub(super) client_retired_ordinals: OrdinalRetirementWindow,
    pub(super) client_ready_sessions: Vec<ReceiveCandidate>,
    pub(super) client_generation_authorization: Option<GenerationAuthorization>,
    pub(super) next_receive_installation_order: u64,
    pub(super) client_draining_sessions: VecDeque<DrainingSession>,
}

pub(super) struct UpstreamSessionPool {
    pub(super) upstream_active_key: Option<SessionKey>,
    pub(super) upstream_pool_generation: Option<PoolGeneration>,
    pub(super) upstream_ready_sessions: VecDeque<ReadySession>,
    pub(super) upstream_pool_epoch: u64,
    pub(super) upstream_pool_epoch_exhausted: bool,
    pub(super) upstream_reserve_handshakes: Vec<ReserveReplyIdHandshake>,
    pub(super) upstream_generation_advance: Option<GenerationAdvanceHandshake>,
    control_send_pool: Vec<super::session_lifecycles::ControlSendCore>,
    pub(super) upstream_draining_sessions: VecDeque<DrainingSession>,
    pub(super) session_pool_target: usize,
    pub(super) next_session_ordinal: u32,
}

impl UpstreamSessionPool {
    pub(super) fn take_control_send(
        &mut self,
        now: std::time::Instant,
        deadline: std::time::Instant,
    ) -> Result<super::session_lifecycles::ControlSendCore, super::ReplyIdHandshakeInvariantError>
    {
        let mut control = self
            .control_send_pool
            .pop()
            .ok_or(super::ReplyIdHandshakeInvariantError)?;
        control.reset_for_new_transaction(now, deadline);
        Ok(control)
    }

    pub(super) fn recycle_control_send(
        &mut self,
        control: super::session_lifecycles::ControlSendCore,
    ) {
        if self.control_send_pool.len() >= super::CONTROL_SEND_POOL_CAPACITY {
            crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
                "ICMP control-send storage pool overflowed"
            ));
        }
        self.control_send_pool.push(control);
    }

    pub(super) fn clear_reserve_handshakes(&mut self) {
        while let Some(candidate) = self.upstream_reserve_handshakes.pop() {
            self.recycle_control_send(candidate.control);
        }
    }

    pub(super) fn clear_generation_advance(&mut self) {
        if let Some(advance) = self.upstream_generation_advance.take() {
            self.recycle_control_send(advance.control);
        }
    }
}

#[derive(Default)]
pub(super) struct SessionPoolMetrics {
    pub(super) candidate_retry_attempts: u64,
    pub(super) candidate_expirations: u64,
    pub(super) candidate_negotiation_latency_ns_total: u128,
    pub(super) candidate_negotiations_completed: u64,
    pub(super) normal_handoffs: u64,
    pub(super) pool_empty_stalls: u64,
    pub(super) stale_session_evictions: u64,
    pub(super) sparse_retirement_exhaustions: u64,
    pub(super) generation_rollovers: u64,
}

pub(super) struct UpstreamRecoveryState {
    pub(super) upstream_recovery_payload: Option<RecoveryPayload>,
    pub(super) upstream_same_generation_fallback: Option<SameGenerationFallback>,
    pub(super) upstream_deferred_peer_controls: VecDeque<DeferredPeerControl>,
    pub(super) upstream_activation_confirmed: bool,
}

pub(super) struct ResetRecoveryState {
    pub(super) client_reset_challenge: Option<ResetChallenge>,
    pub(super) stateless_client_reset_challenges: VecDeque<ResetChallenge>,
    pub(super) reset_challenges_created: u64,
    pub(super) reset_challenges_reused: u64,
    pub(super) reset_challenges_consumed: u64,
    pub(super) reset_challenges_expired: u64,
    pub(super) reset_responses_rate_limited: u64,
    pub(super) reset_responses_accepted: u64,
    pub(super) reset_responses_ignored: u64,
    pub(super) client_reset_response_budget: ResetResponseBudget,
    pub(super) stateless_reset_response_budgets: VecDeque<StatelessResetResponseBudget>,
}

pub(super) struct FlowSessionState {
    pub(super) authority: FlowAuthorityState,
    pub(super) control: SessionControlState,
    pub(super) client_pool: ClientSessionPool,
    pub(super) upstream_pool: UpstreamSessionPool,
    pub(super) metrics: SessionPoolMetrics,
    pub(super) upstream_recovery: UpstreamRecoveryState,
    pub(super) reset_recovery: ResetRecoveryState,
}

impl FlowSessionState {
    pub(super) fn new(session_pool_target: usize) -> Self {
        let now = std::time::Instant::now();
        let mut control_send_pool = Vec::with_capacity(super::CONTROL_SEND_POOL_CAPACITY);
        for _ in 0..super::CONTROL_SEND_POOL_CAPACITY {
            control_send_pool.push(super::session_lifecycles::ControlSendCore::new(now, now));
        }
        Self {
            authority: FlowAuthorityState {
                flow: FlowPhase::Unlocked,
                client_leg: LegSessions::default(),
                upstream_leg: LegSessions::default(),
                client_flow: None,
                flow_claim_generation: None,
                pending_icmp_client_lock: None,
                sync_payload: SyncPayloadSlot::default(),
            },
            control: SessionControlState {
                upstream_reply_id_handshake: ReplyIdHandshake::NotRequired,
                control_lease_epoch: 0,
                control_lease_epoch_exhausted: false,
                upstream_pending_key: None,
                upstream_pending_challenge: None,
            },
            client_pool: ClientSessionPool {
                client_active_key: None,
                client_staged_generation: None,
                client_retired_ordinals: OrdinalRetirementWindow::default(),
                client_ready_sessions: Vec::with_capacity(
                    crate::cli::MAX_ICMP_SESSION_POOL_SIZE + MAX_CONCURRENT_SESSION_CANDIDATES,
                ),
                client_generation_authorization: None,
                next_receive_installation_order: 0,
                client_draining_sessions: VecDeque::with_capacity(
                    crate::cli::MAX_ICMP_SESSION_POOL_SIZE,
                ),
            },
            upstream_pool: UpstreamSessionPool {
                upstream_active_key: None,
                upstream_pool_generation: None,
                upstream_ready_sessions: VecDeque::with_capacity(session_pool_target),
                upstream_pool_epoch: 0,
                upstream_pool_epoch_exhausted: false,
                upstream_reserve_handshakes: Vec::with_capacity(MAX_CONCURRENT_SESSION_CANDIDATES),
                upstream_generation_advance: None,
                control_send_pool,
                upstream_draining_sessions: VecDeque::with_capacity(
                    crate::cli::MAX_ICMP_SESSION_POOL_SIZE,
                ),
                session_pool_target,
                next_session_ordinal: 1,
            },
            metrics: SessionPoolMetrics::default(),
            upstream_recovery: UpstreamRecoveryState {
                upstream_recovery_payload: None,
                upstream_same_generation_fallback: None,
                upstream_deferred_peer_controls: VecDeque::with_capacity(
                    MAX_CONCURRENT_SESSION_CANDIDATES + 1,
                ),
                upstream_activation_confirmed: false,
            },
            reset_recovery: ResetRecoveryState {
                client_reset_challenge: None,
                stateless_client_reset_challenges: VecDeque::with_capacity(
                    MAX_STATELESS_RESET_CHALLENGES,
                ),
                reset_challenges_created: 0,
                reset_challenges_reused: 0,
                reset_challenges_consumed: 0,
                reset_challenges_expired: 0,
                reset_responses_rate_limited: 0,
                reset_responses_accepted: 0,
                reset_responses_ignored: 0,
                client_reset_response_budget: ResetResponseBudget::new(),
                stateless_reset_response_budgets: VecDeque::with_capacity(
                    MAX_STATELESS_RESET_CHALLENGES,
                ),
            },
        }
    }
}
use super::{
    ChallengeControl, ClientFlowKey, DeferredPeerControl, DrainingSession,
    GenerationAdvanceHandshake, GenerationAuthorization, MAX_CONCURRENT_SESSION_CANDIDATES,
    MAX_STATELESS_RESET_CHALLENGES, OrdinalRetirementWindow, PoolGeneration, ReadySession,
    ReceiveCandidate, RecoveryPayload, ReplyIdHandshake, ReserveReplyIdHandshake, ResetChallenge,
    ResetResponseBudget, SameGenerationFallback, SessionId, SessionKey,
    StatelessResetResponseBudget, SyncPayloadSlot, TimedPendingIcmpClientLock,
};
use std::collections::VecDeque;
