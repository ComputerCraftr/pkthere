use super::handshake::HandshakeStart;
use super::{
    ClientCandidateAckLease, ClientFlowReservation, DeferredPeerControl, DroppedReplyIdHandshake,
    ExpiredPendingIcmpClientLock, ExpiredReplyIdHandshake, FlowAuthorityError, FlowMutationError,
    FlowPhase, FlowRuntimeState, FlowSessionState, HandshakeRollbackOutcome,
    MAX_RECEIVE_SESSION_CANDIDATES, MAX_STATELESS_RESET_CHALLENGES, PendingIcmpClientLock,
    PendingIcmpClientLockMismatch, PendingIcmpClientLockSet, ReceiveCandidate, RecoveryPayload,
    RecoveryPayloadRetention, RecoveryPayloadSendCompletion, RecoveryPayloadSendLease,
    RecoveryPayloadSendToken, ReplyIdControlSendCompletion, ReplyIdControlSendLease,
    ReplyIdControlSequenceRecord, ReplyIdHandshake, ReplyIdHandshakeAck,
    ReplyIdHandshakeAckIgnored, ReplyIdHandshakeActivationLease, ReplyIdHandshakeBegin,
    ReplyIdHandshakeCommitToken, ReplyIdHandshakeInvariantError, ReplyIdHandshakeManagerReceipt,
    ReplyIdHandshakeTransitionError, ReplyIdPayloadSendLease, ResetChallenge, ResetChallengeIssue,
    ResetResponseBudget, SameGenerationFallback, StatelessResetResponseBudget,
    TimedPendingIcmpClientLock, UpstreamSessionRecovery, ack_handshake, begin_handshake,
    commit_handshake_session, complete_handshake_activation, complete_handshake_control_send,
    complete_handshake_send, expire_handshake, fresh_nonzero_challenge,
    global_reset_response_budget, handshake, inspect_existing_reset_challenge,
    inspect_stateless_reset_challenge, lease_due_handshake_control, lease_due_handshake_payload,
    mark_handshake_manager_published, poison_handshake_activation, push_draining_session,
    release_handshake_send, release_unsequenced_handshake_control, rollback_handshake,
    session_pool, upstream_data_evidence, upstream_reset_matches,
};
use crate::diagnostics::PacketTraceId;
use crate::flow_key::ClientFlowKey;
use crate::net::framing_shim::{PoolGeneration, ResetRequired, SessionId, SessionKey};
use crate::net::payload::BufferedPayload;
#[cfg(test)]
use crate::net::payload::PayloadEvent;
use std::sync::atomic::Ordering as AtomOrdering;
use std::time::Duration;
use std::time::Instant;

mod client_flow;
mod client_session;
mod handshake_runtime;
mod recovery;
pub(crate) use recovery::UpstreamRecoveryRequest;

impl FlowRuntimeState {
    #[inline]
    pub(super) fn reset_under(
        &self,
        transition: &ClientFlowReservation<'_>,
    ) -> Result<Option<DroppedReplyIdHandshake>, super::FlowAuthorityError> {
        transition
            .assert_current()
            .map_err(super::FlowAuthorityError::from)?;
        let mut sessions =
            crate::runtime_support::lock_authority_or_shutdown(&self.sessions, "flow session");
        let invalidates_flow_authority = sessions.has_flow_authority();
        if invalidates_flow_authority {
            self.advance_activity_generation_under(transition)?;
        }
        let dropped = sessions.reset();
        drop(sessions);
        if invalidates_flow_authority {
            self.invalidate_flow_authority_under(transition)?;
        } else {
            self.invalidate_maintenance_schedule();
        }
        Ok(dropped)
    }

    pub(crate) fn observe_upstream_session_activated(
        &self,
        activated: crate::net::framing_shim::SessionActivated,
        observed_at: Instant,
        evidence: crate::net::icmp_sequence::DataSequenceEvidenceState,
    ) -> Result<bool, ReplyIdHandshakeInvariantError> {
        let mut sessions =
            crate::runtime_support::lock_authority_or_shutdown(&self.sessions, "flow session");
        if sessions.upstream_pool.upstream_active_key != Some(activated.session_key()) {
            return Ok(false);
        }
        let session = activated.session_key().session_id();
        if sessions
            .upstream_recovery
            .upstream_recovery_payload
            .as_ref()
            .is_some_and(|recovery| recovery.session == session && observed_at >= recovery.deadline)
        {
            return Ok(false);
        }
        if evidence == crate::net::icmp_sequence::DataSequenceEvidenceState::Sent {
            sessions.upstream_recovery.upstream_activation_confirmed = true;
            sessions.upstream_recovery.upstream_same_generation_fallback = None;
            if let Some(recovery) = sessions
                .upstream_recovery
                .upstream_recovery_payload
                .as_mut()
                && recovery.session == session
            {
                match recovery.send.observe_recognition()? {
                    super::recovery_core::RecoveryRecognitionDecision::Remove => {
                        sessions.upstream_recovery.upstream_recovery_payload = None;
                    }
                    super::recovery_core::RecoveryRecognitionDecision::Retain => {}
                }
            }
            return Ok(true);
        }
        Ok(false)
    }

    #[cfg(test)]
    pub fn new() -> Self {
        Self::with_session_pool_size(crate::cli::DEFAULT_ICMP_SESSION_POOL_SIZE)
    }

    #[cfg(test)]
    pub(crate) fn with_session_pool_size(session_pool_size: usize) -> Self {
        Self::with_session_pool_size_and_reader_lanes(
            session_pool_size,
            super::topology::DEFAULT_FLOW_READER_LANES,
        )
    }

    pub(crate) fn with_session_pool_size_and_reader_lanes(
        session_pool_size: usize,
        reader_lanes: usize,
    ) -> Self {
        if !(1..=crate::cli::MAX_ICMP_SESSION_POOL_SIZE).contains(&session_pool_size) {
            crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
                "ICMP session pool size bypassed CLI validation"
            ));
        }
        if reader_lanes == 0 {
            crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
                "flow reader lane capacity must be nonzero"
            ));
        }
        let maintenance_origin = Instant::now();
        let mut activity_lanes = Vec::with_capacity(reader_lanes);
        activity_lanes.resize_with(reader_lanes, super::ActivityLane::new);
        let initial_admission = super::FlowAdmissionSnapshot {
            locked: false,
            client_flow: None,
            flow_claim_generation: None,
            pending_icmp_client_lock: None,
            pending_icmp_client_deadline: None,
            client_active_session_key: None,
            client_transmit_session_id: None,
            client_receive_session_id: None,
            upstream_receive_session_id: None,
            upstream_transmit_session_id: None,
            upstream_reply_id_acked: false,
            upstream_handshake_deadline: None,
            client_sessions: super::SessionAdmissionSnapshot::empty(),
            upstream_sessions: super::SessionAdmissionSnapshot::empty(),
        };
        let state = Self {
            activity_lanes: activity_lanes.into_boxed_slice(),
            activity_generation: crate::authority::AuthorityAtomic::new_u64(
                1,
                crate::authority::AtomicProtocolId::ActivityPublication,
            ),
            sessions: crate::authority::AuthorityMutex::new(
                FlowSessionState::new(session_pool_size),
                crate::authority::AuthorityInstance {
                    id: crate::authority::AuthorityId::SessionControl,
                    flow: 0,
                    direction: 0,
                    kind: 0,
                    session: 0,
                },
            ),
            published_admission: crate::authority::AuthorityMutex::new(
                super::PublishedFlowSnapshot {
                    epoch: 0,
                    admission: initial_admission,
                },
                crate::authority::AuthorityInstance {
                    id: crate::authority::AuthorityId::SessionControl,
                    flow: 0,
                    direction: 0,
                    kind: 1,
                    session: 0,
                },
            ),
            control_observations: super::ControlObservationLanes::with_capacity(
                reader_lanes,
                maintenance_origin,
            ),
            client_flow_reservation: crate::net::sock_mgr::transaction_lock::ManagerTransaction::<
                crate::authority::tags::FlowReservation,
            >::new_tagged(0),
            topology: super::topology::FlowTopologyCoordinator::with_reader_lanes(reader_lanes),
            maintenance_epoch: crate::authority::AuthorityAtomic::new_u64(
                0,
                crate::authority::AtomicProtocolId::MaintenanceDeadline,
            ),
            maintenance_epoch_exhausted: crate::authority::AuthorityAtomic::new_bool(
                false,
                crate::authority::AtomicProtocolId::MaintenanceDeadline,
            ),
            maintenance_published_epoch: crate::authority::AuthorityAtomic::new_u64(
                0,
                crate::authority::AtomicProtocolId::MaintenanceDeadline,
            ),
            maintenance_deadline_hint: crate::authority::AuthorityAtomic::new_u64(
                super::NO_MAINTENANCE_DEADLINE,
                crate::authority::AtomicProtocolId::MaintenanceDeadline,
            ),
            maintenance_repair_owner: crate::authority::AuthorityAtomic::new_bool(
                false,
                crate::authority::AtomicProtocolId::MaintenanceRepairOwnership,
            ),
            maintenance_publish: crate::authority::AuthorityMutex::new(
                (),
                crate::authority::AuthorityInstance {
                    id: crate::authority::AuthorityId::Maintenance,
                    flow: 0,
                    direction: 0,
                    kind: 2,
                    session: 0,
                },
            ),
            maintenance_origin,
            maintenance_wakes: std::iter::repeat_with(crate::authority::AuthorityOnceLock::new)
                .take(reader_lanes)
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            maintenance_wake_failures: crate::authority::AuthorityAtomic::new_u64(
                0,
                crate::authority::AtomicProtocolId::DiagnosticCounter,
            ),
        };
        for authority in [
            state.sessions.prewarm(),
            state.published_admission.prewarm(),
            state.maintenance_publish.prewarm(),
        ] {
            authority.unwrap_or_else(|error| {
                crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
                    "flow authority prewarm failed: {error}"
                ))
            });
        }
        state
    }

    pub(crate) fn reserve_control_observation(
        &self,
        lane: usize,
        flow_epoch: u64,
        c2u: bool,
    ) -> std::io::Result<super::ControlObservationReservation<'_>> {
        let observation = self.control_observations.lane(lane).ok_or_else(|| {
            std::io::Error::other("control observation worker lane is out of range")
        })?;
        let generation = observation.begin()?;
        Ok(super::ControlObservationReservation {
            state: self,
            lane,
            generation,
            flow_epoch,
            c2u,
            observed_at: None,
            active: true,
        })
    }

    pub(super) fn release_control_observation(&self, lane: usize, generation: u64) {
        let Some(observation) = self.control_observations.lane(lane) else {
            crate::runtime_support::publish_process_fatal(format_args!(
                "control observation release lane is out of range"
            ));
            return;
        };
        observation.clear(generation, "published observation guard");
        self.invalidate_maintenance_schedule();
    }

    pub(super) fn release_control_observation_reservation(&self, lane: usize, generation: u64) {
        let Some(observation) = self.control_observations.lane(lane) else {
            crate::runtime_support::publish_process_fatal(format_args!(
                "control observation reservation release lane is out of range"
            ));
            return;
        };
        observation.clear(generation, "polling reservation");
        self.invalidate_maintenance_schedule();
    }

    #[cfg(test)]
    pub(crate) fn control_observation_count_for_tests(&self) -> usize {
        self.control_observations.active_count()
    }

    pub(crate) fn register_maintenance_wake(
        &self,
        lane: super::FlowReaderLane,
    ) -> std::io::Result<super::MaintenanceWakeRegistration> {
        let inner = std::sync::Arc::new(super::MaintenanceWakeInner {
            pair: crate::net::managed_socket::ManagedWakePair::new()?,
        });
        let slot = self
            .maintenance_wakes
            .get(lane.index())
            .ok_or_else(|| std::io::Error::other("maintenance wake worker lane is out of range"))?;
        slot.set(std::sync::Arc::downgrade(&inner))
            .map_err(|_| std::io::Error::other("maintenance wake worker lane is already owned"))?;
        Ok(super::MaintenanceWakeRegistration { inner })
    }

    pub(crate) fn invalidate_maintenance_schedule(&self) {
        if self
            .maintenance_epoch
            .try_update(AtomOrdering::Release, AtomOrdering::Relaxed, |epoch| {
                epoch.checked_add(1)
            })
            .is_err()
        {
            self.maintenance_epoch_exhausted
                .store(true, AtomOrdering::Release);
        }
        self.maintenance_deadline_hint
            .fetch_min(0, AtomOrdering::Release);

        self.notify_worker_wakes();
    }

    pub(super) fn notify_worker_wakes(&self) {
        for wake in self
            .maintenance_wakes
            .iter()
            .filter_map(crate::authority::AuthorityOnceLock::get)
            .filter_map(std::sync::Weak::upgrade)
        {
            if wake.pair.notify().is_err()
                && self
                    .maintenance_wake_failures
                    .try_update(AtomOrdering::Relaxed, AtomOrdering::Relaxed, |failures| {
                        Some(failures.saturating_add(1))
                    })
                    .is_err()
            {
                crate::runtime_support::publish_process_fatal(format_args!(
                    "maintenance wake failure accounting rejected a saturating update"
                ));
            }
        }
    }

    pub(crate) fn repair_maintenance_schedule(&self) -> Result<(), ReplyIdHandshakeInvariantError> {
        if self.maintenance_epoch_exhausted.load(AtomOrdering::Acquire) {
            return Err(ReplyIdHandshakeInvariantError);
        }
        let authoritative_epoch = self.maintenance_epoch.load(AtomOrdering::Acquire);
        if self.maintenance_published_epoch.load(AtomOrdering::Acquire) == authoritative_epoch {
            return Ok(());
        }
        let repair = crate::atomic_core::MaintenanceRepairCore::new(
            &self.maintenance_published_epoch,
            &self.maintenance_deadline_hint,
            &self.maintenance_repair_owner,
        );
        let Some(repair) = repair.try_begin() else {
            return Ok(());
        };
        let sessions =
            crate::runtime_support::lock_authority_or_shutdown(&self.sessions, "flow session");
        let _publication = crate::runtime_support::lock_authority_or_shutdown(
            &self.maintenance_publish,
            "maintenance publication",
        );
        if self.maintenance_epoch_exhausted.load(AtomOrdering::Acquire) {
            return Err(ReplyIdHandshakeInvariantError);
        }
        let epoch = self.maintenance_epoch.load(AtomOrdering::Acquire);
        let deadline = sessions.earliest_maintenance_deadline();
        let tick = deadline.map_or(super::NO_MAINTENANCE_DEADLINE, |deadline| {
            let elapsed = deadline.saturating_duration_since(self.maintenance_origin);
            u64::try_from(elapsed.as_nanos())
                .unwrap_or(super::NO_MAINTENANCE_DEADLINE - 1)
                .min(super::NO_MAINTENANCE_DEADLINE - 1)
        });
        repair.publish(epoch, tick);
        drop(_publication);
        drop(sessions);
        Ok(())
    }

    pub(crate) fn maintenance_wait(&self, now: Instant) -> Duration {
        if self.maintenance_epoch_exhausted.load(AtomOrdering::Acquire) {
            return Duration::ZERO;
        }
        let authoritative_epoch = self.maintenance_epoch.load(AtomOrdering::Acquire);
        let published_epoch = self.maintenance_published_epoch.load(AtomOrdering::Acquire);
        if published_epoch != authoritative_epoch {
            return Duration::ZERO;
        }
        let hint = self.maintenance_deadline_hint.load(AtomOrdering::Acquire);
        if hint == super::NO_MAINTENANCE_DEADLINE {
            return super::SESSION_MAINTENANCE_FALLBACK;
        }
        let now_tick = u64::try_from(
            now.saturating_duration_since(self.maintenance_origin)
                .as_nanos(),
        )
        .unwrap_or(super::NO_MAINTENANCE_DEADLINE - 1);
        Duration::from_nanos(hint.saturating_sub(now_tick)).min(super::SESSION_MAINTENANCE_FALLBACK)
    }

    #[inline]
    pub(crate) fn maintenance_due(&self, now: Instant) -> bool {
        self.maintenance_wait(now).is_zero()
    }

    #[inline]
    pub fn is_locked(&self) -> bool {
        crate::runtime_support::lock_authority_or_shutdown(&self.sessions, "flow session")
            .authority
            .flow
            == FlowPhase::Active
    }

    #[inline]
    pub(super) fn reset_send_in_flight(&self) -> bool {
        matches!(
            &crate::runtime_support::lock_authority_or_shutdown(&self.sessions, "flow session")
                .control
                .upstream_reply_id_handshake,
            ReplyIdHandshake::Sending { commit, .. } if commit.cancel_requested()
        )
    }

    #[inline]
    pub(super) fn publish_locked(
        &self,
        transition: &ClientFlowReservation<'_>,
        flow: ClientFlowKey,
        flow_claim_generation: Option<std::num::NonZeroU64>,
    ) -> Result<(), super::FlowAuthorityError> {
        transition
            .assert_current()
            .map_err(super::FlowAuthorityError::from)?;
        let mut sessions =
            crate::runtime_support::lock_authority_or_shutdown(&self.sessions, "flow session");
        let pending_session_changes_authority = sessions
            .authority
            .pending_icmp_client_lock
            .and_then(|pending| pending.candidate.session_key)
            .is_some_and(|pending| sessions.client_pool.client_active_key != Some(pending));
        let changed = sessions.authority.flow != FlowPhase::Active
            || sessions.authority.client_flow != Some(flow)
            || pending_session_changes_authority;
        if let Some(pending) = sessions.authority.pending_icmp_client_lock
            && let Some(session_key) = pending.candidate.session_key
        {
            let session_id = session_key.session_id();
            sessions.authority.client_leg.receive = Some(session_id);
            sessions.authority.client_leg.transmit = Some(session_key.response_session_id());
            sessions.client_pool.client_active_key = Some(session_key);
        }
        sessions.authority.client_flow = Some(flow);
        sessions.authority.flow_claim_generation = flow_claim_generation;
        sessions.authority.flow = FlowPhase::Active;
        sessions.authority.pending_icmp_client_lock = None;
        drop(sessions);
        if changed {
            self.invalidate_flow_authority_under(transition)?;
        }
        Ok(())
    }

    pub(super) fn flow_claim_binding_under(
        &self,
        transition: &ClientFlowReservation<'_>,
    ) -> Result<(Option<ClientFlowKey>, Option<std::num::NonZeroU64>), super::FlowAuthorityError>
    {
        transition
            .assert_current()
            .map_err(super::FlowAuthorityError::from)?;
        let sessions =
            crate::runtime_support::lock_authority_or_shutdown(&self.sessions, "flow session");
        Ok((
            sessions.authority.client_flow,
            sessions.authority.flow_claim_generation,
        ))
    }

    #[inline]
    pub(crate) fn flow_epoch(&self) -> u64 {
        self.topology.published_epoch()
    }

    #[track_caller]
    pub(crate) fn try_topology_read(
        &self,
        lane: super::FlowReaderLane,
    ) -> Result<super::FlowTopologyReadLease<'_>, super::FlowTopologyError> {
        self.topology.try_read_lane(lane)
    }

    pub(crate) fn try_diagnostic_topology_read(
        &self,
    ) -> Result<super::FlowTopologyReadLease<'_>, super::FlowTopologyError> {
        self.topology.try_read_lane(super::FlowReaderLane::new(
            self.topology.reader_lane_count() - 1,
        ))
    }

    pub(crate) fn try_watchdog_topology_read(
        &self,
    ) -> Result<super::FlowTopologyReadLease<'_>, super::FlowTopologyError> {
        self.topology.try_read_lane(super::FlowReaderLane::new(
            self.topology.reader_lane_count() - 2,
        ))
    }

    pub(super) fn invalidate_flow_authority_under(
        &self,
        transition: &ClientFlowReservation<'_>,
    ) -> Result<(), super::FlowAuthorityError> {
        transition
            .assert_current()
            .map_err(super::FlowAuthorityError::from)?;
        let publication_epoch = transition.publication_epoch()?;
        self.publish_admission_snapshot(publication_epoch);
        self.invalidate_maintenance_schedule();
        Ok(())
    }

    pub(super) fn publish_admission_snapshot(&self, publication_epoch: u64) {
        let admission = self.admission_snapshot_under(Instant::now());
        let mut published = crate::runtime_support::lock_authority_or_shutdown(
            &self.published_admission,
            "published flow admission snapshot",
        );
        *published = super::PublishedFlowSnapshot {
            epoch: publication_epoch,
            admission,
        };
        drop(published);
    }

    #[inline]
    #[cfg(test)]
    pub fn record_activity_for_worker(&self, worker_id: usize, t_start: Instant, t_recv: Instant) {
        self.record_activity_for_lane(super::FlowReaderLane::new(worker_id), t_start, t_recv);
    }

    #[inline]
    pub(crate) fn record_activity_for_lane(
        &self,
        lane: super::FlowReaderLane,
        t_start: Instant,
        t_recv: Instant,
    ) {
        let activity_generation = self
            .activity_generation
            .load(std::sync::atomic::Ordering::Acquire);
        let activity_tick_ns = monotonic_tick_ns(t_start, t_recv);
        let lane_index = lane.index();
        let Some(lane) = self.activity_lanes.get(lane_index) else {
            crate::runtime_support::publish_process_fatal(format_args!(
                "worker activity lane {lane_index} exceeds registered capacity"
            ));
            return;
        };
        if crate::atomic_core::publish_activity_lane(
            &lane.publication_sequence,
            &lane.activity_generation,
            &lane.latest_tick,
            activity_generation,
            activity_tick_ns,
        )
        .is_err()
        {
            crate::runtime_support::publish_process_fatal(format_args!(
                "worker activity publication sequence exhausted"
            ));
        }
    }

    #[cfg(test)]
    pub fn record_activity(&self, t_start: Instant, t_recv: Instant) {
        self.record_activity_for_worker(0, t_start, t_recv);
    }

    #[inline]
    pub fn last_activity_tick_ns(&self) -> u64 {
        let expected_generation = self
            .activity_generation
            .load(std::sync::atomic::Ordering::Acquire);
        self.activity_lanes
            .iter()
            .filter_map(|lane| {
                crate::atomic_core::read_activity_lane(
                    &lane.publication_sequence,
                    &lane.activity_generation,
                    &lane.latest_tick,
                    expected_generation,
                )
            })
            .max()
            .unwrap_or(0)
    }

    #[inline]
    pub fn idle_timeout_reached(&self, t_start: Instant, now: Instant, timeout: Duration) -> bool {
        let last_activity_tick_ns = self.last_activity_tick_ns();
        last_activity_tick_ns != 0
            && monotonic_tick_ns(t_start, now).saturating_sub(last_activity_tick_ns)
                >= duration_ns(timeout)
    }

    pub(super) fn advance_activity_generation_under(
        &self,
        transition: &ClientFlowReservation<'_>,
    ) -> Result<(), super::FlowAuthorityError> {
        transition
            .assert_current()
            .map_err(super::FlowAuthorityError::from)?;
        if self
            .activity_generation
            .try_update(
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
                |generation| generation.checked_add(1),
            )
            .is_err()
        {
            crate::runtime_support::publish_process_fatal(format_args!(
                "flow activity generation exhausted"
            ));
            return Err(super::FlowAuthorityError::Reservation(
                crate::net::sock_mgr::transaction_lock::ReservationError::TicketExhausted,
            ));
        }
        Ok(())
    }
}

#[inline]
pub(super) fn monotonic_tick_ns(origin: Instant, instant: Instant) -> u64 {
    duration_ns(instant.saturating_duration_since(origin)).max(1)
}

#[inline]
fn duration_ns(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}
