use super::{
    BufferedPayload, ControlTransactionKey, FlowRuntimeState, HandshakeRollbackOutcome,
    PendingIcmpClientLockSet, ReplyIdControlSendCompletion, ReplyIdHandshake, ReplyIdHandshakeAck,
    ReplyIdHandshakeAckIgnored, ReplyIdHandshakeBegin, ReplyIdHandshakeCommitToken,
    ReplyIdHandshakeInvariantError, ReplyIdHandshakeTransitionError,
};
use crate::cli::SupportedProtocol;
use crate::diagnostics::PacketTraceId;
use crate::endpoint::LogicalEndpoint;
use crate::flow_key::{ClientFlowKey, FlowTuple, SocketLegFlow};
use crate::net::framing_shim::{SessionId, SessionKey};
use crate::net::payload::PayloadEvent;
use std::net::Ipv4Addr;
use std::sync::{Arc, Barrier, mpsc};
use std::thread;
use std::time::{Duration, Instant};

mod multi_worker;
mod rekey_tests;

const RESERVATION_BLOCKED_OBSERVATION: Duration = Duration::from_millis(100);
const RESERVATION_COMPLETION_WAIT: Duration = Duration::from_secs(1);

impl FlowRuntimeState {
    pub fn commit_upstream_reply_id_handshake(
        &self,
        token: ReplyIdHandshakeCommitToken,
    ) -> Result<super::ReplyIdPayloadSendLease, ReplyIdHandshakeTransitionError> {
        let transition = self.reserve_client_flow();
        let result = self
            .mark_upstream_reply_id_manager_published_under(&transition, token)
            .and_then(|receipt| {
                self.commit_upstream_reply_id_handshake_under(&transition, receipt)
            });
        match result {
            Ok(activation) => self.complete_upstream_reply_id_handshake_activation(activation),
            Err(super::FlowMutationError::Operation(error)) => Err(error),
            Err(super::FlowMutationError::Authority(error)) => {
                panic!("test handshake commit lost flow authority: {error}")
            }
        }
    }

    pub(crate) fn reset(&self) -> Option<super::DroppedReplyIdHandshake> {
        let transition = self.reserve_client_flow();
        self.reset_under(&transition)
            .expect("test flow reset must retain reservation and epoch capacity")
    }

    pub(crate) fn set_pending_icmp_client_lock(
        &self,
        pending: super::PendingIcmpClientLock,
        started_s: u64,
        trace: PacketTraceId,
        acknowledge_sequence: u16,
    ) -> Result<PendingIcmpClientLockSet, super::PendingIcmpClientLockMismatch> {
        let now = Instant::now();
        self.set_pending_icmp_client_lock_until(
            pending,
            started_s,
            trace,
            acknowledge_sequence,
            now,
            now + Duration::from_secs(3),
        )
    }

    pub(crate) fn mark_client_candidate_acknowledged(
        &self,
        session_key: SessionKey,
        observed_at: Instant,
    ) -> Result<bool, super::PendingIcmpClientLockMismatch> {
        let Some(lease) = self.begin_client_candidate_ack_send(session_key, observed_at)? else {
            return Ok(false);
        };
        self.complete_client_candidate_ack_send(lease, true)?;
        Ok(true)
    }
}

fn buffered_payload(bytes: &'static [u8]) -> BufferedPayload {
    let event = PayloadEvent::user_payload_plain(SupportedProtocol::ICMP, bytes);
    BufferedPayload::from_event(&event, None)
}

fn traced_payload(bytes: &'static [u8], packet_id: u64) -> BufferedPayload {
    let event = PayloadEvent::user_payload_plain(SupportedProtocol::ICMP, bytes);
    BufferedPayload::from_event(
        &event,
        Some(PacketTraceId {
            worker_id: 2,
            c2u: true,
            packet_id,
        }),
    )
}

pub(super) fn pending_client_lock() -> super::PendingIcmpClientLock {
    let peer = LogicalEndpoint::from_v4(Ipv4Addr::LOCALHOST, 2002);
    let inbound_local = LogicalEndpoint::from_v4(Ipv4Addr::LOCALHOST, 1001);
    let outbound_local = LogicalEndpoint::from_v4(Ipv4Addr::LOCALHOST, 3003);
    let session_key = crate::net::framing_shim::SessionKey::for_tests();
    super::PendingIcmpClientLock {
        flow_key: ClientFlowKey::Icmp(peer),
        session_key: Some(session_key),
        observed_control: Some(super::PendingClientControl::Negotiate {
            reply_id: peer.id(),
        }),
        reset_challenge: 0,
        reset_evidence: None,
        listener_flow: SocketLegFlow::new(
            Some(FlowTuple::new(peer, inbound_local)),
            Some(FlowTuple::new(outbound_local, peer)),
        ),
    }
}

pub(super) fn pending_client_lock_with_session(
    mut pending: super::PendingIcmpClientLock,
    session_key: crate::net::framing_shim::SessionKey,
) -> super::PendingIcmpClientLock {
    let reply_id = pending
        .listener_flow
        .inbound
        .map_or(1, |flow| flow.src.id());
    pending.session_key = Some(session_key);
    pending.observed_control = Some(super::PendingClientControl::Negotiate { reply_id });
    pending
}

fn ack_for_test(
    state: &FlowRuntimeState,
    destination_id: u16,
    instance: u64,
) -> ReplyIdHandshakeAck {
    if let Some(lease) = state.lease_due_upstream_reply_id_negotiation(Instant::now()) {
        state
            .record_upstream_negotiation_sequence(&lease, 0)
            .expect("record test negotiation sequence");
        state.complete_upstream_reply_id_negotiation_send(lease, 0, true, Instant::now());
    }
    state.ack_upstream_reply_id_handshake(destination_id, instance, 0, None)
}

pub(super) fn activate_upstream_session(state: &FlowRuntimeState, session_id: u64) {
    state.begin_upstream_reply_id_handshake(2002, session_id, 1, buffered_payload(b"initial"));
    let ReplyIdHandshakeAck::Matched { token, .. } = ack_for_test(state, 2002, session_id) else {
        panic!("initial session ACK");
    };
    let payload = state
        .commit_upstream_reply_id_handshake(token)
        .expect("initial payload lease");
    assert_eq!(
        state.upstream_session_id().map(|session| session.get()),
        Some(session_id),
        "ACK activates the transmit session before the buffered payload syscall"
    );
    assert!(
        !state
            .complete_upstream_reply_id_payload_send(payload)
            .expect("complete initial payload")
    );
}

pub(super) struct TestDataSend<'cache> {
    reservation: crate::net::icmp_sequence::ArmedOutboundDataSequence<'cache>,
}

impl TestDataSend<'_> {
    pub(super) fn complete(self, sent: bool) -> Option<super::DeferredPeerControl> {
        self.reservation
            .complete(sent)
            .expect("complete production data-sequence evidence")
    }
}

pub(super) fn reserve_data_send<'cache>(
    sequences: &'cache crate::net::icmp_sequence::SharedIcmpSequenceState,
    cache: &'cache mut crate::net::icmp_sequence::IcmpSequenceCache,
    session: crate::net::framing_shim::SessionId,
    expected_sequence: u16,
) -> TestDataSend<'cache> {
    crate::net::icmp_sequence::install_outbound_request_session(sequences, cache, session)
        .expect("prepare production transmit session");
    loop {
        let prepared =
            crate::net::icmp_sequence::claim_prepared_outbound_session(sequences, cache, session)
                .expect("claim production transmit-session capability");
        let mut reservation = crate::worker_support::StableProtocolReservation::reserve(prepared)
            .expect("reserve production transmit sequence");
        let sequence = reservation.sequence();
        crate::net::icmp_sequence::publish_outbound_request_seq(sequences, &reservation);
        if sequence == expected_sequence {
            let reservation = reservation
                .arm_data_evidence()
                .expect("reserve production data-sequence evidence");
            return TestDataSend { reservation };
        }
        assert!(
            sequence < expected_sequence,
            "production allocator skipped the requested test boundary"
        );
    }
}

#[test]
fn delayed_packet_processing_cannot_regress_liveness() {
    let state = FlowRuntimeState::new();
    let start = Instant::now();
    state.record_activity(start, start + Duration::from_secs(9));
    state.record_activity(start, start + Duration::from_secs(3));
    assert_eq!(
        state.last_activity_tick_ns(),
        u64::try_from(Duration::from_secs(9).as_nanos()).expect("test duration fits")
    );
}

#[test]
fn idle_timeout_uses_subsecond_activity_precision() {
    let state = FlowRuntimeState::new();
    let start = Instant::now();
    state.record_activity(start, start + Duration::from_millis(1_900));

    assert!(!state.idle_timeout_reached(
        start,
        start + Duration::from_millis(2_899),
        Duration::from_secs(1),
    ));
    assert!(state.idle_timeout_reached(
        start,
        start + Duration::from_millis(2_900),
        Duration::from_secs(1),
    ));
}

#[test]
fn timeout_writer_revalidates_activity_published_before_reader_drain() {
    let state = FlowRuntimeState::new();
    let start = Instant::now();
    let flow = ClientFlowKey::Icmp(LogicalEndpoint::from_v4(Ipv4Addr::LOCALHOST, 2002));
    let transition = state.reserve_client_flow();
    transition
        .publish_locked(flow)
        .expect("publish locked test flow");
    drop(transition);

    state.record_activity(start, start + Duration::from_secs(11));
    let transition = state.reserve_client_flow();
    let timeout_due = state
        .timeout_due_under(
            &transition,
            start,
            start + Duration::from_secs(12),
            Duration::from_secs(10),
        )
        .expect("revalidate timeout under writer");
    assert!(
        !timeout_due,
        "activity completed before writer admission closed must cancel timeout"
    );
}

#[test]
fn topology_publication_preserves_activity_but_reset_starts_a_new_generation() {
    let state = FlowRuntimeState::new();
    let start = Instant::now();
    let activity = start + Duration::from_secs(2);
    state.record_activity(start, activity);

    let flow = ClientFlowKey::Icmp(LogicalEndpoint::from_v4(Ipv4Addr::LOCALHOST, 2002));
    let transition = state.reserve_client_flow();
    transition
        .publish_locked(flow)
        .expect("publish locked flow under reservation");
    drop(transition);

    assert_eq!(
        state.last_activity_tick_ns(),
        u64::try_from(Duration::from_secs(2).as_nanos()).expect("test duration fits"),
        "routine topology publication must preserve the logical flow idle clock"
    );

    state.reset();
    assert_eq!(
        state.last_activity_tick_ns(),
        0,
        "reset must exclude activity from the retired logical flow"
    );
}

#[test]
fn reply_id_handshake_buffers_until_matching_ack() {
    const INSTANCE: u64 = 17;
    let state = FlowRuntimeState::new();
    assert_eq!(
        state.begin_upstream_reply_id_handshake(2002, INSTANCE, 1, buffered_payload(b"first")),
        ReplyIdHandshakeBegin::Started {
            expected_ack_destination_id: 2002,
            instance: INSTANCE,
            buffered_len: 5,
            buffered_trace: None,
        }
    );
    assert!(matches!(
        ack_for_test(&state, 3003, INSTANCE),
        ReplyIdHandshakeAck::Ignored(ReplyIdHandshakeAckIgnored::WrongDestinationId {
            expected_ack_destination_id: 2002,
            ..
        })
    ));
    assert!(!state.upstream_reply_id_acked());
    assert!(!state.is_locked());

    let ReplyIdHandshakeAck::Matched { token, .. } = ack_for_test(&state, 2002, INSTANCE) else {
        panic!("matching ack must flush buffered payload");
    };
    let flushed = state
        .commit_upstream_reply_id_handshake(token)
        .expect("matching ACK leases buffered payload");
    assert!(state.upstream_reply_id_acked());
    assert!(matches!(
        flushed.as_event(),
        PayloadEvent::UserPayload { bytes, .. } if bytes == b"first"
    ));
}

#[test]
fn reply_id_handshake_preserves_zero_length_first_payload_until_ack() {
    const INSTANCE: u64 = 18;
    let state = FlowRuntimeState::new();
    assert!(matches!(
        state.begin_upstream_reply_id_handshake(2002, INSTANCE, 1, buffered_payload(b"")),
        ReplyIdHandshakeBegin::Started {
            buffered_len: 0,
            ..
        }
    ));
    assert!(matches!(
        ack_for_test(&state, 3003, INSTANCE),
        ReplyIdHandshakeAck::Ignored(ReplyIdHandshakeAckIgnored::WrongDestinationId { .. })
    ));
    assert!(!state.upstream_reply_id_acked());

    let ReplyIdHandshakeAck::Matched { token, .. } = ack_for_test(&state, 2002, INSTANCE) else {
        panic!("matching ack must flush zero-length buffered payload");
    };
    let flushed = state
        .commit_upstream_reply_id_handshake(token)
        .expect("matching ACK leases zero-length payload");
    assert!(matches!(
        flushed.as_event(),
        PayloadEvent::UserPayload { bytes, .. } if bytes.is_empty()
    ));
}

#[test]
fn reply_id_handshake_timeout_drops_buffered_payload() {
    const INSTANCE: u64 = 19;
    let state = FlowRuntimeState::new();
    assert!(matches!(
        state.begin_upstream_reply_id_handshake(3003, INSTANCE, 2, buffered_payload(b"first")),
        ReplyIdHandshakeBegin::Started { .. }
    ));
    assert_eq!(state.expire_reply_id_handshake(Instant::now()), None);
    assert_eq!(
        state.expire_reply_id_handshake(Instant::now() + Duration::from_secs(11)),
        Some(super::ExpiredReplyIdHandshake {
            expected_ack_destination_id: 3003,
            instance: INSTANCE,
            started_s: 2,
            buffered_len: 5,
            buffered_trace: None,
        })
    );
    assert!(matches!(
        ack_for_test(&state, 3003, INSTANCE),
        ReplyIdHandshakeAck::Ignored(ReplyIdHandshakeAckIgnored::NoPending { .. })
    ));
    assert!(!state.upstream_reply_id_acked());
}

#[test]
fn timeout_during_successful_payload_send_does_not_activate_session() {
    const INSTANCE: u64 = 191;
    let state = FlowRuntimeState::new();
    state.begin_upstream_reply_id_handshake(3003, INSTANCE, 2, buffered_payload(b"in-flight"));
    let ReplyIdHandshakeAck::Matched { token, .. } = ack_for_test(&state, 3003, INSTANCE) else {
        panic!("matching ACK must reserve the payload");
    };
    let payload = state
        .commit_upstream_reply_id_handshake(token)
        .expect("matching ACK leases the payload");
    assert_eq!(payload.payload_len(), b"in-flight".len());

    assert_eq!(
        state.expire_reply_id_handshake(Instant::now() + Duration::from_secs(11)),
        None
    );
    assert!(
        state
            .complete_upstream_reply_id_payload_send(payload)
            .expect("in-flight lease remains authoritative")
    );
    assert!(!state.upstream_reply_id_acked());
    assert_eq!(state.upstream_session_id(), None);
}

#[test]
fn timeout_during_failed_payload_send_drops_instead_of_retrying() {
    const INSTANCE: u64 = 192;
    let state = FlowRuntimeState::new();
    state.begin_upstream_reply_id_handshake(3003, INSTANCE, 2, buffered_payload(b"in-flight"));
    let ReplyIdHandshakeAck::Matched { token, .. } = ack_for_test(&state, 3003, INSTANCE) else {
        panic!("matching ACK must reserve the payload");
    };
    let payload = state
        .commit_upstream_reply_id_handshake(token)
        .expect("matching ACK leases the payload");

    assert_eq!(
        state.expire_reply_id_handshake(Instant::now() + Duration::from_secs(11)),
        None
    );
    assert!(
        state
            .release_upstream_reply_id_payload_send(payload)
            .expect("in-flight lease remains authoritative")
    );
    assert!(
        state
            .lease_due_upstream_reply_id_payload(Instant::now() + Duration::from_secs(1))
            .is_none()
    );
    assert!(!state.upstream_reply_id_acked());
}

#[test]
fn reset_during_payload_send_preserves_the_lease_until_completion() {
    const INSTANCE: u64 = 193;
    let state = FlowRuntimeState::new();
    state.begin_upstream_reply_id_handshake(3003, INSTANCE, 2, buffered_payload(b"in-flight"));
    let ReplyIdHandshakeAck::Matched { token, .. } = ack_for_test(&state, 3003, INSTANCE) else {
        panic!("matching ACK must reserve the payload");
    };
    let payload = state
        .commit_upstream_reply_id_handshake(token)
        .expect("matching ACK leases the payload");
    assert_eq!(payload.payload_len(), b"in-flight".len());

    assert_eq!(state.reset(), None);
    assert!(
        state
            .reserve_client_flow()
            .is_locked()
            .expect("reservation"),
        "a replacement flow cannot publish while the old send lease is in flight"
    );
    assert!(
        state
            .complete_upstream_reply_id_payload_send(payload)
            .expect("reset keeps the in-flight token authoritative")
    );
    assert!(
        !state
            .reserve_client_flow()
            .is_locked()
            .expect("reservation")
    );
    assert!(!state.is_locked());
    assert_eq!(state.upstream_session_id(), None);
}

#[test]
fn client_flow_reservation_does_not_hold_its_internal_mutex() {
    let state = FlowRuntimeState::new();
    let reservation = state.reserve_client_flow();
    assert!(
        state.client_flow_mutex_is_available_for_test(),
        "logical flow reservation must release the implementation mutex before backend I/O"
    );
    reservation
        .assert_current()
        .expect("reservation remains current");
}

#[test]
fn client_flow_reservation_commit_and_rollback_are_consuming() {
    let state = FlowRuntimeState::new();
    state
        .reserve_client_flow()
        .commit()
        .expect("commit consumes both reservation authorities");
    state
        .reserve_client_flow()
        .rollback()
        .expect("rollback consumes both reservation authorities");
    state
        .reserve_client_flow()
        .commit()
        .expect("neither completion path leaves an owner token behind");
}

#[test]
fn client_flow_reservation_unwind_emergency_cleanup_releases_once() {
    let state = FlowRuntimeState::new();
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _reservation = state.reserve_client_flow();
        panic!("exercise reservation emergency cleanup");
    }));
    assert!(unwind.is_err());
    state
        .reserve_client_flow()
        .commit()
        .expect("unwind cleanup releases the reservation exactly once");
}

#[test]
fn receive_commit_reservation_serializes_concurrent_flow_reset() {
    let state = Arc::new(FlowRuntimeState::new());
    let flow = pending_client_lock().flow_key;
    state
        .reserve_client_flow()
        .publish_locked(flow)
        .expect("publish flow");
    let epoch_before = state.flow_epoch();
    let receive_commit = state.reserve_client_flow();
    assert!(state.client_flow_mutex_is_available_for_test());

    let start = Arc::new(Barrier::new(2));
    let reset_state = Arc::clone(&state);
    let reset_start = Arc::clone(&start);
    let (completed_tx, completed_rx) = mpsc::channel();
    let resetter = thread::spawn(move || {
        reset_start.wait();
        let reset = reset_state.reserve_client_flow();
        let dropped = reset.reset();
        completed_tx
            .send(dropped)
            .expect("publish serialized reset result");
    });

    start.wait();
    assert!(
        completed_rx
            .recv_timeout(RESERVATION_BLOCKED_OBSERVATION)
            .is_err(),
        "flow reset must not cross a live receive-commit reservation"
    );
    receive_commit
        .assert_current()
        .expect("receive reservation remains current");
    assert_eq!(state.flow_epoch(), epoch_before);

    drop(receive_commit);
    let _reset_result = completed_rx
        .recv_timeout(RESERVATION_COMPLETION_WAIT)
        .expect("reset completes after receive authority is released");
    resetter.join().expect("join serialized reset");
    assert!(state.flow_epoch() > epoch_before);
    assert!(!state.is_locked());
}

#[test]
fn flow_reader_lane_blocks_expiry_writer_until_stable_packet_finishes() {
    let state = Arc::new(FlowRuntimeState::new());
    let flow = pending_client_lock().flow_key;
    state
        .reserve_client_flow()
        .publish_locked(flow)
        .expect("publish flow");
    let epoch_before = state.flow_epoch();
    let reader = state
        .try_topology_read(super::FlowReaderLane::new(0))
        .expect("acquire stable packet flow lane");

    let writer_state = Arc::clone(&state);
    let (started_tx, started_rx) = mpsc::channel();
    let (completed_tx, completed_rx) = mpsc::channel();
    let writer = thread::spawn(move || {
        started_tx.send(()).expect("announce expiry writer");
        let reservation = writer_state.reserve_client_flow();
        let dropped = reservation.reset();
        completed_tx
            .send(dropped)
            .expect("publish expiry writer result");
    });

    started_rx
        .recv_timeout(RESERVATION_COMPLETION_WAIT)
        .expect("expiry writer starts");
    assert!(
        completed_rx
            .recv_timeout(RESERVATION_BLOCKED_OBSERVATION)
            .is_err(),
        "a lifecycle expiry writer must drain the stable packet lane before mutating flow state"
    );
    assert_eq!(state.flow_epoch(), epoch_before);
    assert!(state.is_locked());

    drop(reader);
    let _dropped = completed_rx
        .recv_timeout(RESERVATION_COMPLETION_WAIT)
        .expect("expiry writer completes after stable packet");
    writer.join().expect("join expiry writer");
    assert!(state.flow_epoch() > epoch_before);
    assert!(!state.is_locked());
}

#[test]
fn rollback_publishes_an_equivalent_snapshot_at_the_fresh_epoch() {
    let state = FlowRuntimeState::new();
    let mut cache = super::FlowSnapshotCache::new();
    let initial = state
        .try_topology_read(super::FlowReaderLane::new(0))
        .expect("initial read");
    let initial_snapshot = state
        .admission_snapshot_with_read(&initial, &mut cache, Instant::now())
        .expect("initial snapshot");
    let initial_locked = initial_snapshot.locked;
    let initial_client_flow = initial_snapshot.client_flow;
    assert_eq!(cache.reload_count(), 1);
    let initial_epoch = initial.transaction_epoch();
    drop(initial);

    let reservation = state.reserve_client_flow();
    drop(reservation);

    let read = state
        .try_topology_read(super::FlowReaderLane::new(0))
        .expect("post-rollback read");
    let refreshed = state
        .admission_snapshot_with_read(&read, &mut cache, Instant::now())
        .expect("rollback snapshot");
    assert!(read.transaction_epoch() > initial_epoch);
    assert_eq!(refreshed.locked, initial_locked);
    assert_eq!(refreshed.client_flow, initial_client_flow);
    assert_eq!(cache.reload_count(), 2);
}

#[test]
fn stable_snapshot_cache_borrows_one_publication_without_per_packet_copy_or_allocation() {
    const PACKET_COUNT: usize = 10_000;
    let state = FlowRuntimeState::new();
    let mut cache = super::FlowSnapshotCache::new();
    let read = state
        .try_topology_read(super::FlowReaderLane::new(0))
        .expect("stable flow read");
    let first_address = state
        .admission_snapshot_with_read(&read, &mut cache, Instant::now())
        .map(|snapshot| std::ptr::from_ref(snapshot) as usize)
        .expect("initial cache publication");
    assert_eq!(cache.reload_count(), 1);

    let (all_borrowed, allocations) = crate::allocation_test_support::count_allocations(|| {
        (0..PACKET_COUNT).all(|_| {
            state
                .admission_snapshot_with_read(&read, &mut cache, Instant::now())
                .map(|snapshot| std::ptr::from_ref(snapshot) as usize == first_address)
                .unwrap_or(false)
        })
    });

    assert!(all_borrowed);
    assert_eq!(allocations, 0);
    assert_eq!(cache.reload_count(), 1);
    assert!(
        std::mem::size_of::<super::PacketFlowSnapshot>()
            < std::mem::size_of::<super::FlowAdmissionSnapshot>()
    );
}

#[test]
fn consumed_topology_rollback_already_has_its_equivalent_snapshot() {
    let state = FlowRuntimeState::new();
    let mut reservation = state.reserve_client_flow();
    {
        let _visibility = reservation
            .reserve_topology_until(Instant::now() + Duration::from_secs(1))
            .expect("consume topology reservation");
    }
    drop(reservation);

    let mut cache = super::FlowSnapshotCache::new();
    let read = state
        .try_topology_read(super::FlowReaderLane::new(0))
        .expect("read after consumed rollback");
    let snapshot = state
        .admission_snapshot_with_read(&read, &mut cache, Instant::now())
        .expect("equivalent snapshot was staged before topology ownership transfer");
    assert_eq!(state.flow_epoch(), read.transaction_epoch());
    assert!(!snapshot.locked);
}

#[test]
fn handshake_preserves_origin_trace_through_ack_and_timeout() {
    const INSTANCE: u64 = 20;
    let state = FlowRuntimeState::new();
    state.begin_upstream_reply_id_handshake(3003, INSTANCE, 2, traced_payload(b"ack", 41));
    let ReplyIdHandshakeAck::Matched { buffered_trace, .. } = ack_for_test(&state, 3003, INSTANCE)
    else {
        panic!("matching ACK must release payload");
    };
    assert_eq!(buffered_trace.map(|trace| trace.packet_id), Some(41));

    let state = FlowRuntimeState::new();
    state.begin_upstream_reply_id_handshake(3003, INSTANCE, 2, traced_payload(b"timeout", 42));
    let expired = state
        .expire_reply_id_handshake(Instant::now() + Duration::from_secs(11))
        .expect("handshake expires");
    assert_eq!(
        expired.buffered_trace.map(|trace| trace.packet_id),
        Some(42)
    );
}

#[test]
fn reply_id_handshake_preserves_first_payload_while_pending() {
    const INSTANCE: u64 = 21;
    let state = FlowRuntimeState::new();
    let started =
        state.begin_upstream_reply_id_handshake(2002, INSTANCE, 1, buffered_payload(b"first"));
    assert!(matches!(started, ReplyIdHandshakeBegin::Started { .. }));
    assert!(started.should_send_control());

    let reused = state.begin_upstream_reply_id_handshake(2002, 22, 2, buffered_payload(b"second"));
    assert!(matches!(
        reused,
        ReplyIdHandshakeBegin::PendingReused {
            expected_ack_destination_id: 2002,
            started_s: 1,
            buffered_len: 5,
            ..
        }
    ));
    assert!(!reused.should_send_control());

    let ReplyIdHandshakeAck::Matched { token, .. } = ack_for_test(&state, 2002, INSTANCE) else {
        panic!("matching ack must flush the first payload");
    };
    let payload = state
        .commit_upstream_reply_id_handshake(token)
        .expect("matching ACK leases the first payload");
    assert!(matches!(
        payload.as_event(),
        PayloadEvent::UserPayload { bytes, .. } if bytes == b"first"
    ));
}

#[test]
fn negotiation_retries_have_exactly_one_lease_and_delayed_ack_remains_valid() {
    const INSTANCE: u64 = 0xfeed;
    let state = Arc::new(FlowRuntimeState::new());
    state.begin_upstream_reply_id_handshake(2002, INSTANCE, 1, buffered_payload(b"first"));
    let due = Instant::now() + Duration::from_secs(1);
    let barrier = Arc::new(Barrier::new(8));
    let workers = (0..8)
        .map(|_| {
            let state = Arc::clone(&state);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                state.lease_due_upstream_reply_id_negotiation(due)
            })
        })
        .collect::<Vec<_>>();
    let leases = workers
        .into_iter()
        .filter_map(|worker| worker.join().expect("join negotiation lease worker"))
        .collect::<Vec<_>>();
    assert_eq!(leases.len(), 1, "one worker owns each due retry");
    let first = leases.into_iter().next().expect("one negotiation lease");
    let first_session_id = first.session_id;
    state
        .record_upstream_negotiation_sequence(&first, 7)
        .expect("record first negotiation sequence");
    assert_eq!(
        state.complete_upstream_reply_id_negotiation_send(first, 7, true, due),
        ReplyIdControlSendCompletion::RetryScheduled
    );

    let second = state
        .lease_due_upstream_reply_id_negotiation(due + Duration::from_secs(1))
        .expect("the pending negotiation remains durably retryable");
    assert_eq!(second.session_id, first_session_id);
    state
        .record_upstream_negotiation_sequence(&second, 8)
        .expect("record later negotiation sequence");
    assert!(matches!(
        state.ack_upstream_reply_id_handshake(2002, INSTANCE, 9, None),
        ReplyIdHandshakeAck::Ignored(ReplyIdHandshakeAckIgnored::UnsentSequence {
            observed_sequence: 9,
            ..
        })
    ));

    let ReplyIdHandshakeAck::Matched { token, .. } =
        state.ack_upstream_reply_id_handshake(2002, INSTANCE, 7, None)
    else {
        panic!("an ACK for the current session remains valid after a later retry");
    };
    assert_eq!(
        state.complete_upstream_reply_id_negotiation_send(second, 8, true, due),
        ReplyIdControlSendCompletion::HandshakeAdvanced
    );
    let payload = state
        .commit_upstream_reply_id_handshake(token)
        .expect("delayed ACK releases the original payload");
    assert!(matches!(
        payload.as_event(),
        PayloadEvent::UserPayload { bytes, .. } if bytes == b"first"
    ));
}

#[test]
fn reset_invalidates_an_outstanding_negotiation_lease() {
    let state = FlowRuntimeState::new();
    state.begin_upstream_reply_id_handshake(2002, 77, 1, buffered_payload(b"first"));
    let lease = state
        .lease_due_upstream_reply_id_negotiation(Instant::now() + Duration::from_secs(1))
        .expect("negotiation lease");
    let dropped = state.reset().expect("reset drops buffered first payload");
    assert_eq!(dropped.instance, 77);
    assert_eq!(
        state
            .record_upstream_negotiation_sequence(&lease, 0)
            .expect("reset is a typed lease outcome"),
        super::ReplyIdControlSequenceRecord::ResetWon
    );
    assert_eq!(
        state.complete_upstream_reply_id_negotiation_send(lease, 0, false, Instant::now()),
        ReplyIdControlSendCompletion::ResetWon
    );
}

#[test]
fn control_lease_epoch_exhaustion_never_wraps_or_reuses_a_token() {
    let mut epoch = u64::MAX - 1;
    let mut exhausted = false;
    super::advance_nonwrapping_epoch(&mut epoch, &mut exhausted);
    assert_eq!(epoch, u64::MAX);
    assert!(!exhausted);
    super::advance_nonwrapping_epoch(&mut epoch, &mut exhausted);
    assert_eq!(epoch, u64::MAX);
    assert!(exhausted);
}

// The deadline/epoch state is covered by interpreter-safe tests. This test
// additionally verifies the UDP wake channel, which requires native sockets.
#[cfg(not(miri))]
#[test]
fn maintenance_wake_coalesces_and_repairs_a_stale_early_hint() {
    const WAKE_DELIVERY_DEADLINE: Duration = Duration::from_millis(100);
    let state = FlowRuntimeState::new();
    let wake = state
        .register_maintenance_wake(super::FlowReaderLane::for_worker(
            0,
            crate::cli::WorkerFlowMode::SharedFlow,
        ))
        .expect("create maintenance wake pair");

    state.invalidate_maintenance_schedule();
    state.invalidate_maintenance_schedule();
    assert_eq!(
        state.maintenance_wait(Instant::now()),
        Duration::ZERO,
        "an unpublished epoch must force immediate authoritative repair"
    );

    let mut byte = [0_u8; 1];
    let deadline = Instant::now() + WAKE_DELIVERY_DEADLINE;
    loop {
        match wake.receiver().recv(&mut byte) {
            Ok(length) => {
                assert_eq!(length, 1);
                break;
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                std::thread::yield_now();
            }
            Err(error) => panic!("receive one wake before deadline: {error}"),
        }
    }
    assert_eq!(
        wake.receiver()
            .recv(&mut byte)
            .expect_err("coalescing permits only one unread datagram")
            .kind(),
        std::io::ErrorKind::WouldBlock
    );

    wake.drain().expect("drain wake pair");
    state
        .repair_maintenance_schedule()
        .expect("repair maintenance schedule");
    assert_eq!(
        state
            .maintenance_published_epoch
            .load(std::sync::atomic::Ordering::Acquire),
        state
            .maintenance_epoch
            .load(std::sync::atomic::Ordering::Acquire)
    );
    assert_eq!(
        state
            .maintenance_deadline_hint
            .load(std::sync::atomic::Ordering::Acquire),
        super::NO_MAINTENANCE_DEADLINE
    );
    assert_eq!(
        state.maintenance_wait(Instant::now()),
        super::SESSION_MAINTENANCE_FALLBACK
    );
    assert!(
        !state.maintenance_due(Instant::now()),
        "a repaired no-deadline schedule must keep packet workers out of broad retry authority"
    );
}

#[test]
fn maintenance_epoch_exhaustion_fails_closed_without_wrapping() {
    let state = FlowRuntimeState::new();
    state
        .maintenance_epoch
        .store(u64::MAX, std::sync::atomic::Ordering::Release);

    state.invalidate_maintenance_schedule();

    assert_eq!(
        state
            .maintenance_epoch
            .load(std::sync::atomic::Ordering::Acquire),
        u64::MAX
    );
    assert!(state.repair_maintenance_schedule().is_err());
    assert_eq!(state.maintenance_wait(Instant::now()), Duration::ZERO);
    assert!(
        state.maintenance_due(Instant::now()),
        "an invalid schedule must force the fail-closed maintenance path"
    );
}

#[test]
fn maximum_handshake_retry_schedule_cannot_wrap_a_candidate_sequence() {
    let attempts =
        super::maximum_handshake_retry_attempts(crate::cli::MAX_ICMP_HANDSHAKE_TIMEOUT_SECS);
    assert_eq!(attempts, super::MAX_HANDSHAKE_RETRY_ATTEMPTS);
    assert!(
        attempts < u16::MAX as u32 + 1,
        "the maximum accepted handshake timeout must expire before sequence reuse"
    );
}

mod handshake_closure;
mod handshake_completion;
