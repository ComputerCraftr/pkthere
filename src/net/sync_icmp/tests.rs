use super::sync_catchup_window;
use crate::cli::{
    DebugBehavior, DebugLogs, IcmpReplyIdRequest, ListenMode, ReresolveMode, RuntimeConfig,
    RuntimeOptions, SupportedProtocol, TimeoutAction, WorkerFlowMode,
};
use crate::endpoint::LogicalEndpoint;
use crate::net::framing_shim::SessionId;
use crate::net::icmp_sequence::{
    IcmpSequenceCache, SharedIcmpSequenceState, activate_receive_session, current_reply_seq,
    publish_outbound_request_seq, publish_outbound_request_through,
    reserve_and_publish_outbound_request_seq, reserve_outbound_request_seq, reset_sequence_state,
};
use crate::net::payload::{
    C2uSessionControlDecision, PayloadEvent, U2cDecision, classify_c2u_session_control_event,
    classify_u2c_event,
};
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Barrier, Mutex, MutexGuard};
use std::thread;

static SYNC_TEST_LOCK: Mutex<()> = Mutex::new(());

fn lock_sync_state() -> MutexGuard<'static, ()> {
    match SYNC_TEST_LOCK.lock() {
        Ok(g) => g,
        Err(e) => e.into_inner(),
    }
}

fn localhost_endpoint(id: u16) -> LogicalEndpoint {
    LogicalEndpoint::from_socket_addr_with_id(
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, id)),
        id,
    )
}

fn test_config() -> RuntimeConfig {
    RuntimeConfig {
        listen: localhost_endpoint(0),
        listener_source_id_request: IcmpReplyIdRequest::Default,
        listener_reply_id_request: IcmpReplyIdRequest::Default,
        listen_proto: SupportedProtocol::UDP,
        listen_mode: ListenMode::Dynamic,
        listen_str: String::from("UDP:127.0.0.1:0"),
        upstream: localhost_endpoint(0),
        upstream_source_id_request: IcmpReplyIdRequest::Default,
        upstream_reply_id_request: IcmpReplyIdRequest::Default,
        upstream_proto: SupportedProtocol::ICMP,
        upstream_str: String::from("UDP:127.0.0.1:0"),
        options: RuntimeOptions {
            workers: 1,
            worker_flow_mode: WorkerFlowMode::SharedFlow,
            timeout_secs: 1,
            icmp_handshake_timeout_secs: 1,
            on_timeout: TimeoutAction::Drop,
            stats_interval_mins: 60,
            max_payload: 1500,
            icmp_sync_pps: 100,
            icmp_session_pool_size: crate::cli::DEFAULT_ICMP_SESSION_POOL_SIZE,
            reresolve_secs: 0,
            reresolve_mode: ReresolveMode::Upstream,
            debug_reresolve_address_file: None,
            #[cfg(unix)]
            run_as_user: None,
            #[cfg(unix)]
            run_as_group: None,
            debug_behavior: DebugBehavior {
                icmp_kernel_echo_self_handshake: false,
                client_unconnected: false,
                upstream_unconnected: false,
                fast_stats: false,
                force_raw_icmp_wildcard_upstream: false,
            },
            debug_logs: DebugLogs {
                packets: false,
                handshake: false,
                handles: false,
                drops: false,
                packet_dump: false,
            },
        },
    }
}

fn test_user_event(bytes: &[u8], seq: u16, dst_proto: SupportedProtocol) -> PayloadEvent<'_> {
    PayloadEvent::user_payload(1, 1, seq, dst_proto, bytes)
}

fn test_session_control_event(seq: u16, dst_proto: SupportedProtocol) -> PayloadEvent<'static> {
    PayloadEvent::session_control(1, 1, seq, dst_proto, &[], Some(0x9999))
}

fn test_sequence_state() -> SharedIcmpSequenceState {
    let state = SharedIcmpSequenceState::new();
    activate_test_session(&state, SessionId::for_tests());
    state
}

fn activate_test_session(state: &SharedIcmpSequenceState, session_id: SessionId) {
    let mut cache = state.cache();
    activate_receive_session(state, &mut cache, session_id);
}

fn publish_through(state: &SharedIcmpSequenceState, sequence: u16) {
    publish_session_through(state, SessionId::for_tests(), sequence);
}

fn publish_session_through(state: &SharedIcmpSequenceState, session_id: SessionId, sequence: u16) {
    publish_outbound_request_through(state, session_id, sequence);
}

fn test_reply_id_session_control_event(
    seq: u16,
    dst_proto: SupportedProtocol,
    reply_id: u16,
) -> PayloadEvent<'static> {
    PayloadEvent::session_control(1, 1, seq, dst_proto, &[], Some(reply_id))
}

fn allocate_send_sequence(
    c2u: bool,
    event: &PayloadEvent<'_>,
    will_forward: bool,
    sequence_state: &SharedIcmpSequenceState,
    cache: &mut IcmpSequenceCache,
    session_id: Option<SessionId>,
) -> io::Result<Option<u16>> {
    if !will_forward || event.dst_proto() != SupportedProtocol::ICMP {
        return Ok(None);
    }
    if !c2u {
        return Ok(Some(current_reply_seq(sequence_state, cache)));
    }
    let session_id = session_id.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "outbound ICMP frame requires an active session ID",
        )
    })?;
    reserve_and_publish_outbound_request_seq(sequence_state, cache, session_id)
        .map(Some)
        .map_err(io::Error::other)
}

#[test]
fn classify_u2c_concurrent_duplicates_only_allows_one() {
    let _guard = lock_sync_state();
    let cfg = Arc::new(test_config());
    let sequence_state = Arc::new(test_sequence_state());
    let mut seed_cache = sequence_state.cache();
    let seed_event = test_user_event(b"x", 0, SupportedProtocol::ICMP);
    allocate_send_sequence(
        true,
        &seed_event,
        true,
        &sequence_state,
        &mut seed_cache,
        Some(crate::net::framing_shim::SessionId::for_tests()),
    )
    .expect("seed sequence allocation");

    let thread_count = 16;
    let barrier = Arc::new(Barrier::new(thread_count));
    let mut handles = Vec::new();
    for _ in 0..thread_count {
        let b = barrier.clone();
        let c = cfg.clone();
        let s = sequence_state.clone();
        handles.push(thread::spawn(move || {
            let latest = s.latest_for_tests().unwrap_or(0);
            let event = test_user_event(b"race", latest, SupportedProtocol::UDP);
            b.wait();
            classify_u2c_event(&c, &event, &s)
        }));
    }

    let mut success_count = 0;
    let mut dup_count = 0;
    for h in handles {
        match h.join().unwrap() {
            Ok(_) => success_count += 1,
            Err(e) if e.to_string().contains("duplicate") => dup_count += 1,
            Err(e) => panic!("unexpected error: {e}"),
        }
    }
    assert_eq!(success_count, 1);
    assert_eq!(dup_count, thread_count - 1);
}

#[test]
fn classify_u2c_allows_out_of_order_catch_up() {
    let _guard = lock_sync_state();
    let cfg = test_config();
    let shared = test_sequence_state();
    let mut cache = shared.cache();

    let seed_event = test_user_event(b"x", 0, SupportedProtocol::ICMP);
    allocate_send_sequence(
        true,
        &seed_event,
        true,
        &shared,
        &mut cache,
        Some(crate::net::framing_shim::SessionId::for_tests()),
    )
    .expect("seed sequence allocation");
    publish_through(&shared, 100);
    cache.replace_from_shared_snapshot(&shared);

    let seq100 = test_user_event(b"100", 100, SupportedProtocol::UDP);
    assert!(classify_u2c_event(&cfg, &seq100, &shared).is_ok());

    let seq99 = test_user_event(b"99", 99, SupportedProtocol::UDP);
    assert!(classify_u2c_event(&cfg, &seq99, &shared).is_ok());
    assert!(
        classify_u2c_event(&cfg, &seq99, &shared)
            .unwrap_err()
            .to_string()
            .contains("duplicate")
    );

    let catchup_window = sync_catchup_window(cfg.icmp_sync_pps);
    let stale_seq = 100u16.wrapping_sub((catchup_window + 1) as u16);
    let stale = test_user_event(b"stale", stale_seq, SupportedProtocol::UDP);
    assert!(
        classify_u2c_event(&cfg, &stale, &shared)
            .unwrap_err()
            .to_string()
            .contains("stale")
    );
}

#[test]
fn classify_u2c_accepts_latest_and_rejects_stale_and_duplicate() {
    let _guard = lock_sync_state();
    let cfg = test_config();
    let shared = test_sequence_state();

    publish_through(&shared, 1025);

    let stale = test_user_event(b"stale", 0, SupportedProtocol::UDP);
    assert!(
        classify_u2c_event(&cfg, &stale, &shared)
            .unwrap_err()
            .to_string()
            .contains("stale")
    );

    let latest = test_user_event(b"latest", 1025, SupportedProtocol::UDP);
    assert_eq!(
        classify_u2c_event(&cfg, &latest, &shared).unwrap(),
        U2cDecision::ForwardPayload
    );
    let dup = test_user_event(b"latest", 1025, SupportedProtocol::UDP);
    assert!(
        classify_u2c_event(&cfg, &dup, &shared)
            .unwrap_err()
            .to_string()
            .contains("duplicate")
    );
}

#[test]
fn classify_u2c_rejects_future_reply_sequence() {
    let _guard = lock_sync_state();
    let cfg = test_config();
    let shared = test_sequence_state();

    publish_through(&shared, 5);

    let event = test_user_event(b"future", 7, SupportedProtocol::UDP);
    assert!(
        classify_u2c_event(&cfg, &event, &shared)
            .unwrap_err()
            .to_string()
            .contains("future")
    );
    assert_eq!(shared.rejection_counters().future, 1);

    publish_through(&shared, 7);
    assert!(
        classify_u2c_event(&cfg, &event, &shared).is_ok(),
        "future rejection must not consume the dedup slot"
    );
}

#[test]
fn classify_u2c_rejects_apparent_wraparound_within_one_session() {
    let _guard = lock_sync_state();
    let cfg = test_config();
    let shared = test_sequence_state();

    publish_through(&shared, 1);

    let event = test_user_event(b"wrap", u16::MAX, SupportedProtocol::UDP);
    assert!(classify_u2c_event(&cfg, &event, &shared).is_err());
}

#[test]
fn classify_u2c_marks_empty_latest_reply_as_session_control_for_udp_listener() {
    let _guard = lock_sync_state();
    let cfg = test_config();
    let shared = test_sequence_state();
    let mut cache = shared.cache();
    publish_through(&shared, 5);
    cache.replace_from_shared_snapshot(&shared);

    let event = test_session_control_event(5, SupportedProtocol::UDP);
    assert_eq!(
        classify_u2c_event(&cfg, &event, &shared).unwrap(),
        U2cDecision::ConsumeSessionControl
    );
}

#[test]
fn classify_u2c_leaves_duplicate_session_control_to_protocol_state() {
    let _guard = lock_sync_state();
    let cfg = test_config();
    let shared = test_sequence_state();
    let mut cache = shared.cache();
    publish_through(&shared, 5);
    cache.replace_from_shared_snapshot(&shared);

    let control = test_session_control_event(5, SupportedProtocol::UDP);
    assert_eq!(
        classify_u2c_event(&cfg, &control, &shared).unwrap(),
        U2cDecision::ConsumeSessionControl
    );

    assert_eq!(
        classify_u2c_event(
            &cfg,
            &test_session_control_event(5, SupportedProtocol::UDP),
            &shared
        )
        .unwrap(),
        U2cDecision::ConsumeSessionControl
    );
}

#[test]
fn classify_u2c_leaves_stale_session_control_to_protocol_state() {
    let _guard = lock_sync_state();
    let cfg = test_config();
    let shared = test_sequence_state();
    let mut cache = shared.cache();
    publish_through(&shared, 1025);
    cache.replace_from_shared_snapshot(&shared);

    assert_eq!(
        classify_u2c_event(
            &cfg,
            &test_session_control_event(0, SupportedProtocol::UDP),
            &shared
        )
        .unwrap(),
        U2cDecision::ConsumeSessionControl
    );
    assert_eq!(shared.rejection_counters().stale, 0);
}

#[test]
fn classify_u2c_session_control_does_not_consume_data_replay_slot() {
    let _guard = lock_sync_state();
    let cfg = test_config();
    let shared = test_sequence_state();
    let mut cache = shared.cache();
    publish_through(&shared, 5);
    cache.replace_from_shared_snapshot(&shared);

    let control = test_session_control_event(5, SupportedProtocol::UDP);
    assert_eq!(
        classify_u2c_event(&cfg, &control, &shared).unwrap(),
        U2cDecision::ConsumeSessionControl
    );

    let payload = test_user_event(b"latest", 5, SupportedProtocol::UDP);
    assert_eq!(
        classify_u2c_event(&cfg, &payload, &shared).unwrap(),
        U2cDecision::ForwardPayload
    );
}

#[test]
fn prepare_send_assigns_distinct_sequences_to_negotiation_control_and_buffered_payload() {
    let _guard = lock_sync_state();
    let _cfg = test_config();
    let shared = test_sequence_state();
    let mut cache = shared.cache();

    let control = test_reply_id_session_control_event(0, SupportedProtocol::ICMP, 2002);
    let session_id = crate::net::framing_shim::SessionId::for_tests();
    let control_seq =
        allocate_send_sequence(true, &control, true, &shared, &mut cache, Some(session_id))
            .expect("session-control send should allocate ICMP sequence");
    let control_seq = control_seq.expect("session-control destination is ICMP");

    let buffered_payload = test_user_event(b"buffered", 0, SupportedProtocol::ICMP);
    let payload_seq = allocate_send_sequence(
        true,
        &buffered_payload,
        true,
        &shared,
        &mut cache,
        Some(session_id),
    )
    .expect("buffered payload send should allocate ICMP sequence");
    let payload_seq = payload_seq.expect("buffered payload destination is ICMP");

    assert_ne!(control_seq, payload_seq);
    assert_eq!(payload_seq, control_seq.wrapping_add(1));
    assert_eq!(shared.latest_for_tests(), Some(payload_seq));
}

#[test]
fn classify_u2c_forwards_session_control_reply_for_icmp_listener() {
    let _guard = lock_sync_state();
    let mut cfg = test_config();
    cfg.listen_proto = SupportedProtocol::ICMP;
    let shared = test_sequence_state();
    let mut cache = shared.cache();
    publish_through(&shared, 5);
    cache.replace_from_shared_snapshot(&shared);

    let event = test_session_control_event(5, SupportedProtocol::ICMP);
    assert_eq!(
        classify_u2c_event(&cfg, &event, &shared).unwrap(),
        U2cDecision::ForwardSessionControl
    );
}

#[test]
fn classify_c2u_session_control_replies_locally_when_upstream_is_not_icmp() {
    let _guard = lock_sync_state();
    let mut cfg = test_config();
    cfg.upstream_proto = SupportedProtocol::UDP;
    assert_eq!(
        classify_c2u_session_control_event(
            &cfg,
            &test_session_control_event(11, SupportedProtocol::UDP)
        )
        .unwrap(),
        C2uSessionControlDecision::ReplyLocally
    );
}

#[test]
fn classify_c2u_reply_id_session_control_replies_locally_for_icmp_bridge_sync_path() {
    let _guard = lock_sync_state();
    let mut cfg = test_config();
    cfg.listen_proto = SupportedProtocol::ICMP;
    cfg.upstream_proto = SupportedProtocol::ICMP;
    assert_eq!(
        classify_c2u_session_control_event(
            &cfg,
            &test_session_control_event(11, SupportedProtocol::ICMP)
        )
        .unwrap(),
        C2uSessionControlDecision::ReplyLocally
    );
}

#[test]
fn classify_c2u_reply_id_session_control_replies_locally_for_icmp_bridge() {
    let _guard = lock_sync_state();
    let mut cfg = test_config();
    cfg.listen_proto = SupportedProtocol::ICMP;
    cfg.upstream_proto = SupportedProtocol::ICMP;
    assert_eq!(
        classify_c2u_session_control_event(
            &cfg,
            &test_reply_id_session_control_event(11, SupportedProtocol::ICMP, 2002)
        )
        .unwrap(),
        C2uSessionControlDecision::ReplyLocally
    );
}

#[test]
fn classify_u2c_handles_session_control_when_sync_is_disabled() {
    let _guard = lock_sync_state();
    let mut cfg = test_config();
    cfg.icmp_sync_pps = 0;
    let shared = test_sequence_state();

    let event1 = test_session_control_event(1, SupportedProtocol::UDP);
    assert_eq!(
        classify_u2c_event(&cfg, &event1, &shared).unwrap(),
        U2cDecision::ConsumeSessionControl
    );

    cfg.listen_proto = SupportedProtocol::ICMP;
    let event2 = test_session_control_event(2, SupportedProtocol::UDP);
    assert_eq!(
        classify_u2c_event(&cfg, &event2, &shared).unwrap(),
        U2cDecision::ConsumeSessionControl // NOT Forwarded when sync is disabled
    );
}

#[test]
fn classify_u2c_consumes_wire_cadence_packet() {
    let _guard = lock_sync_state();
    let cfg = test_config();
    let shared = test_sequence_state();
    let mut cache = shared.cache();
    for _ in 0..=7 {
        let control = reserve_outbound_request_seq(
            &shared,
            &mut cache,
            crate::net::framing_shim::SessionId::for_tests(),
        )
        .expect("test sequence allocation");
        publish_outbound_request_seq(&shared, &control);
    }
    let event =
        PayloadEvent::cadence_packet(0x1234, 7, crate::net::framing_shim::SessionId::for_tests());
    assert_eq!(
        classify_u2c_event(&cfg, &event, &shared).unwrap(),
        U2cDecision::ConsumeCadence
    );
}

#[test]
fn classify_c2u_handles_session_control_when_sync_is_disabled() {
    let _guard = lock_sync_state();
    let mut cfg = test_config();
    cfg.listen_proto = SupportedProtocol::ICMP;
    cfg.upstream_proto = SupportedProtocol::ICMP;
    cfg.icmp_sync_pps = 0;
    assert_eq!(
        classify_c2u_session_control_event(
            &cfg,
            &test_session_control_event(11, SupportedProtocol::ICMP)
        )
        .unwrap(),
        C2uSessionControlDecision::ReplyLocally // NOT Forwarded when sync is disabled
    );
}

#[test]
fn classify_u2c_forwards_regular_icmp_reply_when_sync_is_disabled() {
    let _guard = lock_sync_state();
    let mut cfg = test_config();
    cfg.icmp_sync_pps = 0;
    let shared = test_sequence_state();
    let event = test_user_event(b"plain-icmp", 77, SupportedProtocol::UDP);
    assert_eq!(
        classify_u2c_event(&cfg, &event, &shared).unwrap(),
        U2cDecision::ForwardPayload
    );
}

#[test]
fn classify_u2c_rejects_duplicate_user_sequence_when_sync_is_disabled() {
    let _guard = lock_sync_state();
    let mut cfg = test_config();
    cfg.icmp_sync_pps = 0;
    let shared = test_sequence_state();
    let event = test_user_event(b"plain-icmp", 77, SupportedProtocol::UDP);
    assert_eq!(
        classify_u2c_event(&cfg, &event, &shared).unwrap(),
        U2cDecision::ForwardPayload
    );

    let duplicate_error = classify_u2c_event(&cfg, &event, &shared)
        .unwrap_err()
        .to_string();
    assert_eq!(duplicate_error, "duplicate ICMP tunnel sequence");
    assert!(!duplicate_error.contains("sync mode"));
}

#[test]
fn classify_u2c_leaves_duplicate_session_control_to_protocol_state_when_sync_is_disabled() {
    let _guard = lock_sync_state();
    let mut cfg = test_config();
    cfg.icmp_sync_pps = 0;
    let shared = test_sequence_state();
    let event = test_reply_id_session_control_event(77, SupportedProtocol::UDP, 4040);
    assert_eq!(
        classify_u2c_event(&cfg, &event, &shared).unwrap(),
        U2cDecision::ConsumeSessionControl
    );

    assert_eq!(
        classify_u2c_event(&cfg, &event, &shared).unwrap(),
        U2cDecision::ConsumeSessionControl
    );
}

#[test]
fn c2u_negotiate_is_idempotently_replyable_before_data_session_activation() {
    let _guard = lock_sync_state();
    let mut cfg = test_config();
    cfg.listen_proto = SupportedProtocol::ICMP;
    cfg.upstream_proto = SupportedProtocol::UDP;
    let shared = SharedIcmpSequenceState::new();
    let event = test_session_control_event(0, SupportedProtocol::UDP);

    assert_eq!(
        classify_c2u_session_control_event(&cfg, &event).unwrap(),
        C2uSessionControlDecision::ReplyLocally
    );
    assert_eq!(
        classify_c2u_session_control_event(&cfg, &event).unwrap(),
        C2uSessionControlDecision::ReplyLocally
    );
    assert_eq!(shared.tracked_receive_session_count_for_tests(), 0);
}

#[test]
fn session_reset_requires_a_new_session_before_sequence_reuse() {
    let _guard = lock_sync_state();
    let cfg = test_config();
    let shared = test_sequence_state();
    let mut cache = shared.cache();
    publish_through(&shared, 12);
    cache.replace_from_shared_snapshot(&shared);
    let event = test_user_event(b"first", 12, SupportedProtocol::UDP);
    assert!(classify_u2c_event(&cfg, &event, &shared).is_ok());

    reset_sequence_state(false, &shared, &mut cache).expect("reset sequence state");
    publish_through(&shared, 12);
    cache.replace_from_shared_snapshot(&shared);
    assert!(
        classify_u2c_event(&cfg, &event, &shared)
            .expect_err("reset must reject data from the old session")
            .to_string()
            .contains("cannot establish")
    );

    let new_session = SessionId::new(2).expect("test session ID is nonzero");
    activate_test_session(&shared, new_session);
    publish_session_through(&shared, new_session, 12);
    let replacement =
        PayloadEvent::icmp_user_payload(1, 1, 12, new_session, SupportedProtocol::UDP, b"second");
    assert!(classify_u2c_event(&cfg, &replacement, &shared).is_ok());
}

#[test]
fn sync_admission_never_treats_sequence_zero_as_a_wrapped_epoch() {
    let _guard = lock_sync_state();
    let cfg = test_config();
    let shared = test_sequence_state();
    publish_through(&shared, u16::MAX);
    let wrapped = test_user_event(b"wrapped", 0, SupportedProtocol::UDP);

    let error = classify_u2c_event(&cfg, &wrapped, &shared)
        .expect_err("one session cannot wrap its 16-bit sync sequence");
    assert!(error.to_string().contains("stale reply sequence"));
}

#[test]
fn single_flow_uses_independent_sync_states() {
    let _guard = lock_sync_state();
    let cfg = test_config();
    let shared_a = test_sequence_state();
    let shared_b = test_sequence_state();

    publish_through(&shared_a, 44);
    publish_through(&shared_b, 44);

    let event = test_user_event(b"a", 44, SupportedProtocol::UDP);
    assert!(classify_u2c_event(&cfg, &event, &shared_a).is_ok());
    assert!(classify_u2c_event(&cfg, &event, &shared_b).is_ok());
}

#[test]
fn sync_catchup_window_clamps() {
    assert_eq!(sync_catchup_window(0), 8);
    assert_eq!(sync_catchup_window(1000), 250);
    assert_eq!(sync_catchup_window(100000), 1024);
}
