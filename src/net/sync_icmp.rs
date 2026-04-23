use crate::cli::RuntimeConfig;
use crate::net::icmp_sequence::{IcmpSequenceCache, SharedIcmpSequenceState};

use std::io;

const MIN_CATCHUP_WINDOW: usize = 8;
const MAX_CATCHUP_WINDOW: usize = 1024;

#[inline]
pub(crate) fn sync_catchup_window(icmp_sync_pps: u32) -> usize {
    (icmp_sync_pps as usize)
        .saturating_div(4)
        .clamp(MIN_CATCHUP_WINDOW, MAX_CATCHUP_WINDOW)
}

pub(crate) fn validate_u2c_sync(
    cfg: &RuntimeConfig,
    icmp_seq: u16,
    sequence_state: &SharedIcmpSequenceState,
    sequence_cache: &mut IcmpSequenceCache,
) -> io::Result<()> {
    if !cfg.is_icmp_sync_enabled() {
        return Ok(());
    }

    sequence_cache.refresh_from_shared(sequence_state);
    if !sequence_cache.latest_valid {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ICMP sync mode: reply arrived before any request",
        ));
    }

    let latest_seq = sequence_cache.latest_sent_seq;
    let lag = latest_seq.wrapping_sub(icmp_seq) as usize;
    let catchup_window = sync_catchup_window(cfg.icmp_sync_pps);
    if lag > catchup_window {
        let ahead = icmp_seq.wrapping_sub(latest_seq);
        let msg = if ahead != 0 && ahead <= u16::MAX / 2 {
            "ICMP sync mode: future reply sequence"
        } else {
            "ICMP sync mode: stale reply sequence"
        };
        return Err(io::Error::new(io::ErrorKind::InvalidData, msg));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{RuntimeConfig, sync_catchup_window, validate_u2c_sync};
    use crate::cli::{
        DebugBehavior, DebugLogs, IcmpReplyIdRequest, ListenMode, ReresolveMode, RuntimeOptions,
        SupportedProtocol, TimeoutAction, WorkerFlowMode,
    };
    use crate::net::icmp_sequence::{SharedIcmpSequenceState, reset_sequence_state};
    use crate::net::params::CanonicalAddr;
    use crate::net::payload::{
        C2uSessionControlDecision, PayloadEvent, U2cDecision, allocate_send_sequence,
        classify_c2u_session_control_event, classify_u2c_event,
    };
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::sync::atomic::Ordering as AtomOrdering;
    use std::sync::{Arc, Barrier, Mutex, MutexGuard};
    use std::thread;

    static SYNC_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn lock_sync_state() -> MutexGuard<'static, ()> {
        match SYNC_TEST_LOCK.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        }
    }

    fn localhost_canonical(id: u16) -> CanonicalAddr {
        CanonicalAddr::new(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, id)),
            id,
        )
    }

    fn test_config() -> RuntimeConfig {
        RuntimeConfig {
            listen: localhost_canonical(0),
            listener_source_id_request: IcmpReplyIdRequest::Default,
            listener_reply_id_request: IcmpReplyIdRequest::Default,
            listen_proto: SupportedProtocol::UDP,
            listen_mode: ListenMode::Dynamic,
            listen_str: String::from("UDP:127.0.0.1:0"),
            upstream: localhost_canonical(0),
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
        PayloadEvent::user_payload(0, 0, seq, dst_proto, bytes)
    }

    fn test_session_control_event(seq: u16, dst_proto: SupportedProtocol) -> PayloadEvent<'static> {
        PayloadEvent::session_control(0, 0, seq, dst_proto, &[], Some(0x9999))
    }

    fn test_reply_id_session_control_event(
        seq: u16,
        dst_proto: SupportedProtocol,
        reply_id: u16,
    ) -> PayloadEvent<'static> {
        PayloadEvent::session_control(0, 0, seq, dst_proto, &[], Some(reply_id))
    }

    fn reset_request_counter() {
        crate::net::icmp_sequence::reset_request_counter_for_tests();
    }

    #[test]
    fn classify_u2c_concurrent_duplicates_only_allows_one() {
        let _guard = lock_sync_state();
        reset_request_counter();
        let cfg = Arc::new(test_config());
        let sequence_state = Arc::new(SharedIcmpSequenceState::new());
        let mut seed_cache = sequence_state.cache();
        seed_cache.generation = sequence_state.generation.0.load(AtomOrdering::Relaxed);
        let seed_event = test_user_event(b"x", 0, SupportedProtocol::ICMP);
        allocate_send_sequence(true, &seed_event, true, &sequence_state, &mut seed_cache);

        let thread_count = 16;
        let barrier = Arc::new(Barrier::new(thread_count));
        let mut handles = Vec::new();
        for _ in 0..thread_count {
            let b = barrier.clone();
            let c = cfg.clone();
            let s = sequence_state.clone();
            handles.push(thread::spawn(move || {
                let cache = s.cache();
                let event = test_user_event(b"race", cache.latest_sent_seq, SupportedProtocol::UDP);
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
        reset_request_counter();
        let cfg = test_config();
        let shared = SharedIcmpSequenceState::new();
        let mut cache = shared.cache();

        let seed_event = test_user_event(b"x", 0, SupportedProtocol::ICMP);
        allocate_send_sequence(true, &seed_event, true, &shared, &mut cache);
        shared.latest.seq.store(100, AtomOrdering::Relaxed);
        shared.latest.valid.store(true, AtomOrdering::Relaxed);
        cache.refresh_from_shared(&shared);

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
        assert!(classify_u2c_event(&cfg, &stale, &shared).is_ok());
        assert!(
            validate_u2c_sync(&cfg, stale_seq, &shared, &mut cache)
                .unwrap_err()
                .to_string()
                .contains("stale")
        );
    }

    #[test]
    fn classify_u2c_accepts_latest_and_rejects_stale_and_duplicate() {
        let _guard = lock_sync_state();
        reset_request_counter();
        let cfg = test_config();
        let shared = SharedIcmpSequenceState::new();
        let mut cache = shared.cache();

        shared.latest.seq.store(1025, AtomOrdering::Relaxed);
        shared.latest.valid.store(true, AtomOrdering::Relaxed);
        cache.refresh_from_shared(&shared);

        let stale = test_user_event(b"stale", 0, SupportedProtocol::UDP);
        assert!(classify_u2c_event(&cfg, &stale, &shared).is_ok());
        assert!(
            validate_u2c_sync(&cfg, 0, &shared, &mut cache)
                .unwrap_err()
                .to_string()
                .contains("stale")
        );

        let latest = test_user_event(b"latest", 1025, SupportedProtocol::UDP);
        assert_eq!(
            classify_u2c_event(&cfg, &latest, &shared).unwrap(),
            U2cDecision::ForwardPayload
        );
        assert!(validate_u2c_sync(&cfg, 1025, &shared, &mut cache).is_ok());

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
        reset_request_counter();
        let cfg = test_config();
        let shared = SharedIcmpSequenceState::new();
        let mut cache = shared.cache();

        shared.latest.seq.store(5, AtomOrdering::Relaxed);
        shared.latest.valid.store(true, AtomOrdering::Relaxed);
        cache.refresh_from_shared(&shared);

        let event = test_user_event(b"future", 7, SupportedProtocol::UDP);
        assert!(classify_u2c_event(&cfg, &event, &shared).is_ok());
        assert!(
            validate_u2c_sync(&cfg, 7, &shared, &mut cache)
                .unwrap_err()
                .to_string()
                .contains("future")
        );
    }

    #[test]
    fn classify_u2c_handles_wraparound_within_window() {
        let _guard = lock_sync_state();
        reset_request_counter();
        let cfg = test_config();
        let shared = SharedIcmpSequenceState::new();
        let mut cache = shared.cache();

        shared.latest.seq.store(1, AtomOrdering::Relaxed);
        shared.latest.valid.store(true, AtomOrdering::Relaxed);
        cache.refresh_from_shared(&shared);

        let event = test_user_event(b"wrap", u16::MAX, SupportedProtocol::UDP);
        assert_eq!(
            classify_u2c_event(&cfg, &event, &shared).unwrap(),
            U2cDecision::ForwardPayload
        );
        assert!(validate_u2c_sync(&cfg, u16::MAX, &shared, &mut cache).is_ok());
    }

    #[test]
    fn classify_u2c_marks_empty_latest_reply_as_session_control_for_udp_listener() {
        let _guard = lock_sync_state();
        let cfg = test_config();
        let shared = SharedIcmpSequenceState::new();
        let mut cache = shared.cache();
        shared.latest.seq.store(5, AtomOrdering::Relaxed);
        shared.latest.valid.store(true, AtomOrdering::Relaxed);
        cache.refresh_from_shared(&shared);

        let event = test_session_control_event(5, SupportedProtocol::UDP);
        assert_eq!(
            classify_u2c_event(&cfg, &event, &shared).unwrap(),
            U2cDecision::ConsumeSessionControl
        );
    }

    #[test]
    fn classify_u2c_rejects_duplicate_session_control_sequence() {
        let _guard = lock_sync_state();
        let cfg = test_config();
        let shared = SharedIcmpSequenceState::new();
        let mut cache = shared.cache();
        shared.latest.seq.store(5, AtomOrdering::Relaxed);
        shared.latest.valid.store(true, AtomOrdering::Relaxed);
        cache.refresh_from_shared(&shared);

        let control = test_session_control_event(5, SupportedProtocol::UDP);
        assert_eq!(
            classify_u2c_event(&cfg, &control, &shared).unwrap(),
            U2cDecision::ConsumeSessionControl
        );

        let duplicate = test_session_control_event(5, SupportedProtocol::UDP);
        assert!(
            classify_u2c_event(&cfg, &duplicate, &shared)
                .unwrap_err()
                .to_string()
                .contains("duplicate")
        );
    }

    #[test]
    fn classify_u2c_rejects_stale_session_control_sequence() {
        let _guard = lock_sync_state();
        let cfg = test_config();
        let shared = SharedIcmpSequenceState::new();
        let mut cache = shared.cache();
        shared.latest.seq.store(1025, AtomOrdering::Relaxed);
        shared.latest.valid.store(true, AtomOrdering::Relaxed);
        cache.refresh_from_shared(&shared);

        let stale = test_session_control_event(0, SupportedProtocol::UDP);
        assert!(classify_u2c_event(&cfg, &stale, &shared).is_ok());
        assert!(
            validate_u2c_sync(&cfg, 0, &shared, &mut cache)
                .unwrap_err()
                .to_string()
                .contains("stale")
        );
    }

    #[test]
    fn classify_u2c_session_control_consumes_dedup_slot() {
        let _guard = lock_sync_state();
        let cfg = test_config();
        let shared = SharedIcmpSequenceState::new();
        let mut cache = shared.cache();
        shared.latest.seq.store(5, AtomOrdering::Relaxed);
        shared.latest.valid.store(true, AtomOrdering::Relaxed);
        cache.refresh_from_shared(&shared);

        let control = test_session_control_event(5, SupportedProtocol::UDP);
        assert_eq!(
            classify_u2c_event(&cfg, &control, &shared).unwrap(),
            U2cDecision::ConsumeSessionControl
        );

        let payload = test_user_event(b"latest", 5, SupportedProtocol::UDP);
        assert!(
            classify_u2c_event(&cfg, &payload, &shared)
                .unwrap_err()
                .to_string()
                .contains("duplicate")
        );
    }

    #[test]
    fn prepare_send_assigns_distinct_sequences_to_negotiation_control_and_buffered_payload() {
        let _guard = lock_sync_state();
        reset_request_counter();
        let _cfg = test_config();
        let shared = SharedIcmpSequenceState::new();
        let mut cache = shared.cache();

        let control = test_reply_id_session_control_event(0, SupportedProtocol::ICMP, 2002);
        let control_seq = allocate_send_sequence(true, &control, true, &shared, &mut cache)
            .expect("session-control send should allocate ICMP sequence");

        let buffered_payload = test_user_event(b"buffered", 0, SupportedProtocol::ICMP);
        let payload_seq =
            allocate_send_sequence(true, &buffered_payload, true, &shared, &mut cache)
                .expect("buffered payload send should allocate ICMP sequence");

        assert_ne!(control_seq, payload_seq);
        assert_eq!(payload_seq, control_seq.wrapping_add(1));
        assert_eq!(cache.latest_sent_seq, payload_seq);
        assert_eq!(shared.latest.seq.load(AtomOrdering::Relaxed), payload_seq);
    }

    #[test]
    fn classify_u2c_forwards_session_control_reply_for_icmp_listener() {
        let _guard = lock_sync_state();
        let mut cfg = test_config();
        cfg.listen_proto = SupportedProtocol::ICMP;
        let shared = SharedIcmpSequenceState::new();
        let mut cache = shared.cache();
        shared.latest.seq.store(5, AtomOrdering::Relaxed);
        shared.latest.valid.store(true, AtomOrdering::Relaxed);
        cache.refresh_from_shared(&shared);

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
        let shared = SharedIcmpSequenceState::new();
        let mut cache = shared.cache();
        assert_eq!(
            classify_c2u_session_control_event(
                &cfg,
                &test_session_control_event(11, SupportedProtocol::UDP),
                &shared,
                &mut cache
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
        let shared = SharedIcmpSequenceState::new();
        let mut cache = shared.cache();
        assert_eq!(
            classify_c2u_session_control_event(
                &cfg,
                &test_session_control_event(11, SupportedProtocol::ICMP),
                &shared,
                &mut cache
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
        let shared = SharedIcmpSequenceState::new();
        let mut cache = shared.cache();
        assert_eq!(
            classify_c2u_session_control_event(
                &cfg,
                &test_reply_id_session_control_event(11, SupportedProtocol::ICMP, 2002),
                &shared,
                &mut cache
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
        let shared = SharedIcmpSequenceState::new();

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
        let shared = SharedIcmpSequenceState::new();
        let event = PayloadEvent::cadence_packet(0x1234, 7);
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
        let shared = SharedIcmpSequenceState::new();
        let mut cache = shared.cache();
        assert_eq!(
            classify_c2u_session_control_event(
                &cfg,
                &test_session_control_event(11, SupportedProtocol::ICMP),
                &shared,
                &mut cache
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
        let shared = SharedIcmpSequenceState::new();
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
        let shared = SharedIcmpSequenceState::new();
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
    fn classify_u2c_rejects_duplicate_session_control_when_sync_is_disabled() {
        let _guard = lock_sync_state();
        let mut cfg = test_config();
        cfg.icmp_sync_pps = 0;
        let shared = SharedIcmpSequenceState::new();
        let event = test_reply_id_session_control_event(77, SupportedProtocol::UDP, 4040);
        assert_eq!(
            classify_u2c_event(&cfg, &event, &shared).unwrap(),
            U2cDecision::ConsumeSessionControl
        );

        let duplicate_error = classify_u2c_event(&cfg, &event, &shared)
            .unwrap_err()
            .to_string();
        assert_eq!(duplicate_error, "duplicate ICMP tunnel sequence");
        assert!(!duplicate_error.contains("sync mode"));
    }

    #[test]
    fn session_reset_allows_same_sequence_again() {
        let _guard = lock_sync_state();
        let cfg = test_config();
        let shared = SharedIcmpSequenceState::new();
        let mut cache = shared.cache();
        shared.latest.seq.store(12, AtomOrdering::Relaxed);
        shared.latest.valid.store(true, AtomOrdering::Relaxed);
        cache.refresh_from_shared(&shared);
        let event = test_user_event(b"first", 12, SupportedProtocol::UDP);
        assert!(classify_u2c_event(&cfg, &event, &shared).is_ok());

        reset_sequence_state(false, &shared, &mut cache);
        shared.latest.seq.store(12, AtomOrdering::Relaxed);
        shared.latest.valid.store(true, AtomOrdering::Relaxed);
        cache.refresh_from_shared(&shared);
        assert!(classify_u2c_event(&cfg, &event, &shared).is_ok());
    }

    #[test]
    fn single_flow_uses_independent_sync_states() {
        let _guard = lock_sync_state();
        let cfg = test_config();
        let shared_a = SharedIcmpSequenceState::new();
        let shared_b = SharedIcmpSequenceState::new();

        shared_a.latest.seq.store(44, AtomOrdering::Relaxed);
        shared_a.latest.valid.store(true, AtomOrdering::Relaxed);
        shared_b.latest.seq.store(44, AtomOrdering::Relaxed);
        shared_b.latest.valid.store(true, AtomOrdering::Relaxed);

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
}
