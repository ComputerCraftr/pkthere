use crate::cli::{RuntimeConfig, SupportedProtocol};
use crate::net::payload::{PayloadEvent, PayloadOrigin, WirePayload};

use std::io;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering as AtomOrdering};

static REQUEST_ICMP_SEQ: AtomicU16 = AtomicU16::new(0);

const MIN_CATCHUP_WINDOW: usize = 8;
const MAX_CATCHUP_WINDOW: usize = 1024;
const DEDUP_SLOT_COUNT: usize = 2048;

#[repr(align(64))]
struct AlignedAtomicU64(AtomicU64);

#[repr(align(64))]
struct AlignedLatest {
    seq: AtomicU16,
    valid: AtomicBool,
}

#[repr(align(64))]
struct AlignedReplySeq(AtomicU16);

#[repr(align(64))]
struct DedupSlot(AtomicU64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum U2cDecision {
    ForwardPayload,
    ForwardKeepaliveReply,
    ConsumeKeepalive,
}

impl U2cDecision {
    #[inline]
    pub(crate) const fn should_send(self) -> bool {
        matches!(self, Self::ForwardPayload | Self::ForwardKeepaliveReply)
    }

    #[inline]
    pub(crate) const fn counts_as_payload(self) -> bool {
        matches!(self, Self::ForwardPayload)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum C2uKeepaliveDecision {
    Consume,
    ReplyLocally,
}

pub(crate) struct SharedSyncIcmpState {
    generation: AlignedAtomicU64,
    latest: AlignedLatest,
    reply_icmp_seq: AlignedReplySeq,
    dedup_slots: [DedupSlot; DEDUP_SLOT_COUNT],
    catchup_window: usize,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct SyncIcmpCache {
    generation: u64,
    latest_sent_seq: u16,
    latest_valid: bool,
    reply_icmp_seq: u16,
    catchup_window: usize,
}

impl SharedSyncIcmpState {
    pub(crate) fn new(icmp_sync_pps: u32) -> Self {
        Self {
            generation: AlignedAtomicU64(AtomicU64::new(1)),
            latest: AlignedLatest {
                seq: AtomicU16::new(0),
                valid: AtomicBool::new(false),
            },
            reply_icmp_seq: AlignedReplySeq(AtomicU16::new(0)),
            dedup_slots: [const { DedupSlot(AtomicU64::new(0)) }; DEDUP_SLOT_COUNT],
            catchup_window: sync_catchup_window(icmp_sync_pps),
        }
    }

    #[inline]
    pub(crate) fn cache(&self) -> SyncIcmpCache {
        SyncIcmpCache {
            generation: self.generation.0.load(AtomOrdering::Relaxed),
            latest_sent_seq: self.latest.seq.load(AtomOrdering::Relaxed),
            latest_valid: self.latest.valid.load(AtomOrdering::Relaxed),
            reply_icmp_seq: self.reply_icmp_seq.0.load(AtomOrdering::Relaxed),
            catchup_window: self.catchup_window,
        }
    }
}

impl SyncIcmpCache {
    #[inline]
    fn refresh_from_shared(&mut self, shared: &SharedSyncIcmpState) {
        self.generation = shared.generation.0.load(AtomOrdering::Relaxed);
        self.latest_sent_seq = shared.latest.seq.load(AtomOrdering::Relaxed);
        self.latest_valid = shared.latest.valid.load(AtomOrdering::Relaxed);
        self.reply_icmp_seq = shared.reply_icmp_seq.0.load(AtomOrdering::Relaxed);
        self.catchup_window = shared.catchup_window;
    }

    #[cfg(test)]
    fn catchup_window(&self) -> usize {
        self.catchup_window
    }
}

#[inline]
pub(crate) fn sync_icmp_enabled(cfg: &RuntimeConfig) -> bool {
    cfg.icmp_sync_pps > 0 && cfg.upstream_proto == SupportedProtocol::ICMP
}

#[inline]
pub(crate) fn sync_catchup_window(icmp_sync_pps: u32) -> usize {
    usize::try_from(icmp_sync_pps)
        .unwrap_or(usize::MAX)
        .saturating_div(4)
        .clamp(MIN_CATCHUP_WINDOW, MAX_CATCHUP_WINDOW)
}

#[inline]
fn pack_dedup_stamp(generation: u64, seq: u16) -> u64 {
    (generation << 16) | u64::from(seq)
}

pub(crate) fn reset_session(shared: &SharedSyncIcmpState, cache: &mut SyncIcmpCache) {
    let next_generation = shared
        .generation
        .0
        .fetch_add(1, AtomOrdering::Relaxed)
        .wrapping_add(1);
    shared.latest.valid.store(false, AtomOrdering::Relaxed);
    shared.latest.seq.store(0, AtomOrdering::Relaxed);
    shared.reply_icmp_seq.0.store(0, AtomOrdering::Relaxed);
    cache.generation = next_generation;
    cache.latest_valid = false;
    cache.latest_sent_seq = 0;
    cache.reply_icmp_seq = 0;
    cache.catchup_window = shared.catchup_window;
}

pub(crate) fn remember_request_seq(
    shared: &SharedSyncIcmpState,
    cache: &mut SyncIcmpCache,
    wire: &WirePayload<'_>,
) {
    if wire.src_is_icmp {
        shared
            .reply_icmp_seq
            .0
            .store(wire.src_seq, AtomOrdering::Relaxed);
        cache.reply_icmp_seq = wire.src_seq;
    }
}

pub(crate) fn classify_u2c(
    cfg: &RuntimeConfig,
    event: &PayloadEvent<'_>,
    origin: PayloadOrigin,
    shared: &SharedSyncIcmpState,
    cache: &mut SyncIcmpCache,
) -> io::Result<U2cDecision> {
    let wire = event.wire();
    if !wire.src_is_icmp {
        return Ok(U2cDecision::ForwardPayload);
    }
    if !sync_icmp_enabled(cfg) {
        return if matches!(event, PayloadEvent::SyncKeepalive(_)) {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ICMP keepalive arrived while sync mode is disabled",
            ))
        } else {
            Ok(U2cDecision::ForwardPayload)
        };
    }

    cache.refresh_from_shared(shared);
    if !cache.latest_valid {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ICMP sync mode: reply arrived before any request",
        ));
    }

    let latest_seq = cache.latest_sent_seq;
    let lag = latest_seq.wrapping_sub(wire.src_seq) as usize;
    if lag > cache.catchup_window {
        let ahead = wire.src_seq.wrapping_sub(latest_seq);
        let msg = if ahead != 0 && ahead <= u16::MAX / 2 {
            "ICMP sync mode: future reply sequence"
        } else {
            "ICMP sync mode: stale reply sequence"
        };
        return Err(io::Error::new(io::ErrorKind::InvalidData, msg));
    }

    let stamp = pack_dedup_stamp(cache.generation, wire.src_seq);
    let slot = &shared.dedup_slots[(wire.src_seq as usize) & (DEDUP_SLOT_COUNT - 1)].0;
    let mut prev = slot.load(AtomOrdering::Relaxed);
    loop {
        if prev == stamp {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ICMP sync mode: duplicate reply sequence",
            ));
        }
        match slot.compare_exchange_weak(prev, stamp, AtomOrdering::Relaxed, AtomOrdering::Relaxed)
        {
            Ok(_) => break,
            Err(current) => prev = current,
        }
    }

    if matches!(event, PayloadEvent::SyncKeepalive(_)) && origin == PayloadOrigin::Wire {
        if cfg.listen_proto == SupportedProtocol::ICMP {
            Ok(U2cDecision::ForwardKeepaliveReply)
        } else {
            Ok(U2cDecision::ConsumeKeepalive)
        }
    } else {
        Ok(U2cDecision::ForwardPayload)
    }
}

pub(crate) fn classify_c2u_keepalive(
    cfg: &RuntimeConfig,
    wire: &WirePayload<'_>,
    shared: &SharedSyncIcmpState,
    cache: &mut SyncIcmpCache,
) -> io::Result<C2uKeepaliveDecision> {
    if !wire.src_is_icmp {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ICMP keepalive arrived while sync mode is disabled",
        ));
    }
    remember_request_seq(shared, cache, wire);
    if wire.dst_proto == SupportedProtocol::ICMP {
        if !sync_icmp_enabled(cfg) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ICMP keepalive arrived while sync mode is disabled",
            ));
        }
        Ok(C2uKeepaliveDecision::Consume)
    } else {
        Ok(C2uKeepaliveDecision::ReplyLocally)
    }
}

pub(crate) fn prepare_send(
    c2u: bool,
    wire: &WirePayload<'_>,
    will_forward: bool,
    shared: &SharedSyncIcmpState,
    cache: &mut SyncIcmpCache,
) -> Option<u16> {
    if !will_forward || wire.dst_proto != SupportedProtocol::ICMP {
        return None;
    }

    if c2u {
        let seq = REQUEST_ICMP_SEQ.fetch_add(1, AtomOrdering::Relaxed);
        shared.latest.seq.store(seq, AtomOrdering::Relaxed);
        shared.latest.valid.store(true, AtomOrdering::Relaxed);
        cache.latest_sent_seq = seq;
        cache.latest_valid = true;
        cache.generation = shared.generation.0.load(AtomOrdering::Relaxed);
        Some(seq)
    } else {
        cache.reply_icmp_seq = shared.reply_icmp_seq.0.load(AtomOrdering::Relaxed);
        Some(cache.reply_icmp_seq)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{DebugBehavior, DebugLogs, ListenMode, ReresolveMode, TimeoutAction};
    use crate::net::params::CanonicalAddr;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::sync::{Arc, Barrier, Mutex, MutexGuard};
    use std::thread;

    static SYNC_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn test_config() -> RuntimeConfig {
        RuntimeConfig {
            listen: CanonicalAddr::new(
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1234)),
                1234,
            ),
            listen_proto: SupportedProtocol::UDP,
            listen_mode: ListenMode::Fixed,
            listen_str: String::from("test-listen"),
            workers: 1,
            worker_flow_mode: crate::cli::WorkerFlowMode::SharedFlow,
            upstream: CanonicalAddr::new(
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 2222)),
                2222,
            ),
            upstream_proto: SupportedProtocol::ICMP,
            upstream_str: String::from("test-upstream"),
            timeout_secs: 10,
            on_timeout: TimeoutAction::Drop,
            stats_interval_mins: 0,
            max_payload: 1500,
            icmp_sync_pps: 10,
            reresolve_secs: 0,
            reresolve_mode: ReresolveMode::Upstream,
            #[cfg(unix)]
            run_as_user: None,
            #[cfg(unix)]
            run_as_group: None,
            debug_behavior: DebugBehavior::default(),
            debug_logs: DebugLogs::default(),
        }
    }

    fn test_wire<'a>(payload: &'a [u8], seq: u16, dst_proto: SupportedProtocol) -> WirePayload<'a> {
        WirePayload {
            src_is_icmp: true,
            src_ident: 0,
            src_seq: seq,
            dst_proto,
            payload,
            pub_len: payload.len(),
        }
    }

    fn reset_request_counter() {
        REQUEST_ICMP_SEQ.store(0, AtomOrdering::Relaxed);
    }

    fn lock_sync_state() -> MutexGuard<'static, ()> {
        SYNC_TEST_LOCK.lock().unwrap()
    }

    #[test]
    fn classify_u2c_concurrent_duplicates_only_allows_one() {
        let _guard = lock_sync_state();
        reset_request_counter();
        let cfg = Arc::new(test_config());
        let shared = Arc::new(SharedSyncIcmpState::new(cfg.icmp_sync_pps));
        let mut seed = shared.cache();
        seed.generation = shared.generation.0.load(AtomOrdering::Relaxed);
        prepare_send(
            true,
            &test_wire(b"x", 0, SupportedProtocol::ICMP),
            true,
            &shared,
            &mut seed,
        );

        let thread_count = 16;
        let barrier = Arc::new(Barrier::new(thread_count));
        let mut handles = Vec::new();
        for _ in 0..thread_count {
            let b = barrier.clone();
            let c = cfg.clone();
            let s = shared.clone();
            handles.push(thread::spawn(move || {
                let mut cache = s.cache();
                let event = PayloadEvent::UserData(test_wire(
                    b"race",
                    cache.latest_sent_seq,
                    SupportedProtocol::UDP,
                ));
                b.wait();
                classify_u2c(&c, &event, PayloadOrigin::Wire, &s, &mut cache)
            }));
        }

        let mut success_count = 0;
        let mut dup_count = 0;
        for h in handles {
            match h.join().unwrap() {
                Ok(U2cDecision::ForwardPayload) => success_count += 1,
                Err(e) if e.to_string().contains("duplicate") => dup_count += 1,
                other => panic!("unexpected result: {:?}", other),
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
        let shared = SharedSyncIcmpState::new(cfg.icmp_sync_pps);
        let mut cache = shared.cache();
        prepare_send(
            true,
            &test_wire(b"x", 0, SupportedProtocol::ICMP),
            true,
            &shared,
            &mut cache,
        );
        shared.latest.seq.store(100, AtomOrdering::Relaxed);
        cache.latest_sent_seq = 100;

        let seq100 = PayloadEvent::UserData(test_wire(b"100", 100, SupportedProtocol::UDP));
        assert!(classify_u2c(&cfg, &seq100, PayloadOrigin::Wire, &shared, &mut cache).is_ok());

        let seq99 = PayloadEvent::UserData(test_wire(b"99", 99, SupportedProtocol::UDP));
        assert!(classify_u2c(&cfg, &seq99, PayloadOrigin::Wire, &shared, &mut cache).is_ok());
        assert!(
            classify_u2c(&cfg, &seq99, PayloadOrigin::Wire, &shared, &mut cache)
                .unwrap_err()
                .to_string()
                .contains("duplicate")
        );

        let stale = PayloadEvent::UserData(test_wire(
            b"stale",
            100u16.wrapping_sub((cache.catchup_window() + 1) as u16),
            SupportedProtocol::UDP,
        ));
        assert!(
            classify_u2c(&cfg, &stale, PayloadOrigin::Wire, &shared, &mut cache)
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
        let shared = SharedSyncIcmpState::new(cfg.icmp_sync_pps);
        let mut cache = shared.cache();
        shared.latest.seq.store(1025, AtomOrdering::Relaxed);
        shared.latest.valid.store(true, AtomOrdering::Relaxed);
        cache.latest_sent_seq = 1025;
        cache.latest_valid = true;

        let stale = PayloadEvent::UserData(test_wire(b"stale", 0, SupportedProtocol::UDP));
        assert!(
            classify_u2c(&cfg, &stale, PayloadOrigin::Wire, &shared, &mut cache)
                .unwrap_err()
                .to_string()
                .contains("stale")
        );

        let latest = PayloadEvent::UserData(test_wire(b"latest", 1025, SupportedProtocol::UDP));
        assert_eq!(
            classify_u2c(&cfg, &latest, PayloadOrigin::Wire, &shared, &mut cache).unwrap(),
            U2cDecision::ForwardPayload
        );

        let dup = PayloadEvent::UserData(test_wire(b"latest", 1025, SupportedProtocol::UDP));
        assert!(
            classify_u2c(&cfg, &dup, PayloadOrigin::Wire, &shared, &mut cache)
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
        let shared = SharedSyncIcmpState::new(cfg.icmp_sync_pps);
        let mut cache = shared.cache();
        shared.latest.seq.store(5, AtomOrdering::Relaxed);
        shared.latest.valid.store(true, AtomOrdering::Relaxed);
        cache.latest_sent_seq = 5;
        cache.latest_valid = true;

        let event = PayloadEvent::UserData(test_wire(b"future", 7, SupportedProtocol::UDP));
        assert!(
            classify_u2c(&cfg, &event, PayloadOrigin::Wire, &shared, &mut cache)
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
        let shared = SharedSyncIcmpState::new(cfg.icmp_sync_pps);
        let mut cache = shared.cache();
        shared.latest.seq.store(1, AtomOrdering::Relaxed);
        shared.latest.valid.store(true, AtomOrdering::Relaxed);
        cache.latest_sent_seq = 1;
        cache.latest_valid = true;

        let event = PayloadEvent::UserData(test_wire(b"wrap", u16::MAX, SupportedProtocol::UDP));
        assert_eq!(
            classify_u2c(&cfg, &event, PayloadOrigin::Wire, &shared, &mut cache).unwrap(),
            U2cDecision::ForwardPayload
        );
    }

    #[test]
    fn classify_u2c_marks_empty_latest_reply_keepalive_only_for_udp_listener() {
        let _guard = lock_sync_state();
        let cfg = test_config();
        let shared = SharedSyncIcmpState::new(cfg.icmp_sync_pps);
        let mut cache = shared.cache();
        shared.latest.seq.store(5, AtomOrdering::Relaxed);
        shared.latest.valid.store(true, AtomOrdering::Relaxed);
        cache.latest_sent_seq = 5;
        cache.latest_valid = true;

        let event = PayloadEvent::SyncKeepalive(test_wire(&[], 5, SupportedProtocol::UDP));
        assert_eq!(
            classify_u2c(&cfg, &event, PayloadOrigin::Wire, &shared, &mut cache).unwrap(),
            U2cDecision::ConsumeKeepalive
        );
    }

    #[test]
    fn classify_u2c_forwards_keepalive_reply_for_icmp_listener() {
        let _guard = lock_sync_state();
        let mut cfg = test_config();
        cfg.listen_proto = SupportedProtocol::ICMP;
        cfg.listen.id = 2222;
        let shared = SharedSyncIcmpState::new(cfg.icmp_sync_pps);
        let mut cache = shared.cache();
        shared.latest.seq.store(5, AtomOrdering::Relaxed);
        shared.latest.valid.store(true, AtomOrdering::Relaxed);
        cache.latest_sent_seq = 5;
        cache.latest_valid = true;

        let event = PayloadEvent::SyncKeepalive(test_wire(&[], 5, SupportedProtocol::ICMP));
        assert_eq!(
            classify_u2c(&cfg, &event, PayloadOrigin::Wire, &shared, &mut cache).unwrap(),
            U2cDecision::ForwardKeepaliveReply
        );
    }

    #[test]
    fn classify_c2u_keepalive_replies_locally_when_upstream_is_not_icmp() {
        let _guard = lock_sync_state();
        let mut cfg = test_config();
        cfg.listen_proto = SupportedProtocol::ICMP;
        cfg.upstream_proto = SupportedProtocol::UDP;
        let shared = SharedSyncIcmpState::new(cfg.icmp_sync_pps);
        let mut cache = shared.cache();
        let wire = test_wire(&[], 11, SupportedProtocol::UDP);
        assert_eq!(
            classify_c2u_keepalive(&cfg, &wire, &shared, &mut cache).unwrap(),
            C2uKeepaliveDecision::ReplyLocally
        );
    }

    #[test]
    fn classify_c2u_keepalive_consumes_for_icmp_bridge() {
        let _guard = lock_sync_state();
        let mut cfg = test_config();
        cfg.listen_proto = SupportedProtocol::ICMP;
        cfg.upstream_proto = SupportedProtocol::ICMP;
        let shared = SharedSyncIcmpState::new(cfg.icmp_sync_pps);
        let mut cache = shared.cache();
        let wire = test_wire(&[], 11, SupportedProtocol::ICMP);
        assert_eq!(
            classify_c2u_keepalive(&cfg, &wire, &shared, &mut cache).unwrap(),
            C2uKeepaliveDecision::Consume
        );
    }

    #[test]
    fn classify_u2c_rejects_keepalive_when_sync_is_disabled() {
        let _guard = lock_sync_state();
        let mut cfg = test_config();
        cfg.icmp_sync_pps = 0;
        let shared = SharedSyncIcmpState::new(cfg.icmp_sync_pps);
        let mut cache = shared.cache();
        let event = PayloadEvent::SyncKeepalive(test_wire(&[], 5, SupportedProtocol::UDP));
        assert!(
            classify_u2c(&cfg, &event, PayloadOrigin::Wire, &shared, &mut cache)
                .unwrap_err()
                .to_string()
                .contains("sync mode is disabled")
        );
    }

    #[test]
    fn classify_c2u_rejects_keepalive_when_sync_is_disabled() {
        let _guard = lock_sync_state();
        let mut cfg = test_config();
        cfg.listen_proto = SupportedProtocol::ICMP;
        cfg.upstream_proto = SupportedProtocol::ICMP;
        cfg.icmp_sync_pps = 0;
        let shared = SharedSyncIcmpState::new(cfg.icmp_sync_pps);
        let mut cache = shared.cache();
        let wire = test_wire(&[], 11, SupportedProtocol::ICMP);
        assert!(
            classify_c2u_keepalive(&cfg, &wire, &shared, &mut cache)
                .unwrap_err()
                .to_string()
                .contains("sync mode is disabled")
        );
    }

    #[test]
    fn classify_u2c_forwards_regular_icmp_reply_when_sync_is_disabled() {
        let _guard = lock_sync_state();
        let mut cfg = test_config();
        cfg.icmp_sync_pps = 0;
        let shared = SharedSyncIcmpState::new(cfg.icmp_sync_pps);
        let mut cache = shared.cache();
        let event = PayloadEvent::UserData(test_wire(b"plain-icmp", 77, SupportedProtocol::UDP));
        assert_eq!(
            classify_u2c(&cfg, &event, PayloadOrigin::Wire, &shared, &mut cache).unwrap(),
            U2cDecision::ForwardPayload
        );
    }

    #[test]
    fn session_reset_allows_same_sequence_again() {
        let _guard = lock_sync_state();
        let cfg = test_config();
        let shared = SharedSyncIcmpState::new(cfg.icmp_sync_pps);
        let mut cache = shared.cache();
        shared.latest.seq.store(12, AtomOrdering::Relaxed);
        shared.latest.valid.store(true, AtomOrdering::Relaxed);
        cache.latest_sent_seq = 12;
        cache.latest_valid = true;
        let event = PayloadEvent::UserData(test_wire(b"first", 12, SupportedProtocol::UDP));
        assert!(classify_u2c(&cfg, &event, PayloadOrigin::Wire, &shared, &mut cache).is_ok());
        reset_session(&shared, &mut cache);
        shared.latest.seq.store(12, AtomOrdering::Relaxed);
        shared.latest.valid.store(true, AtomOrdering::Relaxed);
        cache.latest_sent_seq = 12;
        cache.latest_valid = true;
        assert!(classify_u2c(&cfg, &event, PayloadOrigin::Wire, &shared, &mut cache).is_ok());
    }

    #[test]
    fn single_flow_uses_independent_sync_states() {
        let _guard = lock_sync_state();
        let cfg = test_config();
        let shared_a = SharedSyncIcmpState::new(cfg.icmp_sync_pps);
        let shared_b = SharedSyncIcmpState::new(cfg.icmp_sync_pps);
        let mut cache_a = shared_a.cache();
        let mut cache_b = shared_b.cache();
        shared_a.latest.seq.store(44, AtomOrdering::Relaxed);
        shared_b.latest.seq.store(44, AtomOrdering::Relaxed);
        shared_a.latest.valid.store(true, AtomOrdering::Relaxed);
        shared_b.latest.valid.store(true, AtomOrdering::Relaxed);
        cache_a.latest_sent_seq = 44;
        cache_b.latest_sent_seq = 44;
        cache_a.latest_valid = true;
        cache_b.latest_valid = true;

        let event = PayloadEvent::UserData(test_wire(b"a", 44, SupportedProtocol::UDP));
        assert!(classify_u2c(&cfg, &event, PayloadOrigin::Wire, &shared_a, &mut cache_a).is_ok());
        assert!(classify_u2c(&cfg, &event, PayloadOrigin::Wire, &shared_b, &mut cache_b).is_ok());
    }

    #[test]
    fn sync_catchup_window_clamps() {
        assert_eq!(sync_catchup_window(0), 8);
        assert_eq!(sync_catchup_window(8), 8);
        assert_eq!(sync_catchup_window(40), 10);
        assert_eq!(sync_catchup_window(u32::from(u16::MAX)), 1024);
    }
}
