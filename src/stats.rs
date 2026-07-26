use crate::flow_state::FlowRuntimeState;
use crate::net::icmp_sequence::{SequenceRejectionCounters, SharedIcmpSequenceState};
use crate::net::sock_mgr::SocketManager;
use crate::runtime_support::{RuntimeFailure, ShutdownController};
use std::io;
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::Ordering as AtomOrdering;
use std::time::{Duration, Instant};

const EWMA_LN_BETA: f64 = -std::f64::consts::LN_2 / 200_000.0;
const STATS_MERGE_EVENTS: u16 = 256;
const STATS_MERGE_INTERVAL: Duration = Duration::from_millis(100);
pub(crate) const STATS_FINAL_FLUSH_DEADLINE: Duration = Duration::from_millis(500);

mod sink_trait;
pub(crate) use sink_trait::StatsSink;

mod rejection;
use rejection::ErrorCategory;
pub(crate) use rejection::PacketRejectionCategory;
mod render;
#[cfg(all(test, not(miri)))]
mod render_tests;

mod diagnostic_capture;
#[cfg(all(test, loom, not(miri), not(target_env = "musl")))]
mod diagnostic_capture_loom;

mod publication;
pub(crate) use publication::StatsAggregatorBootstrap;
use publication::{EnabledStats, StatsRuntime};

mod finality_core;
use finality_core::StatsPublication;
#[cfg(all(test, loom, not(miri), not(target_env = "musl")))]
mod finality_core_loom;

mod aggregator;
use aggregator::StatsAggregator;

pub(crate) struct Stats {
    runtime: StatsRuntime,
}

pub(crate) struct StatsRecorder {
    runtime: RecorderRuntime,
}

pub(crate) struct StatsPrinterInputs {
    pub(crate) sock_mgrs: Vec<Arc<SocketManager>>,
    pub(crate) flow_states: Vec<Arc<FlowRuntimeState>>,
    pub(crate) sequence_states: Vec<Arc<SharedIcmpSequenceState>>,
    pub(crate) start: Instant,
    pub(crate) every_secs: u64,
    pub(crate) shutdown: Arc<ShutdownController>,
}

enum RecorderRuntime {
    Disabled,
    Enabled(Box<EnabledRecorder>),
}

struct EnabledRecorder {
    producer_index: usize,
    shared: Arc<EnabledStats>,
    producer: Arc<publication::StatsProducer>,
    local: RecorderState,
}

struct RecorderState {
    active: Snapshot,
    unpublished: Option<(u64, Snapshot)>,
    events: u16,
    last_merge: Instant,
    next_sequence: u64,
    last_queued_sequence: u64,
    queued_flush_generation: u64,
    pending_flush_marker: Option<(u64, u64)>,
    sequence_exhausted: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProducerSealResult {
    Sealed,
    DeadlineExceeded,
    Failed,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct DirectionSnapshot {
    pkts: u64,
    bytes: u128,
    bytes_max: u64,
    errs: u64,
    lat_sum_ns: u128,
    lat_max_ns: u64,
    queue_sum_ns: u128,
    queue_max_ns: u64,
    service_sum_ns: u128,
    service_max_ns: u64,
    zero_resolution_samples: u64,
    drops_oversize: u64,
    receive_errors: u64,
    user_send_errors: u64,
    control_send_errors: u64,
    admission_drops: u64,
    topology_errors: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ControlSnapshot {
    handshake_invalid_control: u64,
    handshake_stale_ack: u64,
    spurious_readiness_events: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct AdmissionSnapshot {
    malformed_packets: u64,
    wrong_peer_drops: u64,
    wrong_source_drops: u64,
    handshake_invalid_drops: u64,
    replay_drops: u64,
    icmp_abuse_budget_drops: u64,
    stale_session_drops: u64,
    stale_authority_drops: u64,
    invariant_failures: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct NetworkRejectionSnapshot {
    ip_missing_header: u64,
    ip_invalid_version: u64,
    ip_truncated_header: u64,
    ip_declared_length_invalid: u64,
    ip_capture_truncated: u64,
    ip_fragmented: u64,
    ip_reserved_flag: u64,
    ip_extension_chain: u64,
    ip_routing_unsupported: u64,
    ip_jumbogram_unsupported: u64,
    ip_source_mismatch: u64,
    ip_destination_mismatch: u64,
    unrelated_ip_protocol: u64,
    icmp_malformed: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Snapshot {
    c2u: DirectionSnapshot,
    u2c: DirectionSnapshot,
    control: ControlSnapshot,
    admission: AdmissionSnapshot,
    network: NetworkRejectionSnapshot,
    accounting_overflowed: bool,
}

impl DirectionSnapshot {
    fn merge(&mut self, other: Self, overflowed: &mut bool) {
        Stats::add_u64(&mut self.pkts, other.pkts, overflowed);
        Stats::add_u128(&mut self.bytes, other.bytes, overflowed);
        self.bytes_max = self.bytes_max.max(other.bytes_max);
        Stats::add_u64(&mut self.errs, other.errs, overflowed);
        Stats::add_u128(&mut self.lat_sum_ns, other.lat_sum_ns, overflowed);
        self.lat_max_ns = self.lat_max_ns.max(other.lat_max_ns);
        Stats::add_u128(&mut self.queue_sum_ns, other.queue_sum_ns, overflowed);
        self.queue_max_ns = self.queue_max_ns.max(other.queue_max_ns);
        Stats::add_u128(&mut self.service_sum_ns, other.service_sum_ns, overflowed);
        self.service_max_ns = self.service_max_ns.max(other.service_max_ns);
        Stats::add_u64(
            &mut self.zero_resolution_samples,
            other.zero_resolution_samples,
            overflowed,
        );
        Stats::add_u64(&mut self.drops_oversize, other.drops_oversize, overflowed);
        Stats::add_u64(&mut self.receive_errors, other.receive_errors, overflowed);
        Stats::add_u64(
            &mut self.user_send_errors,
            other.user_send_errors,
            overflowed,
        );
        Stats::add_u64(
            &mut self.control_send_errors,
            other.control_send_errors,
            overflowed,
        );
        Stats::add_u64(&mut self.admission_drops, other.admission_drops, overflowed);
        Stats::add_u64(&mut self.topology_errors, other.topology_errors, overflowed);
    }
}

impl ControlSnapshot {
    fn merge(&mut self, other: Self, overflowed: &mut bool) {
        Stats::add_u64(
            &mut self.handshake_invalid_control,
            other.handshake_invalid_control,
            overflowed,
        );
        Stats::add_u64(
            &mut self.handshake_stale_ack,
            other.handshake_stale_ack,
            overflowed,
        );
        Stats::add_u64(
            &mut self.spurious_readiness_events,
            other.spurious_readiness_events,
            overflowed,
        );
    }
}

impl AdmissionSnapshot {
    fn merge(&mut self, other: Self, overflowed: &mut bool) {
        macro_rules! merge_counter {
            ($field:ident) => {
                Stats::add_u64(&mut self.$field, other.$field, overflowed)
            };
        }
        merge_counter!(malformed_packets);
        merge_counter!(wrong_peer_drops);
        merge_counter!(wrong_source_drops);
        merge_counter!(handshake_invalid_drops);
        merge_counter!(replay_drops);
        merge_counter!(icmp_abuse_budget_drops);
        merge_counter!(stale_session_drops);
        merge_counter!(stale_authority_drops);
        merge_counter!(invariant_failures);
    }
}

impl NetworkRejectionSnapshot {
    fn merge(&mut self, other: Self, overflowed: &mut bool) {
        macro_rules! merge_counter {
            ($field:ident) => {
                Stats::add_u64(&mut self.$field, other.$field, overflowed)
            };
        }
        merge_counter!(ip_missing_header);
        merge_counter!(ip_invalid_version);
        merge_counter!(ip_truncated_header);
        merge_counter!(ip_declared_length_invalid);
        merge_counter!(ip_capture_truncated);
        merge_counter!(ip_fragmented);
        merge_counter!(ip_reserved_flag);
        merge_counter!(ip_extension_chain);
        merge_counter!(ip_routing_unsupported);
        merge_counter!(ip_jumbogram_unsupported);
        merge_counter!(ip_source_mismatch);
        merge_counter!(ip_destination_mismatch);
        merge_counter!(unrelated_ip_protocol);
        merge_counter!(icmp_malformed);
    }
}

impl Stats {
    #[inline]
    const fn average_ns(sum: u128, packets: u64) -> u64 {
        match sum.checked_div(packets as u128) {
            Some(average) if average <= u64::MAX as u128 => average as u64,
            Some(_) => u64::MAX,
            None => 0,
        }
    }

    #[inline]
    fn add_u64(total: &mut u64, value: u64, overflowed: &mut bool) {
        match total.checked_add(value) {
            Some(sum) => *total = sum,
            None => {
                *total = u64::MAX;
                *overflowed = true;
            }
        }
    }

    #[inline]
    fn add_u128(total: &mut u128, value: u128, overflowed: &mut bool) {
        match total.checked_add(value) {
            Some(sum) => *total = sum,
            None => {
                *total = u128::MAX;
                *overflowed = true;
            }
        }
    }

    #[inline]
    const fn project_u128(value: u128) -> (u64, bool) {
        if value > u64::MAX as u128 {
            (u64::MAX, true)
        } else {
            (value as u64, false)
        }
    }

    pub(crate) fn bootstrap(
        producer_count: usize,
        enabled: bool,
    ) -> io::Result<(Self, Option<StatsAggregatorBootstrap>)> {
        if enabled {
            let (shared, aggregator) = EnabledStats::new(producer_count)?;
            Ok((
                Self {
                    runtime: StatsRuntime::Enabled(shared),
                },
                Some(aggregator),
            ))
        } else {
            Ok((
                Self {
                    runtime: StatsRuntime::Disabled,
                },
                None,
            ))
        }
    }

    #[cfg(test)]
    pub(crate) fn new(producer_count: usize, enabled: bool) -> io::Result<Self> {
        Self::bootstrap(producer_count, enabled).map(|(stats, _aggregator)| stats)
    }

    #[cfg(test)]
    pub(crate) fn with_worker_shards(worker_threads: usize) -> Self {
        Self::new(worker_threads, true).expect("create test stats runtime")
    }

    pub(crate) fn try_recorder(
        &self,
        producer_index: usize,
    ) -> Result<StatsRecorder, RuntimeFailure> {
        let runtime = match &self.runtime {
            StatsRuntime::Disabled => RecorderRuntime::Disabled,
            StatsRuntime::Enabled(shared) => {
                let producer = shared.claim_producer(producer_index)?;
                RecorderRuntime::Enabled(Box::new(EnabledRecorder {
                    producer_index,
                    shared: Arc::clone(shared),
                    producer,
                    local: RecorderState {
                        active: Snapshot::default(),
                        unpublished: None,
                        events: 0,
                        last_merge: Instant::now(),
                        next_sequence: 1,
                        last_queued_sequence: 0,
                        queued_flush_generation: 0,
                        pending_flush_marker: None,
                        sequence_exhausted: false,
                    },
                }))
            }
        };
        Ok(StatsRecorder { runtime })
    }

    #[cfg(test)]
    pub(crate) fn recorder(&self, producer_index: usize) -> StatsRecorder {
        self.try_recorder(producer_index)
            .expect("test stats recorder index must be configured")
    }

    pub(crate) fn request_final_flush(&self, deadline: Instant) {
        let _snapshot = self.request_final_flush_inner(deadline);
    }

    #[cfg(test)]
    fn request_final_flush_for_test(&self, deadline: Instant) -> Snapshot {
        self.request_final_flush_inner(deadline)
    }

    fn request_final_flush_inner(&self, deadline: Instant) -> Snapshot {
        #[cfg(test)]
        let mut test_snapshot = Snapshot::default();
        let StatsRuntime::Enabled(shared) = &self.runtime else {
            return Snapshot::default();
        };
        #[cfg(test)]
        let mut test_last_sequences = vec![0; shared.producers.len()];
        let generation = shared.begin_final_flush();
        while Instant::now() < deadline {
            #[cfg(test)]
            tests::drain_for_test(shared, &mut test_snapshot, &mut test_last_sequences);
            if shared
                .all_live_producers_acknowledged(generation)
                .unwrap_or(false)
            {
                let abandoned = shared.abandoned_producers.load(AtomOrdering::Acquire);
                shared
                    .final_flush_incomplete
                    .store(abandoned != 0, AtomOrdering::Release);
                #[cfg(test)]
                return test_snapshot;
                #[cfg(not(test))]
                return Snapshot::default();
            }
            crate::authority::audited_thread_sleep(Duration::from_millis(1));
        }
        shared
            .final_flush_incomplete
            .store(true, AtomOrdering::Release);
        #[cfg(test)]
        return test_snapshot;
        #[cfg(not(test))]
        Snapshot::default()
    }

    #[cfg(test)]
    fn load_snapshot(&self) -> Snapshot {
        let StatsRuntime::Enabled(shared) = &self.runtime else {
            return Snapshot::default();
        };
        let mut snapshot = Snapshot::default();
        let mut last_sequences = vec![0; shared.producers.len()];
        tests::drain_for_test(shared, &mut snapshot, &mut last_sequences);
        snapshot
    }

    #[cfg(test)]
    fn final_flush_incomplete(&self) -> bool {
        match &self.runtime {
            StatsRuntime::Disabled => false,
            StatsRuntime::Enabled(shared) => {
                shared.final_flush_incomplete.load(AtomOrdering::Acquire)
            }
        }
    }

    #[cfg(test)]
    pub(crate) const fn is_enabled(&self) -> bool {
        matches!(&self.runtime, StatsRuntime::Enabled(_))
    }

    fn merge_snapshot(acc: &mut Snapshot, snap: Snapshot) {
        acc.accounting_overflowed |= snap.accounting_overflowed;
        acc.c2u.merge(snap.c2u, &mut acc.accounting_overflowed);
        acc.u2c.merge(snap.u2c, &mut acc.accounting_overflowed);
        acc.control
            .merge(snap.control, &mut acc.accounting_overflowed);
        acc.admission
            .merge(snap.admission, &mut acc.accounting_overflowed);
        acc.network
            .merge(snap.network, &mut acc.accounting_overflowed);
    }

    fn sequence_rejection_snapshot(
        states: &[Arc<SharedIcmpSequenceState>],
    ) -> (SequenceRejectionCounters, bool) {
        let mut unique = Vec::<*const SharedIcmpSequenceState>::new();
        let mut overflowed = false;
        let counters = states
            .iter()
            .filter_map(|state| {
                let ptr = Arc::as_ptr(state);
                if unique.contains(&ptr) {
                    None
                } else {
                    unique.push(ptr);
                    Some(state.rejection_counters())
                }
            })
            .fold(
                SequenceRejectionCounters::default(),
                |mut total, counters| {
                    Self::add_u64(&mut total.future, counters.future, &mut overflowed);
                    Self::add_u64(&mut total.stale, counters.stale, &mut overflowed);
                    Self::add_u64(&mut total.duplicate, counters.duplicate, &mut overflowed);
                    total
                },
            );
        (counters, overflowed)
    }

    #[inline]
    fn ewma_compute(prev_ns: u64, sample_avg_ns: u64, sample_count: u64) -> u64 {
        if sample_count == 0 {
            return prev_ns;
        }
        if prev_ns == 0 {
            return sample_avg_ns;
        }
        let k = sample_count as f64;
        let x = EWMA_LN_BETA * k;
        let one_minus_beta_k = -x.exp_m1();
        let beta_k = 1.0 - one_minus_beta_k;

        let prev_f = prev_ns as f64;
        let samp_f = sample_avg_ns as f64;
        let newf = beta_k * prev_f + one_minus_beta_k * samp_f;

        if !newf.is_finite() {
            return prev_ns;
        }
        let r = newf.max(0.0).round();
        if r >= (u64::MAX as f64) {
            u64::MAX
        } else {
            r as u64
        }
    }

    #[inline]
    pub(super) fn safe_println(s: &str) {
        log_info!("{}", s);
        let _flush = crate::authority::audited_operation(crate::authority::OperationId::StatsFlush);
        if std::io::stdout().flush().is_err() {
            // Stats output is best-effort; logging already handles broken stdout.
        }
    }

    pub fn run_stats_printer(
        self: Arc<Self>,
        aggregator: StatsAggregatorBootstrap,
        inputs: StatsPrinterInputs,
    ) -> Result<(), RuntimeFailure> {
        let StatsRuntime::Enabled(shared) = &self.runtime else {
            return Err(RuntimeFailure::fatal(format_args!(
                "stats aggregator started while statistics are disabled"
            )));
        };
        StatsAggregator::new(Arc::clone(shared), aggregator, inputs.start)?.run(
            inputs.sock_mgrs,
            inputs.flow_states,
            inputs.sequence_states,
            inputs.every_secs,
            inputs.shutdown,
        )
    }
}

mod accounting;
use accounting::{
    record_categorical_error_snapshot, record_drop_error_snapshot, record_drop_oversize_snapshot,
    record_handshake_snapshot, record_packet_rejection_snapshot, record_send_snapshot,
    record_spurious_readiness_snapshot,
};

mod recorder;

#[cfg(test)]
mod tests;
