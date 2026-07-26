use super::finality_core::AcceptedStatsPublication;
use super::publication::{
    EnabledStats, STATS_CONTROL_FALLBACK, StatsAggregatorBootstrap, StatsControl, StatsProducer,
};
use super::{Snapshot, Stats};
use crate::flow_state::FlowRuntimeState;
use crate::net::icmp_sequence::SharedIcmpSequenceState;
use crate::net::sock_mgr::SocketManager;
use crate::runtime_support::{RuntimeFailure, ShutdownController};
use crossbeam_channel::RecvTimeoutError;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

pub(super) struct StatsAggregator {
    shared: Arc<EnabledStats>,
    control: crate::authority::AuthorityChannelReceiver<
        crate::authority::tags::StatsPublication,
        StatsControl,
    >,
    snapshot: Snapshot,
    previous_interval: Snapshot,
    last_sequences: Box<[u64]>,
    c2u_ewma_ns: u64,
    u2c_ewma_ns: u64,
}

struct AggregatorRunGuard {
    shared: Arc<EnabledStats>,
    completed: bool,
}

impl AggregatorRunGuard {
    fn complete(mut self) {
        self.completed = true;
    }
}

impl Drop for AggregatorRunGuard {
    fn drop(&mut self) {
        if !self.completed {
            self.shared
                .final_flush_incomplete
                .store(true, Ordering::Release);
        }
    }
}

impl StatsAggregator {
    pub(super) fn new(
        shared: Arc<EnabledStats>,
        bootstrap: StatsAggregatorBootstrap,
        start: Instant,
    ) -> Result<Self, RuntimeFailure> {
        if shared.start.set(start).is_err() {
            return Err(RuntimeFailure::fatal(format_args!(
                "stats start time was published twice"
            )));
        }
        let last_sequences = vec![0; shared.producers.len()].into_boxed_slice();
        Ok(Self {
            shared,
            control: bootstrap.receiver.transfer(),
            snapshot: Snapshot::default(),
            previous_interval: Snapshot::default(),
            last_sequences,
            c2u_ewma_ns: 0,
            u2c_ewma_ns: 0,
        })
    }

    pub(super) fn run(
        mut self,
        sock_mgrs: Vec<Arc<SocketManager>>,
        flow_states: Vec<Arc<FlowRuntimeState>>,
        sequence_states: Vec<Arc<SharedIcmpSequenceState>>,
        every_secs: u64,
        shutdown: Arc<ShutdownController>,
    ) -> Result<(), RuntimeFailure> {
        let run_guard = AggregatorRunGuard {
            shared: Arc::clone(&self.shared),
            completed: false,
        };
        let print_period = Duration::from_secs(every_secs.max(1));
        let start =
            self.shared.start.get().copied().ok_or_else(|| {
                RuntimeFailure::fatal(format_args!("stats start time is missing"))
            })?;
        let mut next_print_at = start + print_period;
        loop {
            let control = self.control.recv_timeout(STATS_CONTROL_FALLBACK);
            match control {
                Ok(StatsControl::ProducerReady(index)) => self.drain_producer(index)?,
                Ok(StatsControl::FlushRequested) | Err(RecvTimeoutError::Timeout) => {
                    self.drain_all()?;
                }
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(RuntimeFailure::fatal(format_args!(
                        "stats control channel disconnected"
                    )));
                }
            }

            let now = Instant::now();
            if now >= next_print_at {
                self.update_interval_ewma();
                self.print_snapshot(
                    &sock_mgrs,
                    &flow_states,
                    &sequence_states,
                    now.saturating_duration_since(start).as_secs(),
                );
                next_print_at = now + print_period;
            }

            if shutdown.is_requested() {
                let deadline = now + super::STATS_FINAL_FLUSH_DEADLINE;
                self.drain_until_final_marker(deadline)?;
                self.update_interval_ewma();
                self.print_snapshot(
                    &sock_mgrs,
                    &flow_states,
                    &sequence_states,
                    Instant::now().saturating_duration_since(start).as_secs(),
                );
                run_guard.complete();
                return Ok(());
            }
        }
    }

    fn drain_until_final_marker(&mut self, deadline: Instant) -> Result<(), RuntimeFailure> {
        let generation = self.shared.begin_final_flush();
        while Instant::now() < deadline {
            self.drain_all()?;
            if self.shared.all_live_producers_acknowledged(generation)? {
                let abandoned = self.shared.abandoned_producers.load(Ordering::Acquire);
                self.shared
                    .final_flush_incomplete
                    .store(abandoned != 0, Ordering::Release);
                return Ok(());
            }
            let control = self.control.recv_timeout(STATS_CONTROL_FALLBACK);
            match control {
                Ok(StatsControl::ProducerReady(index)) => self.drain_producer(index)?,
                Ok(StatsControl::FlushRequested) | Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }
        self.shared
            .final_flush_incomplete
            .store(true, Ordering::Release);
        Ok(())
    }

    fn drain_all(&mut self) -> Result<(), RuntimeFailure> {
        for index in 0..self.shared.producers.len() {
            self.drain_producer(index)?;
        }
        Ok(())
    }

    fn drain_producer(&mut self, index: usize) -> Result<(), RuntimeFailure> {
        let producer = self
            .shared
            .producers
            .get(index)
            .ok_or_else(|| {
                RuntimeFailure::fatal(format_args!(
                    "stats control referenced unknown producer {index}"
                ))
            })
            .map(Arc::clone)?;
        loop {
            let observed_generation = producer.ready_generation();
            self.drain_available(index, &producer)?;
            if !producer.rearm_notification(observed_generation) {
                return Ok(());
            }
        }
    }

    fn drain_available(
        &mut self,
        index: usize,
        producer: &StatsProducer,
    ) -> Result<(), RuntimeFailure> {
        let Some(last) = self.last_sequences.get_mut(index) else {
            return Err(RuntimeFailure::fatal(format_args!(
                "stats producer {index} has no sequence slot"
            )));
        };
        while let Some(publication) = producer.accept_next(last)? {
            if let AcceptedStatsPublication::Delta(delta) = publication {
                Stats::merge_snapshot(&mut self.snapshot, delta);
            }
        }
        Ok(())
    }

    fn update_interval_ewma(&mut self) {
        let c2u_packets = self
            .snapshot
            .c2u
            .pkts
            .saturating_sub(self.previous_interval.c2u.pkts);
        let u2c_packets = self
            .snapshot
            .u2c
            .pkts
            .saturating_sub(self.previous_interval.u2c.pkts);
        let c2u_latency = self
            .snapshot
            .c2u
            .lat_sum_ns
            .saturating_sub(self.previous_interval.c2u.lat_sum_ns);
        let u2c_latency = self
            .snapshot
            .u2c
            .lat_sum_ns
            .saturating_sub(self.previous_interval.u2c.lat_sum_ns);
        if c2u_packets != 0 {
            self.c2u_ewma_ns = Stats::ewma_compute(
                self.c2u_ewma_ns,
                Stats::average_ns(c2u_latency, c2u_packets),
                c2u_packets,
            );
        }
        if u2c_packets != 0 {
            self.u2c_ewma_ns = Stats::ewma_compute(
                self.u2c_ewma_ns,
                Stats::average_ns(u2c_latency, u2c_packets),
                u2c_packets,
            );
        }
        self.previous_interval = self.snapshot;
    }

    fn print_snapshot(
        &self,
        sock_mgrs: &[Arc<SocketManager>],
        flow_states: &[Arc<FlowRuntimeState>],
        sequence_states: &[Arc<SharedIcmpSequenceState>],
        uptime_seconds: u64,
    ) {
        let rendered = super::render::render_snapshot(super::render::SnapshotRenderInput {
            snapshot: self.snapshot,
            sock_mgrs,
            flow_states,
            sequence_states,
            c2u_ewma_ns: self.c2u_ewma_ns,
            u2c_ewma_ns: self.u2c_ewma_ns,
            uptime: uptime_seconds,
            final_flush_incomplete: self.shared.final_flush_incomplete.load(Ordering::Acquire),
        });
        Stats::safe_println(&rendered.to_string());
    }
}

#[cfg(test)]
mod tests;
