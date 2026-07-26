use super::finality_core::{
    ProducerLifecycle, QueuedStatsPublication, StatsPublicationKind, StatsSealingOwner,
    StatsSealingResult, StatsSealingTransaction,
};
use super::{
    AtomOrdering, EnabledRecorder, ErrorCategory, Instant, PacketRejectionCategory,
    ProducerSealResult, RecorderRuntime, STATS_MERGE_EVENTS, STATS_MERGE_INTERVAL, Snapshot, Stats,
    StatsPublication, StatsRecorder, StatsSink, record_categorical_error_snapshot,
    record_drop_error_snapshot, record_drop_oversize_snapshot, record_handshake_snapshot,
    record_packet_rejection_snapshot, record_send_snapshot, record_spurious_readiness_snapshot,
};
use std::time::Duration;

impl StatsRecorder {
    fn update(&mut self, update: impl FnOnce(&mut Snapshot)) {
        self.update_at(Instant::now(), update);
    }

    pub(super) fn update_at(&mut self, _now: Instant, update: impl FnOnce(&mut Snapshot)) {
        let RecorderRuntime::Enabled(enabled) = &mut self.runtime else {
            return;
        };
        if !matches!(enabled.producer.lifecycle(), Ok(ProducerLifecycle::Running)) {
            crate::runtime_support::publish_process_fatal(format_args!(
                "stats producer {} received accounting after sealing",
                enabled.producer_index
            ));
            return;
        }
        update(&mut enabled.local.active);
        enabled.local.events = enabled.local.events.saturating_add(1);
        // Packet accounting is deliberately thread-local. Queue publication is
        // performed by `maintenance`, after packet flow/socket/protocol
        // authorities have been released. This prevents the bounded
        // Crossbeam queue's shared indices from becoming a hidden packet-path
        // authority while preserving the event/time publication thresholds.
    }

    pub(crate) fn maintenance(&mut self) {
        let RecorderRuntime::Enabled(enabled) = &mut self.runtime else {
            return;
        };
        let now = Instant::now();
        let should_publish = enabled.local.events >= STATS_MERGE_EVENTS
            || (enabled.local.events != 0
                && now.saturating_duration_since(enabled.local.last_merge) >= STATS_MERGE_INTERVAL);
        if should_publish {
            enabled.publish_pending(now);
        } else {
            enabled.retry_unpublished();
        }
    }

    pub(crate) fn begin_final_flush(&self) -> u64 {
        match &self.runtime {
            RecorderRuntime::Disabled => 0,
            RecorderRuntime::Enabled(enabled) => enabled.shared.begin_final_flush(),
        }
    }

    pub(crate) fn seal_until(mut self, generation: u64, deadline: Instant) -> ProducerSealResult {
        let _flush = crate::authority::audited_operation(crate::authority::OperationId::StatsFlush);
        let RecorderRuntime::Enabled(enabled) = &mut self.runtime else {
            return ProducerSealResult::Sealed;
        };
        let transaction = match StatsSealingTransaction::begin(
            ProductionStatsSealing { enabled, deadline },
            generation,
        ) {
            Ok(transaction) => transaction,
            Err(_) => {
                return ProducerSealResult::Failed;
            }
        };
        match transaction.seal() {
            Ok(StatsSealingResult::Sealed) => ProducerSealResult::Sealed,
            Ok(StatsSealingResult::DeadlineExceeded) => ProducerSealResult::DeadlineExceeded,
            Err(_) => ProducerSealResult::Failed,
        }
    }

    #[cfg(test)]
    pub(crate) fn is_disabled(&self) -> bool {
        matches!(&self.runtime, RecorderRuntime::Disabled)
    }

    #[cfg(test)]
    pub(crate) fn last_merge_for_test(&self) -> Option<Instant> {
        match &self.runtime {
            RecorderRuntime::Disabled => None,
            RecorderRuntime::Enabled(enabled) => Some(enabled.local.last_merge),
        }
    }
}

impl EnabledRecorder {
    pub(super) fn publish_pending(&mut self, now: Instant) {
        if self.local.sequence_exhausted {
            self.shared
                .final_flush_incomplete
                .store(true, AtomOrdering::Release);
            return;
        }
        self.local.events = 0;
        self.local.last_merge = now;
        let active = std::mem::take(&mut self.local.active);
        if let Some((_, unpublished)) = &mut self.local.unpublished {
            Stats::merge_snapshot(unpublished, active);
        } else if !active.is_empty() {
            let sequence = self.local.next_sequence;
            self.local.unpublished = Some((sequence, active));
        }
        self.retry_unpublished();
    }

    fn retry_unpublished(&mut self) {
        loop {
            let publication = {
                self.local
                    .unpublished
                    .take()
                    .map(|(sequence, delta)| StatsPublication::delta(sequence, delta))
                    .or_else(|| {
                        self.local.pending_flush_marker.take().map(
                            |(generation, through_sequence)| {
                                StatsPublication::flush_marker(generation, through_sequence)
                            },
                        )
                    })
            };
            let Some(publication) = publication else {
                return;
            };
            let completion = match publication.kind {
                StatsPublicationKind::Delta => PublicationCompletion::Delta(publication.sequence),
                StatsPublicationKind::FlushMarker => {
                    PublicationCompletion::FlushMarker(publication.generation)
                }
            };
            let queued = self.producer.queue_publication(publication);
            match queued {
                QueuedStatsPublication::Queued {
                    notify_required,
                    notification_generation_exhausted,
                } => {
                    self.complete_publication(completion);
                    if notification_generation_exhausted {
                        crate::runtime_support::publish_process_fatal(format_args!(
                            "stats producer {} notification generation exhausted",
                            self.producer_index
                        ));
                    } else {
                        self.shared
                            .notify_producer_ready(self.producer_index, notify_required);
                    }
                }
                QueuedStatsPublication::Returned(publication) => {
                    match publication.kind {
                        StatsPublicationKind::Delta => {
                            self.local.unpublished =
                                Some((publication.sequence, publication.delta));
                        }
                        StatsPublicationKind::FlushMarker => {
                            self.local.pending_flush_marker =
                                Some((publication.generation, publication.through_sequence));
                        }
                    }
                    return;
                }
            }
        }
    }

    fn complete_publication(&mut self, publication: PublicationCompletion) {
        let local = &mut self.local;
        match publication {
            PublicationCompletion::Delta(sequence) => {
                local.last_queued_sequence = sequence;
                let Some(next) = sequence.checked_add(1) else {
                    local.sequence_exhausted = true;
                    crate::runtime_support::publish_process_fatal(format_args!(
                        "stats producer {} sequence exhausted",
                        self.producer_index
                    ));
                    return;
                };
                local.next_sequence = next;
            }
            PublicationCompletion::FlushMarker(generation) => {
                local.queued_flush_generation = generation;
            }
        }
    }

    fn queue_flush_marker(&mut self, generation: u64) {
        if self.local.queued_flush_generation >= generation
            || self
                .local
                .pending_flush_marker
                .is_some_and(|(pending, _)| pending >= generation)
        {
            return;
        }
        if self.local.unpublished.is_some() {
            self.retry_unpublished();
            if self.local.unpublished.is_some() {
                return;
            }
        }
        self.local.pending_flush_marker = Some((generation, self.local.last_queued_sequence));
        self.retry_unpublished();
    }
}

struct ProductionStatsSealing<'a> {
    enabled: &'a mut EnabledRecorder,
    deadline: Instant,
}

impl StatsSealingOwner for ProductionStatsSealing<'_> {
    type Error = crate::runtime_support::RuntimeFailure;

    fn begin_sealing(&self, generation: u64) -> Result<(), Self::Error> {
        self.enabled.producer.begin_sealing(generation)
    }

    fn drive_sealing_once(&mut self, generation: u64) -> Result<(), Self::Error> {
        self.enabled.publish_pending(Instant::now());
        self.enabled.queue_flush_marker(generation);
        if self.enabled.local.queued_flush_generation < generation
            && !matches!(
                self.enabled.producer.lifecycle(),
                Ok(ProducerLifecycle::Sealing)
            )
        {
            return Err(crate::runtime_support::RuntimeFailure::fatal(format_args!(
                "stats sealing transaction lost producer ownership"
            )));
        }
        Ok(())
    }

    fn marker_is_queued(&self, generation: u64) -> bool {
        self.enabled.local.queued_flush_generation >= generation
    }

    fn deadline_reached(&self) -> bool {
        Instant::now() >= self.deadline
    }

    fn wait_before_retry(&self) {
        crate::authority::audited_thread_sleep(Duration::from_millis(1));
    }

    fn finish_sealing(&self, generation: u64) -> Result<(), Self::Error> {
        self.enabled.producer.finish_sealing(generation)
    }

    fn abandon_sealing(&self) {
        self.enabled
            .shared
            .final_flush_incomplete
            .store(true, AtomOrdering::Release);
        let _abandoned = self.enabled.producer.abandon();
    }
}

enum PublicationCompletion {
    Delta(u64),
    FlushMarker(u64),
}

impl Drop for StatsRecorder {
    fn drop(&mut self) {
        let RecorderRuntime::Enabled(enabled) = &self.runtime else {
            return;
        };
        if matches!(
            enabled.producer.lifecycle(),
            Ok(ProducerLifecycle::Running | ProducerLifecycle::Sealing)
        ) {
            if enabled.producer.abandon()
                && enabled
                    .shared
                    .abandoned_producers
                    .try_update(AtomOrdering::Release, AtomOrdering::Relaxed, |value| {
                        value.checked_add(1)
                    })
                    .is_err()
            {
                crate::runtime_support::publish_process_fatal(format_args!(
                    "stats abandoned-producer counter exhausted"
                ));
            }
            enabled
                .shared
                .final_flush_incomplete
                .store(true, AtomOrdering::Release);
        }
    }
}

impl Snapshot {
    fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

impl StatsSink for StatsRecorder {
    fn send_add(
        &mut self,
        c2u: bool,
        bytes: u64,
        received_at: Instant,
        attempted_at: Instant,
        completed_at: Instant,
    ) {
        self.update(|snapshot| {
            record_send_snapshot(
                snapshot,
                c2u,
                bytes,
                received_at,
                attempted_at,
                completed_at,
            );
        });
    }

    fn drop_err(&mut self, c2u: bool) {
        self.update(|snapshot| record_drop_error_snapshot(snapshot, c2u));
    }

    fn receive_error(&mut self, c2u: bool) {
        self.update(|snapshot| {
            record_categorical_error_snapshot(snapshot, c2u, ErrorCategory::Receive);
        });
    }

    fn spurious_readiness(&mut self, _c2u: bool) {
        self.update(record_spurious_readiness_snapshot);
    }

    fn user_send_error(&mut self, c2u: bool) {
        self.update(|snapshot| {
            record_categorical_error_snapshot(snapshot, c2u, ErrorCategory::UserSend);
        });
    }

    fn control_send_error(&mut self, c2u: bool) {
        self.update(|snapshot| {
            record_categorical_error_snapshot(snapshot, c2u, ErrorCategory::ControlSend);
        });
    }

    fn admission_drop(&mut self, c2u: bool) {
        self.update(|snapshot| {
            record_categorical_error_snapshot(snapshot, c2u, ErrorCategory::Admission);
        });
    }

    fn topology_error(&mut self, c2u: bool) {
        self.update(|snapshot| {
            record_categorical_error_snapshot(snapshot, c2u, ErrorCategory::Topology);
        });
    }

    fn malformed_packet(&mut self, c2u: bool) {
        self.update(|snapshot| {
            record_categorical_error_snapshot(snapshot, c2u, ErrorCategory::MalformedPacket);
        });
    }

    fn wrong_peer_drop(&mut self, c2u: bool) {
        self.update(|snapshot| {
            record_categorical_error_snapshot(snapshot, c2u, ErrorCategory::WrongPeer);
        });
    }

    fn wrong_source_drop(&mut self, c2u: bool) {
        self.update(|snapshot| {
            record_categorical_error_snapshot(snapshot, c2u, ErrorCategory::WrongSource);
        });
    }

    fn handshake_invalid_drop(&mut self, c2u: bool) {
        self.update(|snapshot| {
            record_categorical_error_snapshot(snapshot, c2u, ErrorCategory::HandshakeInvalid);
        });
    }

    fn replay_drop(&mut self, c2u: bool) {
        self.update(|snapshot| {
            record_categorical_error_snapshot(snapshot, c2u, ErrorCategory::Replay);
        });
    }

    fn icmp_abuse_budget_drop(&mut self, c2u: bool) {
        self.update(|snapshot| {
            record_categorical_error_snapshot(snapshot, c2u, ErrorCategory::IcmpAbuseBudget);
        });
    }

    fn stale_session_drop(&mut self, c2u: bool) {
        self.update(|snapshot| {
            record_categorical_error_snapshot(snapshot, c2u, ErrorCategory::StaleSession);
        });
    }

    fn stale_authority_drop(&mut self, c2u: bool) {
        self.update(|snapshot| {
            record_categorical_error_snapshot(snapshot, c2u, ErrorCategory::StaleAuthority);
        });
    }

    fn packet_rejection(&mut self, _c2u: bool, category: PacketRejectionCategory) {
        self.update(|snapshot| record_packet_rejection_snapshot(snapshot, category));
    }

    fn invariant_failure(&mut self, c2u: bool) {
        self.update(|snapshot| {
            record_categorical_error_snapshot(snapshot, c2u, ErrorCategory::InvariantFailure);
        });
    }

    fn drop_oversize(&mut self, c2u: bool) {
        self.update(|snapshot| record_drop_oversize_snapshot(snapshot, c2u));
    }

    fn handshake_invalid_control(&mut self, _c2u: bool) {
        self.update(|snapshot| record_handshake_snapshot(snapshot, true));
    }

    fn handshake_stale_ack(&mut self) {
        self.update(|snapshot| record_handshake_snapshot(snapshot, false));
    }
}
