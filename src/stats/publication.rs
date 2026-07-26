use super::Snapshot;
use super::finality_core::{
    AcceptedStatsPublication, ProducerLifecycle, QueuedStatsPublication, StatsFinalityCore,
    StatsFinalityError, StatsPublication,
};
use crate::runtime_support::RuntimeFailure;
use crossbeam_channel::TrySendError;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::time::Instant;

pub(super) const STATS_PUBLICATION_QUEUE_CAPACITY: usize = 4;
pub(super) const STATS_CONTROL_FALLBACK: std::time::Duration = std::time::Duration::from_millis(50);

type ProductionStatsFinality = StatsFinalityCore<
    crate::authority::AuthorityAtomic<crate::authority::tags::StatsPublication, AtomicU8>,
    crate::authority::AuthorityAtomic<crate::authority::tags::StatsPublication, AtomicU64>,
    crate::authority::AuthorityAtomic<crate::authority::tags::StatsPublication, AtomicBool>,
    crate::authority::AuthorityQueue<
        crate::authority::tags::StatsPublication,
        StatsPublication<Snapshot>,
    >,
>;

#[derive(Clone, Copy, Debug)]
pub(super) enum StatsControl {
    ProducerReady(usize),
    FlushRequested,
}

pub(super) struct StatsProducer {
    finality: ProductionStatsFinality,
}

impl StatsProducer {
    fn new(index: usize) -> Self {
        Self {
            finality: StatsFinalityCore::new(
                crate::authority::AuthorityAtomic::new_u8(
                    ProducerLifecycle::Unclaimed as u8,
                    crate::authority::AtomicProtocolId::StatsFinality,
                ),
                crate::authority::AuthorityAtomic::new_u64(
                    0,
                    crate::authority::AtomicProtocolId::StatsFinality,
                ),
                crate::authority::AuthorityAtomic::new_u64(
                    0,
                    crate::authority::AtomicProtocolId::StatsFinality,
                ),
                crate::authority::AuthorityAtomic::new_u64(
                    0,
                    crate::authority::AtomicProtocolId::StatsFinality,
                ),
                crate::authority::AuthorityAtomic::new_bool(
                    false,
                    crate::authority::AtomicProtocolId::StatsFinality,
                ),
                crate::authority::AuthorityAtomic::new_u64(
                    0,
                    crate::authority::AtomicProtocolId::StatsFinality,
                ),
                crate::authority::AuthorityQueue::new(
                    STATS_PUBLICATION_QUEUE_CAPACITY,
                    crate::authority::AuthorityInstance {
                        id: crate::authority::AuthorityId::StatsPublication,
                        flow: 0,
                        direction: 0,
                        kind: 0,
                        session: index as u64,
                    },
                ),
            ),
        }
    }

    pub(super) fn lifecycle(&self) -> Result<ProducerLifecycle, RuntimeFailure> {
        self.finality.lifecycle().map_err(stats_finality_failure)
    }

    pub(super) fn abandon(&self) -> bool {
        match self.finality.abandon() {
            Ok(abandoned) => abandoned,
            Err(error) => {
                crate::runtime_support::publish_process_fatal(format_args!(
                    "stats producer abandonment failed: {error:?}"
                ));
                false
            }
        }
    }

    pub(super) fn begin_sealing(&self, generation: u64) -> Result<(), RuntimeFailure> {
        self.finality
            .begin_sealing(generation)
            .map_err(stats_finality_failure)
    }

    pub(super) fn finish_sealing(&self, generation: u64) -> Result<(), RuntimeFailure> {
        self.finality
            .finish_sealing(generation)
            .map_err(stats_finality_failure)
    }

    pub(super) fn queue_publication(
        &self,
        publication: StatsPublication<Snapshot>,
    ) -> QueuedStatsPublication<Snapshot> {
        self.finality.queue_publication(publication)
    }

    pub(super) fn accept_next(
        &self,
        last_sequence: &mut u64,
    ) -> Result<Option<AcceptedStatsPublication<Snapshot>>, RuntimeFailure> {
        self.finality
            .accept_next(last_sequence)
            .map_err(stats_finality_failure)
    }

    pub(super) fn acknowledged(&self, generation: u64) -> Result<bool, RuntimeFailure> {
        self.finality
            .acknowledged(generation)
            .map_err(stats_finality_failure)
    }

    pub(super) fn ready_generation(&self) -> u64 {
        self.finality.ready_generation()
    }

    pub(super) fn rearm_notification(&self, observed_generation: u64) -> bool {
        self.finality.rearm_notification(observed_generation)
    }

    #[cfg(test)]
    pub(super) fn acknowledged_generation_for_test(&self) -> u64 {
        self.finality.acknowledged_generation_for_test()
    }
}

pub(super) fn stats_finality_failure(error: StatsFinalityError) -> RuntimeFailure {
    RuntimeFailure::fatal(format_args!("stats producer finality failed: {error:?}"))
}

pub(super) struct EnabledStats {
    pub(super) producers: Box<[Arc<StatsProducer>]>,
    pub(super) flush_generation:
        crate::authority::AuthorityAtomic<crate::authority::tags::StatsPublication, AtomicU64>,
    pub(super) final_flush_incomplete:
        crate::authority::AuthorityAtomic<crate::authority::tags::StatsPublication, AtomicBool>,
    pub(super) abandoned_producers:
        crate::authority::AuthorityAtomic<crate::authority::tags::DiagnosticCounter, AtomicU64>,
    pub(super) control_sender: crate::authority::AuthorityChannelSender<
        crate::authority::tags::StatsPublication,
        StatsControl,
    >,
    pub(super) start:
        crate::authority::AuthorityOnceLock<crate::authority::tags::StatsPublication, Instant>,
}

pub(crate) struct StatsAggregatorBootstrap {
    pub(super) receiver: crate::authority::SingleConsumerBootstrap<
        crate::authority::AuthorityChannelReceiver<
            crate::authority::tags::StatsPublication,
            StatsControl,
        >,
    >,
}

impl EnabledStats {
    pub(super) fn new(producer_count: usize) -> io::Result<(Arc<Self>, StatsAggregatorBootstrap)> {
        let producer_count = producer_count.max(1);
        let control_capacity = producer_count
            .checked_add(2)
            .ok_or_else(|| io::Error::other("stats control capacity exceeds usize"))?;
        let (control_sender, control_receiver) = crate::authority::bounded_authority_channel(
            control_capacity,
            crate::authority::AuthorityInstance::singleton(
                crate::authority::AuthorityId::StatsPublication,
            ),
            crate::authority::OperationId::ChannelSend,
            crate::authority::OperationId::ChannelReceive,
        );
        let mut producers = Vec::new();
        producers
            .try_reserve_exact(producer_count)
            .map_err(|_| io::Error::other("could not allocate stats producer slots"))?;
        producers.extend((0..producer_count).map(|index| Arc::new(StatsProducer::new(index))));
        let shared = Arc::new(Self {
            producers: producers.into_boxed_slice(),
            flush_generation: crate::authority::AuthorityAtomic::new_u64(
                0,
                crate::authority::AtomicProtocolId::StatsFinality,
            ),
            final_flush_incomplete: crate::authority::AuthorityAtomic::new_bool(
                false,
                crate::authority::AtomicProtocolId::StatsFinality,
            ),
            abandoned_producers: crate::authority::AuthorityAtomic::new_u64(
                0,
                crate::authority::AtomicProtocolId::DiagnosticCounter,
            ),
            control_sender,
            start: crate::authority::AuthorityOnceLock::new(),
        });
        Ok((
            shared,
            StatsAggregatorBootstrap {
                receiver: crate::authority::SingleConsumerBootstrap::new(control_receiver),
            },
        ))
    }

    pub(super) fn claim_producer(
        self: &Arc<Self>,
        producer_index: usize,
    ) -> Result<Arc<StatsProducer>, RuntimeFailure> {
        let producer = self
            .producers
            .get(producer_index)
            .map(Arc::clone)
            .ok_or_else(|| {
                RuntimeFailure::fatal(format_args!(
                    "stats recorder index {producer_index} is outside the configured producer set"
                ))
            })?;
        if producer.finality.claim().is_err() {
            return Err(RuntimeFailure::fatal(format_args!(
                "stats producer {producer_index} was claimed more than once"
            )));
        }
        Ok(producer)
    }

    pub(super) fn notify_producer_ready(&self, producer_index: usize, notify_required: bool) {
        if self.producers.get(producer_index).is_none() {
            crate::runtime_support::publish_process_fatal(format_args!(
                "stats producer notification index {producer_index} is invalid"
            ));
            return;
        }
        if notify_required {
            match self
                .control_sender
                .try_send(StatsControl::ProducerReady(producer_index))
            {
                Ok(()) | Err(TrySendError::Full(_)) => {}
                Err(TrySendError::Disconnected(_)) => {}
            }
        }
    }

    pub(super) fn begin_final_flush(&self) -> u64 {
        loop {
            let current = self.flush_generation.load(Ordering::Acquire);
            if current != 0 {
                return current;
            }
            match self
                .flush_generation
                .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => {
                    match self.control_sender.try_send(StatsControl::FlushRequested) {
                        Ok(())
                        | Err(TrySendError::Full(_))
                        | Err(TrySendError::Disconnected(_)) => {}
                    }
                    return 1;
                }
                Err(observed) if observed != 0 => return observed,
                Err(_) => {}
            }
        }
    }

    pub(super) fn all_live_producers_acknowledged(
        &self,
        generation: u64,
    ) -> Result<bool, RuntimeFailure> {
        self.producers.iter().try_fold(true, |complete, producer| {
            Ok(complete && producer.acknowledged(generation)?)
        })
    }
}

pub(super) enum StatsRuntime {
    Disabled,
    Enabled(Arc<EnabledStats>),
}
