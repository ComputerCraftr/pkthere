#![cfg(all(test, loom, not(miri), not(target_env = "musl")))]

use super::finality_core::{
    AcceptedStatsPublication, ProducerLifecycle, QueuedStatsPublication, StatsFinalityCore,
    StatsFinalityError, StatsPublication, StatsPublicationQueue, StatsSealingOwner,
    StatsSealingTransaction,
};
use crate::atomic_core::StatsPublicationOrderError;
use loom::sync::atomic::{AtomicBool, AtomicU8, AtomicU64};
use loom::sync::{Arc, Mutex};
use loom::thread;
use std::collections::VecDeque;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct TinyDelta(u8);

struct ModeledQueue {
    capacity: usize,
    values: Mutex<VecDeque<StatsPublication<TinyDelta>>>,
}

impl ModeledQueue {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            values: Mutex::new(VecDeque::new()),
        }
    }
}

impl StatsPublicationQueue<TinyDelta> for ModeledQueue {
    fn push_publication(
        &self,
        publication: StatsPublication<TinyDelta>,
    ) -> Result<(), StatsPublication<TinyDelta>> {
        let mut values = self.values.lock().expect("modeled queue push");
        if values.len() == self.capacity {
            return Err(publication);
        }
        values.push_back(publication);
        Ok(())
    }

    fn pop_publication(&self) -> Option<StatsPublication<TinyDelta>> {
        self.values.lock().expect("modeled queue pop").pop_front()
    }

    fn queue_is_empty(&self) -> bool {
        self.values.lock().expect("modeled queue state").is_empty()
    }
}

type LoomFinality = StatsFinalityCore<AtomicU8, AtomicU64, AtomicBool, ModeledQueue>;

struct LoomSealingOwner {
    core: Arc<LoomFinality>,
    pending: Option<StatsPublication<TinyDelta>>,
    marker_generation: u64,
    queued_generation: u64,
    deadline_reached: bool,
}

impl LoomSealingOwner {
    fn marker(core: Arc<LoomFinality>, generation: u64, through_sequence: u64) -> Self {
        Self {
            core,
            pending: Some(StatsPublication::flush_marker(generation, through_sequence)),
            marker_generation: generation,
            queued_generation: 0,
            deadline_reached: false,
        }
    }
}

impl StatsSealingOwner for LoomSealingOwner {
    type Error = StatsFinalityError;

    fn begin_sealing(&self, generation: u64) -> Result<(), Self::Error> {
        self.core.begin_sealing(generation)
    }

    fn drive_sealing_once(&mut self, _generation: u64) -> Result<(), Self::Error> {
        let Some(publication) = self.pending.take() else {
            return Ok(());
        };
        match self.core.queue_publication(publication) {
            QueuedStatsPublication::Queued { .. } => {
                self.queued_generation = self.marker_generation;
            }
            QueuedStatsPublication::Returned(publication) => {
                self.pending = Some(publication);
                let lifecycle = self.core.lifecycle()?;
                if lifecycle != ProducerLifecycle::Sealing {
                    return Err(StatsFinalityError::InvalidLifecycle(lifecycle));
                }
            }
        }
        Ok(())
    }

    fn marker_is_queued(&self, generation: u64) -> bool {
        self.queued_generation >= generation
    }

    fn deadline_reached(&self) -> bool {
        self.deadline_reached
    }

    fn wait_before_retry(&self) {}

    fn finish_sealing(&self, generation: u64) -> Result<(), Self::Error> {
        self.core.finish_sealing(generation)
    }

    fn abandon_sealing(&self) {
        let _result = self.core.abandon();
    }
}

fn core(capacity: usize) -> LoomFinality {
    StatsFinalityCore::new(
        AtomicU8::new(ProducerLifecycle::Unclaimed as u8),
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicBool::new(false),
        AtomicU64::new(0),
        ModeledQueue::new(capacity),
    )
}

#[test]
fn production_stats_core_acknowledges_only_a_fifo_marker_after_its_delta() {
    loom::model(|| {
        let core = Arc::new(core(2));
        core.claim().expect("claim producer");
        assert!(matches!(
            core.queue_publication(StatsPublication::delta(1, TinyDelta(7))),
            QueuedStatsPublication::Queued { .. }
        ));
        let sealing =
            StatsSealingTransaction::begin(LoomSealingOwner::marker(Arc::clone(&core), 3, 1), 3)
                .expect("begin sealing transaction");

        let producer_core = Arc::clone(&core);
        let producer = thread::spawn(move || {
            drop(producer_core);
            sealing.seal()
        });

        let aggregator_core = Arc::clone(&core);
        let aggregator = thread::spawn(move || {
            let mut last_sequence = 0;
            let first = aggregator_core
                .accept_next(&mut last_sequence)
                .expect("accept first publication");
            let second = aggregator_core
                .accept_next(&mut last_sequence)
                .expect("accept second publication");
            (first, second, last_sequence)
        });

        assert_eq!(
            producer.join().expect("producer actor"),
            Ok(super::finality_core::StatsSealingResult::Sealed)
        );
        let (first, second, last_sequence) = aggregator.join().expect("aggregator actor");
        assert!(matches!(
            first,
            Some(AcceptedStatsPublication::Delta(TinyDelta(7)))
        ));
        if second.is_none() {
            let mut eventual_last_sequence = last_sequence;
            assert!(matches!(
                core.accept_next(&mut eventual_last_sequence)
                    .expect("eventual marker"),
                Some(AcceptedStatsPublication::FlushMarker)
            ));
        } else {
            assert!(matches!(
                second,
                Some(AcceptedStatsPublication::FlushMarker)
            ));
        }
        let acknowledged = core.acknowledged(3).expect("final acknowledgement");
        assert!(acknowledged);
    });
}

#[test]
fn production_stats_core_queue_full_returns_owned_delta_for_exact_retry() {
    loom::model(|| {
        let core = core(1);
        core.claim().expect("claim producer");
        assert!(matches!(
            core.queue_publication(StatsPublication::delta(1, TinyDelta(5))),
            QueuedStatsPublication::Queued { .. }
        ));
        let QueuedStatsPublication::Returned(retained) =
            core.queue_publication(StatsPublication::delta(2, TinyDelta(9)))
        else {
            panic!("full queue must return the exact publication");
        };
        assert_eq!((retained.sequence, retained.delta), (2, TinyDelta(9)));

        let mut last_sequence = 0;
        assert!(matches!(
            core.accept_next(&mut last_sequence)
                .expect("accept first delta"),
            Some(AcceptedStatsPublication::Delta(TinyDelta(5)))
        ));
        assert!(matches!(
            core.queue_publication(retained),
            QueuedStatsPublication::Queued { .. }
        ));
        assert!(matches!(
            core.accept_next(&mut last_sequence)
                .expect("accept retained delta"),
            Some(AcceptedStatsPublication::Delta(TinyDelta(9)))
        ));
        assert_eq!(last_sequence, 2);
    });
}

#[test]
fn production_stats_core_notification_clear_recheck_cannot_lose_publication() {
    loom::model(|| {
        let core = Arc::new(core(2));
        core.claim().expect("claim producer");
        assert!(matches!(
            core.queue_publication(StatsPublication::delta(1, TinyDelta(1))),
            QueuedStatsPublication::Queued {
                notify_required: true,
                notification_generation_exhausted: false,
            }
        ));

        let aggregator_core = Arc::clone(&core);
        let aggregator = thread::spawn(move || {
            let observed_generation = aggregator_core.ready_generation();
            let mut last_sequence = 0;
            let _ = aggregator_core
                .accept_next(&mut last_sequence)
                .expect("drain first publication");
            aggregator_core.rearm_notification(observed_generation)
        });

        let producer_core = Arc::clone(&core);
        let producer = thread::spawn(move || {
            producer_core.queue_publication(StatsPublication::delta(2, TinyDelta(2)))
        });

        let rearmed = aggregator.join().expect("aggregator actor");
        let second = producer.join().expect("producer actor");
        let producer_notified = matches!(
            second,
            QueuedStatsPublication::Queued {
                notify_required: true,
                notification_generation_exhausted: false,
            }
        );
        assert!(
            rearmed || producer_notified,
            "a queued publication must remain represented by pending state or a producer hint"
        );
    });
}

#[test]
fn production_stats_core_sealing_and_abandonment_have_one_terminal_owner() {
    loom::model(|| {
        let core = Arc::new(core(1));
        core.claim().expect("claim producer");

        let sealing_core = Arc::clone(&core);
        let sealing = thread::spawn(move || {
            StatsSealingTransaction::begin(LoomSealingOwner::marker(sealing_core, 4, 0), 4)
                .and_then(StatsSealingTransaction::seal)
        });
        let abandon_core = Arc::clone(&core);
        let abandon = thread::spawn(move || abandon_core.abandon());

        let sealed = sealing.join().expect("sealing actor").is_ok();
        let abandoned = abandon
            .join()
            .expect("abandon actor")
            .expect("valid lifecycle");
        assert!(!(sealed && abandoned));
        assert!(matches!(
            core.lifecycle().expect("terminal lifecycle"),
            ProducerLifecycle::Sealed | ProducerLifecycle::Abandoned
        ));
    });
}

#[test]
fn weakened_marker_before_delta_is_rejected_by_the_production_consumer() {
    loom::model(|| {
        let core = core(2);
        core.claim().expect("claim producer");
        core.begin_sealing(8).expect("begin sealing");
        let mut last_sequence = 0;
        assert_eq!(
            core.accept_publication(
                StatsPublication::<TinyDelta>::flush_marker(8, 1),
                &mut last_sequence,
            ),
            Err(StatsFinalityError::PublicationOrder(
                StatsPublicationOrderError::MarkerBeforeDelta
            ))
        );
    });
}
