use crate::atomic_core::{
    AtomicBoolAuthority, AtomicU8Authority, AtomicU64Authority, AtomicU64Value,
    StatsPublicationOrderError, accept_stats_delta, accept_stats_flush_marker,
    advance_notification_generation, begin_stats_sealing, finish_stats_sealing,
    mark_notification_pending, rearm_notification_after_clear,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum StatsPublicationKind {
    Delta,
    FlushMarker,
}

#[derive(Debug)]
pub(super) struct StatsPublication<Delta> {
    pub(super) kind: StatsPublicationKind,
    pub(super) sequence: u64,
    pub(super) delta: Delta,
    pub(super) generation: u64,
    pub(super) through_sequence: u64,
}

impl<Delta: Default> StatsPublication<Delta> {
    pub(super) fn delta(sequence: u64, delta: Delta) -> Self {
        Self {
            kind: StatsPublicationKind::Delta,
            sequence,
            delta,
            generation: 0,
            through_sequence: 0,
        }
    }

    pub(super) fn flush_marker(generation: u64, through_sequence: u64) -> Self {
        Self {
            kind: StatsPublicationKind::FlushMarker,
            sequence: 0,
            delta: Delta::default(),
            generation,
            through_sequence,
        }
    }
}

pub(super) trait StatsPublicationQueue<Delta> {
    fn push_publication(
        &self,
        publication: StatsPublication<Delta>,
    ) -> Result<(), StatsPublication<Delta>>;
    fn pop_publication(&self) -> Option<StatsPublication<Delta>>;
    fn queue_is_empty(&self) -> bool;
}

pub(super) trait StatsSealingOwner {
    type Error;

    fn begin_sealing(&self, generation: u64) -> Result<(), Self::Error>;
    fn drive_sealing_once(&mut self, generation: u64) -> Result<(), Self::Error>;
    fn marker_is_queued(&self, generation: u64) -> bool;
    fn deadline_reached(&self) -> bool;
    fn wait_before_retry(&self);
    fn finish_sealing(&self, generation: u64) -> Result<(), Self::Error>;
    fn abandon_sealing(&self);
}

#[must_use]
pub(super) struct StatsSealingTransaction<Owner>
where
    Owner: StatsSealingOwner,
{
    owner: Owner,
    generation: u64,
    terminal: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum StatsSealingResult {
    Sealed,
    DeadlineExceeded,
}

impl<Owner> StatsSealingTransaction<Owner>
where
    Owner: StatsSealingOwner,
{
    pub(super) fn begin(owner: Owner, generation: u64) -> Result<Self, Owner::Error> {
        owner.begin_sealing(generation)?;
        Ok(Self {
            owner,
            generation,
            terminal: false,
        })
    }

    pub(super) fn seal(mut self) -> Result<StatsSealingResult, Owner::Error> {
        loop {
            self.owner.drive_sealing_once(self.generation)?;
            if self.owner.marker_is_queued(self.generation) {
                self.owner.finish_sealing(self.generation)?;
                self.terminal = true;
                return Ok(StatsSealingResult::Sealed);
            }
            if self.owner.deadline_reached() {
                return Ok(StatsSealingResult::DeadlineExceeded);
            }
            self.owner.wait_before_retry();
        }
    }
}

impl<Owner> Drop for StatsSealingTransaction<Owner>
where
    Owner: StatsSealingOwner,
{
    fn drop(&mut self) {
        if !self.terminal {
            self.owner.abandon_sealing();
        }
    }
}

impl<Tag: crate::authority::AuthoritySpec, Delta> StatsPublicationQueue<Delta>
    for crate::authority::AuthorityQueue<Tag, StatsPublication<Delta>>
{
    fn push_publication(
        &self,
        publication: StatsPublication<Delta>,
    ) -> Result<(), StatsPublication<Delta>> {
        self.push(publication)
    }

    fn pop_publication(&self) -> Option<StatsPublication<Delta>> {
        self.pop()
    }

    fn queue_is_empty(&self) -> bool {
        self.is_empty()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum ProducerLifecycle {
    Unclaimed = 0,
    Running = 1,
    Sealing = 2,
    Sealed = 3,
    Abandoned = 4,
}

impl ProducerLifecycle {
    fn decode(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Unclaimed),
            1 => Some(Self::Running),
            2 => Some(Self::Sealing),
            3 => Some(Self::Sealed),
            4 => Some(Self::Abandoned),
            _ => None,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum StatsFinalityError {
    CorruptedLifecycle(u8),
    InvalidLifecycle(ProducerLifecycle),
    MarkerGenerationMismatch,
    MarkerNotQueued,
    PublicationOrder(StatsPublicationOrderError),
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum AcceptedStatsPublication<Delta> {
    Delta(Delta),
    FlushMarker,
}

#[derive(Debug)]
pub(super) enum QueuedStatsPublication<Delta> {
    Queued {
        notify_required: bool,
        notification_generation_exhausted: bool,
    },
    Returned(StatsPublication<Delta>),
}

/// The production queue-facing lifecycle for one statistics producer.
///
/// This core owns claim, sealing, final-marker publication, ordered
/// consumption, acknowledgement, and abandonment. Production and Loom use
/// the same methods with different atomic and bounded-queue backends.
pub(super) struct StatsFinalityCore<Lifecycle, Generation, Pending, Queue> {
    lifecycle: Lifecycle,
    lifecycle_generation: Generation,
    marker_queued_generation: Generation,
    acknowledged_generation: Generation,
    ready_pending: Pending,
    ready_generation: Generation,
    queue: Queue,
}

impl<Lifecycle, Generation, Pending, Queue> StatsFinalityCore<Lifecycle, Generation, Pending, Queue>
where
    Lifecycle: AtomicU8Authority,
    Generation: AtomicU64Value + AtomicU64Authority,
    Pending: AtomicBoolAuthority,
{
    pub(super) fn new(
        lifecycle: Lifecycle,
        lifecycle_generation: Generation,
        marker_queued_generation: Generation,
        acknowledged_generation: Generation,
        ready_pending: Pending,
        ready_generation: Generation,
        queue: Queue,
    ) -> Self {
        Self {
            lifecycle,
            lifecycle_generation,
            marker_queued_generation,
            acknowledged_generation,
            ready_pending,
            ready_generation,
            queue,
        }
    }

    pub(super) fn lifecycle(&self) -> Result<ProducerLifecycle, StatsFinalityError> {
        let value = self.lifecycle.load_acquire();
        ProducerLifecycle::decode(value).ok_or(StatsFinalityError::CorruptedLifecycle(value))
    }

    pub(super) fn claim(&self) -> Result<(), StatsFinalityError> {
        self.lifecycle
            .compare_release(
                ProducerLifecycle::Unclaimed as u8,
                ProducerLifecycle::Running as u8,
            )
            .map(|_| ())
            .map_err(|observed| self.observed_lifecycle_error(observed))
    }

    pub(super) fn begin_sealing(&self, generation: u64) -> Result<(), StatsFinalityError> {
        begin_stats_sealing(
            &self.lifecycle,
            &self.lifecycle_generation,
            ProducerLifecycle::Running as u8,
            ProducerLifecycle::Sealing as u8,
            generation,
        )
        .map_err(|observed| self.observed_lifecycle_error(observed))
    }

    pub(super) fn queue_publication<Delta>(
        &self,
        publication: StatsPublication<Delta>,
    ) -> QueuedStatsPublication<Delta>
    where
        Queue: StatsPublicationQueue<Delta>,
    {
        let valid = match publication.kind {
            StatsPublicationKind::Delta => {
                matches!(
                    self.lifecycle(),
                    Ok(ProducerLifecycle::Running | ProducerLifecycle::Sealing)
                ) && AtomicU64Value::load_acquire(&self.marker_queued_generation) == 0
            }
            StatsPublicationKind::FlushMarker => {
                self.lifecycle() == Ok(ProducerLifecycle::Sealing)
                    && AtomicU64Value::load_acquire(&self.lifecycle_generation)
                        == publication.generation
                    && AtomicU64Value::load_acquire(&self.marker_queued_generation) == 0
            }
        };
        if !valid {
            return QueuedStatsPublication::Returned(publication);
        }
        let marker_generation = publication.generation;
        let marker = publication.kind == StatsPublicationKind::FlushMarker;
        if let Err(publication) = self.queue.push_publication(publication) {
            return QueuedStatsPublication::Returned(publication);
        }
        if marker {
            self.marker_queued_generation
                .store_release(marker_generation);
        }
        let notification_generation_exhausted =
            advance_notification_generation(&self.ready_generation).is_err();
        QueuedStatsPublication::Queued {
            notify_required: !notification_generation_exhausted
                && mark_notification_pending(&self.ready_pending),
            notification_generation_exhausted,
        }
    }

    pub(super) fn finish_sealing(&self, generation: u64) -> Result<(), StatsFinalityError> {
        if AtomicU64Value::load_acquire(&self.marker_queued_generation) != generation {
            return Err(StatsFinalityError::MarkerNotQueued);
        }
        finish_stats_sealing(
            &self.lifecycle,
            &self.lifecycle_generation,
            ProducerLifecycle::Sealing as u8,
            ProducerLifecycle::Sealed as u8,
            generation,
        )
        .map_err(|observed| self.observed_lifecycle_error(observed))
    }

    pub(super) fn accept_next<Delta>(
        &self,
        last_sequence: &mut u64,
    ) -> Result<Option<AcceptedStatsPublication<Delta>>, StatsFinalityError>
    where
        Queue: StatsPublicationQueue<Delta>,
    {
        let Some(publication) = self.queue.pop_publication() else {
            return Ok(None);
        };
        self.accept_publication(publication, last_sequence)
            .map(Some)
    }

    pub(super) fn accept_publication<Delta>(
        &self,
        publication: StatsPublication<Delta>,
        last_sequence: &mut u64,
    ) -> Result<AcceptedStatsPublication<Delta>, StatsFinalityError> {
        match publication.kind {
            StatsPublicationKind::Delta => {
                accept_stats_delta(last_sequence, publication.sequence)
                    .map_err(StatsFinalityError::PublicationOrder)?;
                Ok(AcceptedStatsPublication::Delta(publication.delta))
            }
            StatsPublicationKind::FlushMarker => {
                if AtomicU64Value::load_acquire(&self.lifecycle_generation)
                    != publication.generation
                {
                    return Err(StatsFinalityError::MarkerGenerationMismatch);
                }
                accept_stats_flush_marker(*last_sequence, publication.through_sequence)
                    .map_err(StatsFinalityError::PublicationOrder)?;
                self.acknowledged_generation
                    .store_release(publication.generation);
                Ok(AcceptedStatsPublication::FlushMarker)
            }
        }
    }

    pub(super) fn acknowledged(&self, generation: u64) -> Result<bool, StatsFinalityError> {
        Ok(match self.lifecycle()? {
            ProducerLifecycle::Unclaimed | ProducerLifecycle::Abandoned => true,
            ProducerLifecycle::Running | ProducerLifecycle::Sealing => false,
            ProducerLifecycle::Sealed => {
                AtomicU64Value::load_acquire(&self.lifecycle_generation) == generation
                    && AtomicU64Value::load_acquire(&self.acknowledged_generation) >= generation
            }
        })
    }

    pub(super) fn rearm_notification<Delta>(&self, observed_generation: u64) -> bool
    where
        Queue: StatsPublicationQueue<Delta>,
    {
        rearm_notification_after_clear(
            &self.ready_pending,
            &self.ready_generation,
            observed_generation,
            || !self.queue.queue_is_empty(),
        )
    }

    pub(super) fn ready_generation(&self) -> u64 {
        AtomicU64Value::load_acquire(&self.ready_generation)
    }

    pub(super) fn abandon(&self) -> Result<bool, StatsFinalityError> {
        loop {
            let observed = self.lifecycle.load_acquire();
            let lifecycle = ProducerLifecycle::decode(observed)
                .ok_or(StatsFinalityError::CorruptedLifecycle(observed))?;
            if matches!(
                lifecycle,
                ProducerLifecycle::Unclaimed
                    | ProducerLifecycle::Sealed
                    | ProducerLifecycle::Abandoned
            ) {
                return Ok(false);
            }
            if self
                .lifecycle
                .compare_release(observed, ProducerLifecycle::Abandoned as u8)
                .is_ok()
            {
                return Ok(true);
            }
        }
    }

    #[cfg(test)]
    pub(super) fn acknowledged_generation_for_test(&self) -> u64 {
        AtomicU64Value::load_acquire(&self.acknowledged_generation)
    }

    fn observed_lifecycle_error(&self, observed: u8) -> StatsFinalityError {
        ProducerLifecycle::decode(observed).map_or(
            StatsFinalityError::CorruptedLifecycle(observed),
            StatsFinalityError::InvalidLifecycle,
        )
    }
}
