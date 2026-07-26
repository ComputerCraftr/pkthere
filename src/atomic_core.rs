//! Atomic transition kernels shared by production and Loom.

mod descriptor_cache;
#[cfg(all(test, loom, not(miri), not(target_env = "musl")))]
mod loom_backend;
mod maintenance_repair;
mod pacing;
mod prepared_session;

pub(crate) use descriptor_cache::{DescriptorCacheCore, DescriptorCacheRegistration};
#[cfg(all(test, loom, not(miri), not(target_env = "musl")))]
pub(crate) use loom_backend::LoomAtomicU64;
pub(crate) use maintenance_repair::MaintenanceRepairCore;
pub(crate) use pacing::{NEVER_PACED, PacingAtomic, PacingCore};
pub(crate) use prepared_session::PreparedSessionGeneration;

#[cfg(all(test, not(miri), not(target_env = "musl")))]
mod pacing_loom;

const WAKE_PENDING_BIT: u64 = 1;
const MAX_WAKE_GENERATION: u64 = u64::MAX >> 1;
pub(crate) const WRITER_RESERVED_EPOCH_LANE: u64 = u64::MAX;

pub(crate) trait AtomicU64Authority {
    fn load_acquire(&self) -> u64;
    fn compare_acqrel(&self, current: u64, next: u64) -> Result<u64, u64>;
    fn compare_release(&self, current: u64, next: u64) -> Result<u64, u64>;
    fn cross_atomic_fence(&self);
}

pub(crate) trait AtomicBoolAuthority {
    fn load_acquire(&self) -> bool;
    fn claim_acqrel(&self) -> bool;
    fn store_release(&self, value: bool);
}

pub(crate) trait AtomicU64Value {
    fn load_acquire(&self) -> u64;
    fn store_release(&self, value: u64);
}

pub(crate) trait AtomicU8Authority {
    fn load_acquire(&self) -> u8;
    fn store_release(&self, value: u8);
    fn compare_acqrel(&self, current: u8, next: u8) -> Result<u8, u8>;
    fn compare_release(&self, current: u8, next: u8) -> Result<u8, u8>;
}

pub(crate) trait AtomicObservationWord {
    fn load_acquire(&self) -> u64;
    fn load_relaxed(&self) -> u64;
    fn compare_acqrel(&self, current: u64, next: u64) -> Result<u64, u64>;
    fn compare_release(&self, current: u64, next: u64) -> Result<u64, u64>;
    fn store_relaxed(&self, value: u64);
}

impl AtomicU64Authority for std::sync::atomic::AtomicU64 {
    fn load_acquire(&self) -> u64 {
        self.load(std::sync::atomic::Ordering::Acquire)
    }

    fn compare_acqrel(&self, current: u64, next: u64) -> Result<u64, u64> {
        self.compare_exchange(
            current,
            next,
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
        )
    }

    fn compare_release(&self, current: u64, next: u64) -> Result<u64, u64> {
        std::sync::atomic::AtomicU64::compare_exchange(
            self,
            current,
            next,
            std::sync::atomic::Ordering::Release,
            std::sync::atomic::Ordering::Acquire,
        )
    }

    fn cross_atomic_fence(&self) {
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
    }
}

impl AtomicBoolAuthority for std::sync::atomic::AtomicBool {
    fn load_acquire(&self) -> bool {
        self.load(std::sync::atomic::Ordering::Acquire)
    }

    fn claim_acqrel(&self) -> bool {
        self.compare_exchange(
            false,
            true,
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
        )
        .is_ok()
    }

    fn store_release(&self, value: bool) {
        self.store(value, std::sync::atomic::Ordering::Release);
    }
}

impl AtomicU64Value for std::sync::atomic::AtomicU64 {
    fn load_acquire(&self) -> u64 {
        self.load(std::sync::atomic::Ordering::Acquire)
    }

    fn store_release(&self, value: u64) {
        self.store(value, std::sync::atomic::Ordering::Release);
    }
}

impl AtomicU8Authority for std::sync::atomic::AtomicU8 {
    fn load_acquire(&self) -> u8 {
        self.load(std::sync::atomic::Ordering::Acquire)
    }

    fn store_release(&self, value: u8) {
        self.store(value, std::sync::atomic::Ordering::Release);
    }

    fn compare_acqrel(&self, current: u8, next: u8) -> Result<u8, u8> {
        std::sync::atomic::AtomicU8::compare_exchange(
            self,
            current,
            next,
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
        )
    }

    fn compare_release(&self, current: u8, next: u8) -> Result<u8, u8> {
        std::sync::atomic::AtomicU8::compare_exchange(
            self,
            current,
            next,
            std::sync::atomic::Ordering::Release,
            std::sync::atomic::Ordering::Acquire,
        )
    }
}

impl AtomicObservationWord for std::sync::atomic::AtomicU64 {
    fn load_acquire(&self) -> u64 {
        self.load(std::sync::atomic::Ordering::Acquire)
    }

    fn load_relaxed(&self) -> u64 {
        self.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn compare_acqrel(&self, current: u64, next: u64) -> Result<u64, u64> {
        self.compare_exchange(
            current,
            next,
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
        )
    }

    fn compare_release(&self, current: u64, next: u64) -> Result<u64, u64> {
        self.compare_exchange(
            current,
            next,
            std::sync::atomic::Ordering::Release,
            std::sync::atomic::Ordering::Acquire,
        )
    }

    fn store_relaxed(&self, value: u64) {
        self.store(value, std::sync::atomic::Ordering::Relaxed);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AllocationStepError {
    QueueFull,
    Exhausted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FifoTicketError {
    Exhausted,
    OwnershipLost,
    CancellationCorrupted,
}

pub(crate) fn allocate_bounded_u64<A: AtomicU64Authority>(
    authority: &A,
    lower_bound: impl Fn() -> u64,
    maximum_outstanding: u64,
) -> Result<u64, AllocationStepError> {
    loop {
        // Observe the lower bound first. A serving-ticket publication is
        // ordered after allocation of that ticket, so its Acquire load makes
        // the corresponding `next` publication visible. Loading `next` first
        // can combine a stale allocation frontier with a newer serving value
        // and falsely report exhaustion during ordinary FIFO progress.
        let lower_bound = lower_bound();
        let current = authority.load_acquire();
        let outstanding = current
            .checked_sub(lower_bound)
            .ok_or(AllocationStepError::Exhausted)?;
        if outstanding >= maximum_outstanding {
            return Err(AllocationStepError::QueueFull);
        }
        let next = current
            .checked_add(1)
            .ok_or(AllocationStepError::Exhausted)?;
        if authority.compare_acqrel(current, next).is_ok() {
            return Ok(current);
        }
    }
}

pub(crate) fn mark_fifo_ticket_cancelled<A: AtomicU64Authority>(
    cancelled_slot: &A,
    ticket: u64,
) -> Result<(), FifoTicketError> {
    cancelled_slot
        .compare_release(0, ticket)
        .map(|_| ())
        .map_err(|_| FifoTicketError::CancellationCorrupted)
}

pub(crate) fn release_fifo_ticket<A: AtomicU64Authority>(
    serving_ticket: &A,
    ticket: u64,
) -> Result<u64, FifoTicketError> {
    let next = ticket.checked_add(1).ok_or(FifoTicketError::Exhausted)?;
    serving_ticket
        .compare_acqrel(ticket, next)
        .map(|_| next)
        .map_err(|_| FifoTicketError::OwnershipLost)
}

pub(crate) fn stabilize_fifo_cancellation<
    Serving: AtomicU64Authority,
    Cancelled: AtomicU64Authority,
>(
    serving_ticket: &Serving,
    cancelled_slot: &Cancelled,
    ticket: u64,
) -> Result<(), FifoTicketError> {
    loop {
        let serving = serving_ticket.load_acquire();
        if serving > ticket {
            return match cancelled_slot.compare_acqrel(ticket, 0) {
                Ok(_) | Err(0) => Ok(()),
                Err(_) => Err(FifoTicketError::CancellationCorrupted),
            };
        }
        if serving == ticket {
            if skip_cancelled_fifo_ticket(serving_ticket, cancelled_slot)? {
                return Ok(());
            }
            // Another owner may have cleared this slot and still be advancing
            // `serving`. Recheck that publication instead of misclassifying
            // the transient handoff as corruption.
            continue;
        }
        // Publish the cancellation into the serving ticket's release sequence.
        // A later AcqRel owner release must observe this RMW before scanning
        // the cancellation slot, closing the mark-versus-release race.
        if serving_ticket.compare_acqrel(serving, serving).is_ok() {
            return Ok(());
        }
    }
}

pub(crate) fn skip_cancelled_fifo_ticket<
    Serving: AtomicU64Authority,
    Cancelled: AtomicU64Authority,
>(
    serving_ticket: &Serving,
    cancelled_slot: &Cancelled,
) -> Result<bool, FifoTicketError> {
    let serving = serving_ticket.load_acquire();
    if cancelled_slot.load_acquire() != serving {
        return Ok(false);
    }
    let next = serving.checked_add(1).ok_or(FifoTicketError::Exhausted)?;
    match cancelled_slot.compare_acqrel(serving, 0) {
        Ok(_) => {}
        Err(0) => return Ok(false),
        Err(_) => return Err(FifoTicketError::CancellationCorrupted),
    }
    match serving_ticket.compare_acqrel(serving, next) {
        Ok(_) => {}
        Err(observed) if observed >= next => {}
        Err(_) => return Err(FifoTicketError::CancellationCorrupted),
    }
    Ok(true)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExpectedPublicationError {
    Exhausted,
    Changed(u64),
}

pub(crate) fn publish_expected_u64<A: AtomicU64Authority>(
    authority: &A,
    expected: u64,
) -> Result<u64, ExpectedPublicationError> {
    let next = expected
        .checked_add(1)
        .ok_or(ExpectedPublicationError::Exhausted)?;
    authority
        .compare_release(expected, next)
        .map(|_| next)
        .map_err(ExpectedPublicationError::Changed)
}

/// Publishes a descriptor-cache revocation request only for a registered
/// worker cache. A concurrent unregister remains safe because unregistering
/// drops the cached strong descriptor before publishing `registered = false`.
pub(crate) fn request_descriptor_cache_revocation<
    Registered: AtomicBoolAuthority,
    Generation: AtomicU64Value,
>(
    registered: &Registered,
    requested: &Generation,
    generation: u64,
) -> bool {
    if !registered.load_acquire() {
        return false;
    }
    requested.store_release(generation);
    true
}

/// Claims one descriptor-cache slot and then revalidates admission.
///
/// A transition may close the gate between the first observation and the
/// registration CAS. The second gate read releases that claim before any
/// descriptor upgrade, so an unregistered strong owner cannot escape the
/// retirement protocol.
pub(crate) fn register_descriptor_cache<Registered: AtomicBoolAuthority, Gate: AtomicU64Value>(
    registered: &Registered,
    gate: &Gate,
    closed_mask: u64,
) -> DescriptorCacheRegistration {
    if gate.load_acquire() & closed_mask != 0 {
        return DescriptorCacheRegistration::GateClosed;
    }
    if !registered.claim_acqrel() {
        return DescriptorCacheRegistration::SlotOccupied;
    }
    if gate.load_acquire() & closed_mask != 0 {
        registered.store_release(false);
        return DescriptorCacheRegistration::GateClosed;
    }
    DescriptorCacheRegistration::Registered
}

pub(crate) fn acknowledge_descriptor_cache_revocation<Generation: AtomicU64Value, T>(
    requested: &Generation,
    acknowledged: &Generation,
    cached_generation: &mut u64,
    topology_epoch: &mut u64,
    descriptor: &mut Option<T>,
) -> bool {
    let generation = requested.load_acquire();
    if generation <= *cached_generation {
        return false;
    }
    *descriptor = None;
    *topology_epoch = u64::MAX;
    *cached_generation = generation;
    acknowledged.store_release(generation);
    true
}

/// Removes a worker cache from revocation accounting. The descriptor is
/// dropped before the Release publication that lets a transition stop waiting.
pub(crate) fn unregister_descriptor_cache<Registered: AtomicBoolAuthority, T>(
    registered: &Registered,
    cached_generation: &mut u64,
    topology_epoch: &mut u64,
    descriptor: &mut Option<T>,
) {
    *descriptor = None;
    *topology_epoch = u64::MAX;
    *cached_generation = 0;
    registered.store_release(false);
}

pub(crate) fn descriptor_cache_revocation_pending<
    Registered: AtomicBoolAuthority,
    Generation: AtomicU64Value,
>(
    registered: &Registered,
    acknowledged: &Generation,
    generation: u64,
) -> bool {
    registered.load_acquire() && acknowledged.load_acquire() < generation
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WakePublication {
    pub(crate) generation: u64,
    pub(crate) send_wake: bool,
}

pub(crate) fn publish_wake_generation<A: AtomicU64Authority>(
    state: &A,
) -> Result<WakePublication, ExpectedPublicationError> {
    loop {
        let current = state.load_acquire();
        let generation = current >> 1;
        let next_generation = generation
            .checked_add(1)
            .filter(|next| *next <= MAX_WAKE_GENERATION)
            .ok_or(ExpectedPublicationError::Exhausted)?;
        let next = (next_generation << 1) | WAKE_PENDING_BIT;
        if state.compare_acqrel(current, next).is_ok() {
            return Ok(WakePublication {
                generation: next_generation,
                send_wake: current & WAKE_PENDING_BIT == 0,
            });
        }
    }
}

pub(crate) fn clear_wake_pending<A: AtomicU64Authority>(state: &A) -> u64 {
    loop {
        let current = state.load_acquire();
        let cleared = current & !WAKE_PENDING_BIT;
        if state.compare_acqrel(current, cleared).is_ok() {
            return current >> 1;
        }
    }
}

pub(crate) fn wake_drain_is_stable<A: AtomicU64Authority>(
    state: &A,
    cleared_generation: u64,
) -> bool {
    state.load_acquire() == cleared_generation << 1
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LaneAdmissionError {
    Closed,
    Occupied,
    EpochExhausted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EpochRefreshError {
    Admission(LaneAdmissionError),
    Changed { expected: u64, observed: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WriterCountError {
    Exhausted,
    Empty,
}

pub(crate) fn announce_writer<A: AtomicU64Authority>(count: &A) -> Result<u64, WriterCountError> {
    loop {
        let current = count.load_acquire();
        let next = current.checked_add(1).ok_or(WriterCountError::Exhausted)?;
        if count.compare_acqrel(current, next).is_ok() {
            return Ok(next);
        }
    }
}

pub(crate) fn withdraw_writer<A: AtomicU64Authority>(count: &A) -> Result<bool, WriterCountError> {
    loop {
        let current = count.load_acquire();
        let next = current.checked_sub(1).ok_or(WriterCountError::Empty)?;
        if count.compare_acqrel(current, next).is_ok() {
            return Ok(next == 0);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ClosedEpochGate {
    pub(crate) previous_epoch: u64,
    pub(crate) next_epoch: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EpochGateTransitionError {
    Closed,
    Changed,
    EpochExhausted,
}

pub(crate) fn close_epoch_gate<A: AtomicU64Authority>(
    gate: &A,
    closed_bit: u64,
) -> Result<ClosedEpochGate, EpochGateTransitionError> {
    let observed = gate.load_acquire();
    if observed & closed_bit != 0 {
        return Err(EpochGateTransitionError::Closed);
    }
    let previous_epoch = observed & !closed_bit;
    let next_epoch = previous_epoch
        .checked_add(1)
        .filter(|epoch| *epoch <= !closed_bit)
        .ok_or(EpochGateTransitionError::EpochExhausted)?;
    gate.compare_acqrel(observed, observed | closed_bit)
        .map_err(|_| EpochGateTransitionError::Changed)?;
    gate.cross_atomic_fence();
    Ok(ClosedEpochGate {
        previous_epoch,
        next_epoch,
    })
}

pub(crate) fn close_expected_epoch_gate<A: AtomicU64Authority>(
    gate: &A,
    expected_epoch: u64,
    closed_bit: u64,
) -> Result<(), EpochGateTransitionError> {
    gate.compare_acqrel(expected_epoch, expected_epoch | closed_bit)
        .map(|_| gate.cross_atomic_fence())
        .map_err(|_| EpochGateTransitionError::Changed)
}

pub(crate) fn reopen_epoch_gate<A: AtomicU64Authority>(
    gate: &A,
    transition: ClosedEpochGate,
    closed_bit: u64,
) -> Result<(), EpochGateTransitionError> {
    gate.compare_release(
        transition.previous_epoch | closed_bit,
        transition.next_epoch,
    )
    .map(|_| ())
    .map_err(|_| EpochGateTransitionError::Changed)
}

pub(crate) fn publish_socket_state_before_gate<
    Association: AtomicU64Value,
    Gate: AtomicU64Value,
>(
    association: &Association,
    association_state: u64,
    gate: &Gate,
    gate_state: u64,
) {
    publish_before_epoch_gate(gate, gate_state, || {
        association.store_release(association_state);
    });
}

pub(crate) fn acquire_epoch_lane<G: AtomicU64Authority, L: AtomicU64Authority>(
    gate: &G,
    lane: &L,
    closed_bit: u64,
) -> Result<u64, LaneAdmissionError> {
    let observed = gate.load_acquire();
    if observed & closed_bit != 0 {
        return Err(LaneAdmissionError::Closed);
    }
    let epoch = observed & !closed_bit;
    let encoded = epoch
        .checked_add(1)
        .ok_or(LaneAdmissionError::EpochExhausted)?;
    match lane.compare_acqrel(0, encoded) {
        Ok(_) => {}
        Err(WRITER_RESERVED_EPOCH_LANE) => return Err(LaneAdmissionError::Closed),
        Err(_) => return Err(LaneAdmissionError::Occupied),
    }
    lane.cross_atomic_fence();
    if gate.load_acquire() != observed {
        lane.compare_release(encoded, 0)
            .map_err(|_| LaneAdmissionError::Occupied)?;
        return Err(LaneAdmissionError::Closed);
    }
    Ok(epoch)
}

/// Reacquires a lane only when the publication epoch is identical to the one
/// released before an external snapshot was captured.
///
/// A successful ordinary admission at a different epoch is immediately
/// released. Callers therefore never receive authority for stale snapshot
/// data collected across a topology publication.
pub(crate) fn reacquire_expected_epoch_lane<G: AtomicU64Authority, L: AtomicU64Authority>(
    gate: &G,
    lane: &L,
    expected_epoch: u64,
    closed_bit: u64,
) -> Result<u64, EpochRefreshError> {
    let observed =
        acquire_epoch_lane(gate, lane, closed_bit).map_err(EpochRefreshError::Admission)?;
    if observed == expected_epoch {
        return Ok(observed);
    }
    release_epoch_lane(lane, observed).map_err(EpochRefreshError::Admission)?;
    Err(EpochRefreshError::Changed {
        expected: expected_epoch,
        observed,
    })
}

pub(crate) fn acquire_contended_epoch_lane<G: AtomicU64Authority, L: AtomicU64Authority>(
    gate: &G,
    lane: &L,
    closed_bit: u64,
) -> Result<u64, LaneAdmissionError> {
    acquire_epoch_lane(gate, lane, closed_bit)
}

pub(crate) fn release_epoch_lane<A: AtomicU64Authority>(
    lane: &A,
    epoch: u64,
) -> Result<(), LaneAdmissionError> {
    let encoded = epoch
        .checked_add(1)
        .ok_or(LaneAdmissionError::EpochExhausted)?;
    lane.compare_release(encoded, 0)
        .map(|_| ())
        .map_err(|_| LaneAdmissionError::Occupied)
}

pub(crate) trait EpochLaneReleaseOwner {
    fn release_owned_epoch_lane(&self, lane_index: usize, epoch: u64);
}

pub(crate) struct EpochLaneGuard<'a, O: EpochLaneReleaseOwner> {
    owner: &'a O,
    lane_index: usize,
    epoch: u64,
}

impl<'a, O: EpochLaneReleaseOwner> EpochLaneGuard<'a, O> {
    pub(crate) const fn new(owner: &'a O, lane_index: usize, epoch: u64) -> Self {
        Self {
            owner,
            lane_index,
            epoch,
        }
    }
}

impl<O: EpochLaneReleaseOwner> Drop for EpochLaneGuard<'_, O> {
    fn drop(&mut self) {
        self.owner
            .release_owned_epoch_lane(self.lane_index, self.epoch);
    }
}

pub(crate) fn release_contended_epoch_lane<A: AtomicU64Authority>(
    lane: &A,
    epoch: u64,
) -> Result<(), LaneAdmissionError> {
    release_epoch_lane(lane, epoch)
}

/// Reserves an idle lane for a closed-gate writer. Once every lane is
/// reserved, a reader that observed a stale open gate cannot publish itself
/// after the writer's drain scan.
pub(crate) fn reserve_epoch_lane_for_writer<A: AtomicU64Authority>(
    lane: &A,
) -> Result<bool, LaneAdmissionError> {
    match lane.compare_acqrel(0, WRITER_RESERVED_EPOCH_LANE) {
        Ok(_) | Err(WRITER_RESERVED_EPOCH_LANE) => Ok(true),
        Err(_) => Ok(false),
    }
}

pub(crate) fn release_writer_epoch_lane<A: AtomicU64Authority>(
    lane: &A,
) -> Result<(), LaneAdmissionError> {
    lane.compare_release(WRITER_RESERVED_EPOCH_LANE, 0)
        .map(|_| ())
        .map_err(|_| LaneAdmissionError::Occupied)
}

#[inline]
pub(crate) fn epoch_lane_is_active(value: u64) -> bool {
    value != 0 && value != WRITER_RESERVED_EPOCH_LANE
}

#[inline]
pub(crate) const fn lane_drain_wait_required(
    lanes_active: bool,
    observed_wake_generation: u64,
    current_wake_generation: u64,
    shutdown_requested: bool,
) -> bool {
    lanes_active && observed_wake_generation == current_wake_generation && !shutdown_requested
}

pub(crate) fn mark_notification_pending<A: AtomicBoolAuthority>(authority: &A) -> bool {
    authority.claim_acqrel()
}

pub(crate) fn advance_notification_generation<A: AtomicU64Authority>(
    generation: &A,
) -> Result<u64, ExpectedPublicationError> {
    loop {
        let current = generation.load_acquire();
        let next = current
            .checked_add(1)
            .ok_or(ExpectedPublicationError::Exhausted)?;
        match generation.compare_acqrel(current, next) {
            Ok(_) => return Ok(next),
            Err(_) => continue,
        }
    }
}

pub(crate) fn rearm_notification_after_clear<
    Pending: AtomicBoolAuthority,
    Generation: AtomicU64Authority,
>(
    pending: &Pending,
    generation: &Generation,
    observed_generation: u64,
    queue_nonempty_after_clear: impl FnOnce() -> bool,
) -> bool {
    pending.store_release(false);
    if !queue_nonempty_after_clear() && generation.load_acquire() == observed_generation {
        return false;
    }
    let _won_notification_ownership = pending.claim_acqrel();
    true
}

pub(crate) fn begin_stats_sealing<Lifecycle: AtomicU8Authority, Generation: AtomicU64Value>(
    lifecycle: &Lifecycle,
    generation_slot: &Generation,
    running: u8,
    sealing: u8,
    generation: u64,
) -> Result<(), u8> {
    lifecycle.compare_release(running, sealing)?;
    generation_slot.store_release(generation);
    Ok(())
}

pub(crate) fn finish_stats_sealing<Lifecycle: AtomicU8Authority, Generation: AtomicU64Value>(
    lifecycle: &Lifecycle,
    generation_slot: &Generation,
    sealing: u8,
    sealed: u8,
    generation: u64,
) -> Result<(), u8> {
    if generation_slot.load_acquire() != generation {
        return Err(lifecycle.load_acquire());
    }
    lifecycle.compare_release(sealing, sealed).map(|_| ())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StatsPublicationOrderError {
    SequenceExhausted,
    UnexpectedSequence,
    MarkerBeforeDelta,
}

pub(crate) fn accept_stats_delta(
    last_sequence: &mut u64,
    sequence: u64,
) -> Result<(), StatsPublicationOrderError> {
    let expected = last_sequence
        .checked_add(1)
        .ok_or(StatsPublicationOrderError::SequenceExhausted)?;
    if sequence != expected {
        return Err(StatsPublicationOrderError::UnexpectedSequence);
    }
    *last_sequence = sequence;
    Ok(())
}

pub(crate) fn accept_stats_flush_marker(
    last_sequence: u64,
    through_sequence: u64,
) -> Result<(), StatsPublicationOrderError> {
    if last_sequence != through_sequence {
        return Err(StatsPublicationOrderError::MarkerBeforeDelta);
    }
    Ok(())
}

pub(crate) fn publish_before_epoch_gate<Gate: AtomicU64Value>(
    gate: &Gate,
    open_epoch: u64,
    publish_grouped_state: impl FnOnce(),
) {
    publish_grouped_state();
    gate.store_release(open_epoch);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ActivityPublicationError {
    SequenceExhausted,
}

pub(crate) fn publish_activity_lane<A: AtomicU64Value>(
    publication_sequence: &A,
    published_epoch: &A,
    latest_tick: &A,
    flow_epoch: u64,
    observed_tick: u64,
) -> Result<(), ActivityPublicationError> {
    let current = publication_sequence.load_acquire();
    let odd = current
        .checked_add(1)
        .ok_or(ActivityPublicationError::SequenceExhausted)?;
    let even = odd
        .checked_add(1)
        .ok_or(ActivityPublicationError::SequenceExhausted)?;
    publication_sequence.store_release(odd);
    let previous_tick = if published_epoch.load_acquire() == flow_epoch {
        latest_tick.load_acquire()
    } else {
        0
    };
    latest_tick.store_release(previous_tick.max(observed_tick));
    published_epoch.store_release(flow_epoch);
    publication_sequence.store_release(even);
    Ok(())
}

pub(crate) fn read_activity_lane<A: AtomicU64Value>(
    publication_sequence: &A,
    published_epoch: &A,
    latest_tick: &A,
    expected_epoch: u64,
) -> Option<u64> {
    let before = publication_sequence.load_acquire();
    if before & 1 != 0 {
        return None;
    }
    let flow_epoch = published_epoch.load_acquire();
    let tick = latest_tick.load_acquire();
    let after = publication_sequence.load_acquire();
    (before == after && flow_epoch == expected_epoch).then_some(tick)
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum IdleTransitionAttempt<R> {
    NotDue,
    Cancelled,
    Authorized(R),
}

/// Backend operations whose order is owned by [`attempt_idle_transition`].
///
/// `reserve_and_drain` returns only after writer reservation, admission closure,
/// and reader drain. Implementations supply platform/runtime mechanics but may
/// not choose the transition ordering.
pub(crate) trait IdleTransitionBackend {
    type Reservation;
    type Error;

    fn tentative_timeout(&mut self) -> bool;
    fn reserve_and_drain(&mut self) -> Result<Self::Reservation, Self::Error>;
    fn revalidate_after_drain(
        &mut self,
        reservation: &Self::Reservation,
    ) -> Result<bool, Self::Error>;
}

/// Complete timeout-decision protocol used by production and Loom.
pub(crate) fn attempt_idle_transition<Backend: IdleTransitionBackend>(
    mut backend: Backend,
) -> Result<IdleTransitionAttempt<Backend::Reservation>, Backend::Error> {
    if !backend.tentative_timeout() {
        return Ok(IdleTransitionAttempt::NotDue);
    }
    let reservation = backend.reserve_and_drain()?;
    if backend.revalidate_after_drain(&reservation)? {
        Ok(IdleTransitionAttempt::Authorized(reservation))
    } else {
        drop(reservation);
        Ok(IdleTransitionAttempt::Cancelled)
    }
}

/// Backend for the one flow snapshot/visibility publication transaction.
pub(crate) trait FlowSnapshotPublicationBackend {
    type Error;

    fn install_snapshot(&mut self) -> Result<(), Self::Error>;
    fn publish_visibility(&mut self) -> Result<(), Self::Error>;
}

/// Consuming publication typestate. The backend owns an already closed and
/// drained topology reservation, so visibility cannot reopen before snapshot
/// installation succeeds.
pub(crate) struct FlowSnapshotPublicationCore<Backend> {
    backend: Backend,
}

pub(crate) struct InstalledFlowSnapshot<Backend> {
    backend: Backend,
}

impl<Backend: FlowSnapshotPublicationBackend> FlowSnapshotPublicationCore<Backend> {
    pub(crate) const fn new(backend: Backend) -> Self {
        Self { backend }
    }

    pub(crate) fn install_snapshot(
        mut self,
    ) -> Result<InstalledFlowSnapshot<Backend>, Backend::Error> {
        self.backend.install_snapshot()?;
        Ok(InstalledFlowSnapshot {
            backend: self.backend,
        })
    }
}

impl<Backend: FlowSnapshotPublicationBackend> InstalledFlowSnapshot<Backend> {
    pub(crate) fn publish_visibility(mut self) -> Result<(), Backend::Error> {
        self.backend.publish_visibility()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ObservationPublicationError {
    OwnershipLost,
    WidthMismatch,
}

pub(crate) fn publish_observation_words<A: AtomicObservationWord>(
    state: &A,
    slots: &[A],
    observed_tick: &A,
    polling_state: u64,
    observed_state: u64,
    words: &[u64],
    observed_tick_value: u64,
) -> Result<(), ObservationPublicationError> {
    if slots.len() != words.len() {
        return Err(ObservationPublicationError::WidthMismatch);
    }
    if state.load_acquire() != polling_state {
        return Err(ObservationPublicationError::OwnershipLost);
    }
    for (slot, value) in slots.iter().zip(words.iter().copied()) {
        slot.store_relaxed(value);
    }
    observed_tick.store_relaxed(observed_tick_value);
    state
        .compare_release(polling_state, observed_state)
        .map(|_| ())
        .map_err(|_| ObservationPublicationError::OwnershipLost)
}

/// Reads one complete observation publication. The state word is sampled on
/// both sides of the fixed binding so a reader never combines fields from two
/// worker publications.
pub(crate) fn read_observation_binding<A: AtomicObservationWord, const WORDS: usize>(
    state: &A,
    slots: &[A; WORDS],
    observed_tick: &A,
    phase_mask: u64,
    observed_phase: u64,
) -> Option<([u64; WORDS], u64)> {
    let before = state.load_acquire();
    if before & phase_mask != observed_phase {
        return None;
    }
    let binding = std::array::from_fn(|index| slots[index].load_relaxed());
    let tick = observed_tick.load_relaxed();
    let after = state.load_acquire();
    (before == after).then_some((binding, tick))
}

#[cfg(all(test, not(miri), not(target_env = "musl")))]
mod loom_semantic_tests;
#[cfg(all(test, not(miri), not(target_env = "musl")))]
mod loom_tests;
