use std::fmt;
use std::num::NonZeroU64;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

const GATE_CLOSED_BIT: u64 = 1_u64 << (u64::BITS - 1);
const GATE_EPOCH_MASK: u64 = !GATE_CLOSED_BIT;
const FLOW_TOPOLOGY_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);
#[cfg(test)]
pub(crate) const DEFAULT_FLOW_READER_LANES: usize = 16;
pub(crate) const FLOW_READER_LANE_BYTES: usize = size_of::<ReaderLane>();

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FlowReaderLane(usize);

impl FlowReaderLane {
    pub(crate) fn new(index: usize) -> Self {
        Self(index)
    }

    pub(crate) fn for_worker(worker_id: usize, mode: crate::cli::WorkerFlowMode) -> Self {
        match mode {
            crate::cli::WorkerFlowMode::SharedFlow => Self(worker_id),
            crate::cli::WorkerFlowMode::SingleFlow => Self(worker_id & 1),
        }
    }

    pub(crate) const fn index(self) -> usize {
        self.0
    }
}

#[repr(align(128))]
struct ReaderLane {
    active_epoch: crate::authority::AuthorityAtomic<crate::authority::tags::FlowRead, AtomicU64>,
}

impl ReaderLane {
    const fn new() -> Self {
        Self {
            active_epoch: crate::authority::AuthorityAtomic::new_u64(
                0,
                crate::authority::AtomicProtocolId::FlowGateSnapshot,
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum TransitionPhase {
    Reserved,
    GatesClosed,
    SocketTransitionsApplied,
    ManagerStatePrepared,
    SessionCommitted,
    Published,
    Poisoned,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FlowTopologyError {
    Busy,
    TimedOut,
    QueueFull,
    ReaderCountExhausted,
    EpochExhausted,
    TokenExhausted,
    OwnershipLost,
    ForeignReceipt,
    AlreadyCommitted,
    Shutdown,
    Poisoned,
}

impl fmt::Display for FlowTopologyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        crate::runtime_support::format_debug(self, formatter)
    }
}

impl std::error::Error for FlowTopologyError {}

impl FlowTopologyError {
    pub(crate) const fn class(self) -> crate::runtime_support::FailureClass {
        use crate::runtime_support::FailureClass;
        match self {
            Self::Busy | Self::TimedOut => FailureClass::RetryableContention,
            Self::QueueFull => FailureClass::OperationFailed,
            Self::Shutdown => FailureClass::Shutdown,
            Self::ReaderCountExhausted
            | Self::EpochExhausted
            | Self::TokenExhausted
            | Self::OwnershipLost
            | Self::ForeignReceipt
            | Self::AlreadyCommitted
            | Self::Poisoned => FailureClass::FatalInvariant,
        }
    }
}

pub(crate) struct FlowTopologyCoordinator {
    gate: crate::authority::AuthorityAtomic<crate::authority::tags::FlowWrite, AtomicU64>,
    reader_lanes: Box<[ReaderLane]>,
    wake_generation:
        crate::authority::AuthorityAtomic<crate::authority::tags::WakeGeneration, AtomicU64>,
    pending_writers:
        crate::authority::AuthorityAtomic<crate::authority::tags::FlowWrite, AtomicU64>,
    writer_queue: crate::net::sock_mgr::transaction_lock::ManagerTransaction<
        crate::authority::tags::FlowWrite,
    >,
    corrupted: crate::authority::AuthorityAtomic<crate::authority::tags::FlowWrite, AtomicBool>,
    wake: Arc<crate::runtime_support::WaitAuthorityWake>,
}

pub(crate) struct FlowTopologyReadLease<'a> {
    coordinator: &'a FlowTopologyCoordinator,
    transaction_epoch: u64,
    lane: FlowReaderLane,
    lane_guard: Option<crate::atomic_core::EpochLaneGuard<'a, FlowTopologyCoordinator>>,
    authority: crate::authority::AuthorityScope<crate::authority::tags::FlowRead>,
}

#[derive(Debug)]
pub(crate) enum ReleasedFlowOperationError<OperationError> {
    Operation(OperationError),
    Reacquire(FlowTopologyError),
}

pub(crate) struct FlowTopologyWriteReservation<'a> {
    coordinator: &'a FlowTopologyCoordinator,
    token: NonZeroU64,
    previous_epoch: u64,
    next_epoch: u64,
    phase: TransitionPhase,
    committed_flow_epochs: Option<(u64, u64)>,
    writer_reservation: Option<
        crate::net::sock_mgr::transaction_lock::ManagerTransactionGuard<
            'a,
            crate::authority::tags::FlowWrite,
        >,
    >,
    writer_announced: bool,
}

pub(crate) type SocketTransitionsAppliedTopology<'a> =
    super::topology_typestate::SocketTransitionsAppliedTopology<FlowTopologyWriteReservation<'a>>;
pub(crate) type PreparedTopology<'a> =
    super::topology_typestate::PreparedTopology<FlowTopologyWriteReservation<'a>>;
pub(crate) type SessionCommittedTopology<'a> =
    super::topology_typestate::SessionCommittedTopology<FlowTopologyWriteReservation<'a>>;

pub(crate) struct ResetReceipt {
    transaction_token: NonZeroU64,
    expected_flow_epoch: u64,
    resulting_flow_epoch: u64,
}

impl FlowTopologyCoordinator {
    pub(crate) fn with_reader_lanes(reader_lanes: usize) -> Self {
        let mut lanes = Vec::with_capacity(reader_lanes);
        lanes.resize_with(reader_lanes, ReaderLane::new);
        Self {
            gate: crate::authority::AuthorityAtomic::new_u64(
                0,
                crate::authority::AtomicProtocolId::FlowGateSnapshot,
            ),
            reader_lanes: lanes.into_boxed_slice(),
            wake_generation: crate::authority::AuthorityAtomic::new_u64(
                0,
                crate::authority::AtomicProtocolId::WakeCoalescing,
            ),
            pending_writers: crate::authority::AuthorityAtomic::new_u64(
                0,
                crate::authority::AtomicProtocolId::FlowGateSnapshot,
            ),
            writer_queue: crate::net::sock_mgr::transaction_lock::ManagerTransaction::new_tagged(
                0x464c_4f57,
            ),
            corrupted: crate::authority::AuthorityAtomic::new_bool(
                false,
                crate::authority::AtomicProtocolId::FlowGateSnapshot,
            ),
            wake: crate::runtime_support::WaitAuthorityWake::new(
                crate::authority::WaitId::FlowReadersDrain,
            ),
        }
    }

    #[track_caller]
    pub(crate) fn try_read_lane(
        &self,
        lane: FlowReaderLane,
    ) -> Result<FlowTopologyReadLease<'_>, FlowTopologyError> {
        self.try_read_lane_internal(lane, None)
    }

    #[track_caller]
    fn try_read_lane_expected(
        &self,
        lane: FlowReaderLane,
        expected_epoch: u64,
    ) -> Result<FlowTopologyReadLease<'_>, FlowTopologyError> {
        self.try_read_lane_internal(lane, Some(expected_epoch))
    }

    #[track_caller]
    fn try_read_lane_internal(
        &self,
        lane: FlowReaderLane,
        expected_epoch: Option<u64>,
    ) -> Result<FlowTopologyReadLease<'_>, FlowTopologyError> {
        if self.corrupted.load(Ordering::Acquire) {
            self.publish_corruption(FlowTopologyError::Poisoned);
            return Err(FlowTopologyError::Poisoned);
        }
        if crate::runtime_support::process_shutdown_requested() {
            return Err(FlowTopologyError::Shutdown);
        }
        if self.writer_is_pending() {
            return Err(FlowTopologyError::Busy);
        }
        let Some(reader_lane) = self.reader_lanes.get(lane.0) else {
            return Err(self.corrupt(FlowTopologyError::ReaderCountExhausted));
        };
        let admission = match expected_epoch {
            Some(expected) => crate::atomic_core::reacquire_expected_epoch_lane(
                &self.gate,
                &reader_lane.active_epoch,
                expected,
                GATE_CLOSED_BIT,
            )
            .map_err(|error| match error {
                crate::atomic_core::EpochRefreshError::Admission(error) => error,
                crate::atomic_core::EpochRefreshError::Changed { .. } => {
                    crate::atomic_core::LaneAdmissionError::Closed
                }
            }),
            None => crate::atomic_core::acquire_epoch_lane(
                &self.gate,
                &reader_lane.active_epoch,
                GATE_CLOSED_BIT,
            ),
        };
        let epoch = match admission {
            Ok(epoch) => epoch,
            Err(crate::atomic_core::LaneAdmissionError::Closed) => {
                return Err(FlowTopologyError::Busy);
            }
            Err(crate::atomic_core::LaneAdmissionError::Occupied) => {
                return Err(self.corrupt(FlowTopologyError::OwnershipLost));
            }
            Err(crate::atomic_core::LaneAdmissionError::EpochExhausted) => {
                return Err(self.corrupt(FlowTopologyError::EpochExhausted));
            }
        };
        if self.writer_is_pending() {
            self.release_reader(lane, epoch);
            return Err(FlowTopologyError::Busy);
        }
        Ok(FlowTopologyReadLease {
            coordinator: self,
            transaction_epoch: epoch,
            lane,
            lane_guard: Some(crate::atomic_core::EpochLaneGuard::new(self, lane.0, epoch)),
            authority: crate::authority::AuthorityScope::enter(
                crate::authority::AuthorityInstance {
                    id: crate::authority::AuthorityId::FlowRead,
                    flow: self as *const Self as usize as u64,
                    direction: (lane.0 & 1) as u8,
                    kind: 0,
                    session: 0,
                },
            )
            .unwrap_or_else(|error| {
                self.release_reader(lane, epoch);
                crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
                    "flow read authority order was violated: {error}"
                ))
            }),
        })
    }

    #[cfg(test)]
    pub(crate) fn reserve_until(
        &self,
        outer_deadline: Instant,
    ) -> Result<FlowTopologyWriteReservation<'_>, FlowTopologyError> {
        self.reserve_until_inner(outer_deadline, None)
    }

    pub(crate) fn reserve_until_with_runtime_wake(
        &self,
        outer_deadline: Instant,
        runtime: &super::FlowRuntimeState,
    ) -> Result<FlowTopologyWriteReservation<'_>, FlowTopologyError> {
        self.reserve_until_inner(outer_deadline, Some(runtime))
    }

    fn reserve_until_inner(
        &self,
        outer_deadline: Instant,
        runtime: Option<&super::FlowRuntimeState>,
    ) -> Result<FlowTopologyWriteReservation<'_>, FlowTopologyError> {
        if self.corrupted.load(Ordering::Acquire) {
            self.publish_corruption(FlowTopologyError::Poisoned);
            return Err(FlowTopologyError::Poisoned);
        }
        self.announce_writer()?;
        let writer_reservation = match self.writer_queue.reserve_until(outer_deadline) {
            Ok(reservation) => reservation,
            Err(error) => {
                self.withdraw_writer()?;
                return Err(self.map_reservation_error(error));
            }
        };
        let token = writer_reservation.ticket();
        let deadline = outer_deadline.min(Instant::now() + FLOW_TOPOLOGY_DRAIN_TIMEOUT);
        loop {
            match crate::atomic_core::close_epoch_gate(&self.gate, GATE_CLOSED_BIT) {
                Ok(closed) => {
                    if let Some(runtime) = runtime {
                        runtime.notify_worker_wakes();
                    }
                    let mut reservation = FlowTopologyWriteReservation {
                        coordinator: self,
                        token,
                        previous_epoch: closed.previous_epoch,
                        next_epoch: closed.next_epoch,
                        phase: TransitionPhase::Reserved,
                        committed_flow_epochs: None,
                        writer_reservation: Some(writer_reservation),
                        writer_announced: true,
                    };
                    reservation.phase = TransitionPhase::GatesClosed;
                    if self.wait_for_readers(deadline)? {
                        return Ok(reservation);
                    }
                    reservation.rollback_internal()?;
                    return Err(FlowTopologyError::TimedOut);
                }
                Err(crate::atomic_core::EpochGateTransitionError::EpochExhausted) => {
                    self.withdraw_writer()?;
                    return Err(self.corrupt(FlowTopologyError::EpochExhausted));
                }
                Err(
                    crate::atomic_core::EpochGateTransitionError::Closed
                    | crate::atomic_core::EpochGateTransitionError::Changed,
                ) => {}
            }
            if Instant::now() >= deadline {
                self.withdraw_writer()?;
                return Err(FlowTopologyError::TimedOut);
            }
            if crate::runtime_support::process_shutdown_requested() {
                self.withdraw_writer()?;
                return Err(FlowTopologyError::Shutdown);
            }
            self.wait_once(deadline);
        }
    }

    fn announce_writer(&self) -> Result<(), FlowTopologyError> {
        crate::atomic_core::announce_writer(&self.pending_writers)
            .map_err(|_| self.corrupt(FlowTopologyError::TokenExhausted))?;
        Ok(())
    }

    fn withdraw_writer(&self) -> Result<(), FlowTopologyError> {
        let last = crate::atomic_core::withdraw_writer(&self.pending_writers)
            .map_err(|_| self.corrupt(FlowTopologyError::OwnershipLost))?;
        if last {
            self.wake.notify_all();
        }
        Ok(())
    }

    #[inline]
    fn writer_is_pending(&self) -> bool {
        self.pending_writers.load(Ordering::Acquire) != 0
    }

    fn map_reservation_error(
        &self,
        error: crate::net::sock_mgr::transaction_lock::ReservationError,
    ) -> FlowTopologyError {
        use crate::net::sock_mgr::transaction_lock::ReservationError;
        match error {
            ReservationError::TimedOut => FlowTopologyError::TimedOut,
            ReservationError::QueueFull => FlowTopologyError::QueueFull,
            ReservationError::Shutdown => FlowTopologyError::Shutdown,
            ReservationError::TicketExhausted => self.corrupt(FlowTopologyError::TokenExhausted),
            ReservationError::OwnershipLost | ReservationError::CancellationCorrupted => {
                self.corrupt(FlowTopologyError::OwnershipLost)
            }
        }
    }

    #[cfg(test)]
    fn admission_closed_for_test(&self) -> bool {
        self.gate.load(Ordering::Acquire) & GATE_CLOSED_BIT != 0
    }

    fn wait_for_readers(&self, deadline: Instant) -> Result<bool, FlowTopologyError> {
        loop {
            if self.corrupted.load(Ordering::Acquire) {
                self.publish_corruption(FlowTopologyError::Poisoned);
                return Err(FlowTopologyError::Poisoned);
            }
            if crate::runtime_support::process_shutdown_requested() {
                return Err(FlowTopologyError::Shutdown);
            }
            if self.reserve_idle_reader_lanes()? {
                return Ok(true);
            }
            if Instant::now() >= deadline {
                return Ok(false);
            }
            let guard = self.wake.coordination_guard();
            let wake_generation = self.wake_generation.load(Ordering::Acquire);
            let lanes_active = self.reader_lanes.iter().any(|lane| {
                crate::atomic_core::epoch_lane_is_active(lane.active_epoch.load(Ordering::Acquire))
            });
            if crate::atomic_core::lane_drain_wait_required(
                lanes_active,
                wake_generation,
                self.wake_generation.load(Ordering::Acquire),
                crate::runtime_support::process_shutdown_requested(),
            ) {
                self.wake
                    .wait_guard_until(guard, deadline, Duration::from_millis(50));
            } else {
                drop(guard);
            }
        }
    }

    fn reserve_idle_reader_lanes(&self) -> Result<bool, FlowTopologyError> {
        let mut all_reserved = true;
        for lane in &self.reader_lanes {
            match crate::atomic_core::reserve_epoch_lane_for_writer(&lane.active_epoch) {
                Ok(true) => {}
                Ok(false) => all_reserved = false,
                Err(_) => return Err(self.corrupt(FlowTopologyError::OwnershipLost)),
            }
        }
        Ok(all_reserved)
    }

    fn release_reserved_reader_lanes(&self) -> Result<(), FlowTopologyError> {
        for lane in &self.reader_lanes {
            if lane.active_epoch.load(Ordering::Acquire)
                == crate::atomic_core::WRITER_RESERVED_EPOCH_LANE
            {
                crate::atomic_core::release_writer_epoch_lane(&lane.active_epoch)
                    .map_err(|_| self.corrupt(FlowTopologyError::OwnershipLost))?;
            }
        }
        Ok(())
    }

    fn wait_once(&self, deadline: Instant) {
        self.wake.wait_until(deadline, Duration::from_millis(50));
    }

    pub(crate) fn reader_lane_count(&self) -> usize {
        self.reader_lanes.len()
    }

    pub(crate) fn published_epoch(&self) -> u64 {
        self.gate.load(Ordering::Acquire) & GATE_EPOCH_MASK
    }
    fn release_reader(&self, lane: FlowReaderLane, epoch: u64) {
        let Some(reader_lane) = self.reader_lanes.get(lane.0) else {
            self.corrupt(FlowTopologyError::OwnershipLost);
            return;
        };
        match crate::atomic_core::release_epoch_lane(&reader_lane.active_epoch, epoch) {
            Ok(()) => {}
            Err(crate::atomic_core::LaneAdmissionError::EpochExhausted) => {
                self.corrupt(FlowTopologyError::EpochExhausted);
                return;
            }
            Err(
                crate::atomic_core::LaneAdmissionError::Closed
                | crate::atomic_core::LaneAdmissionError::Occupied,
            ) => {
                self.corrupt(FlowTopologyError::OwnershipLost);
                return;
            }
        }
        if self.writer_is_pending() {
            if self.increment_wake_generation().is_err() {
                self.corrupt(FlowTopologyError::EpochExhausted);
                return;
            }
            self.wake.notify_all_synchronized();
        }
    }

    fn increment_wake_generation(&self) -> Result<(), ()> {
        loop {
            let current = self.wake_generation.load(Ordering::Acquire);
            let next = current.checked_add(1).ok_or(())?;
            if self
                .wake_generation
                .compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Ok(());
            }
        }
    }

    fn corrupt(&self, error: FlowTopologyError) -> FlowTopologyError {
        self.corrupted.store(true, Ordering::Release);
        self.publish_corruption(error);
        error
    }

    fn publish_corruption(&self, error: FlowTopologyError) {
        self.wake.notify_all();
        crate::runtime_support::publish_process_fatal(format_args!(
            "flow-topology authority corrupted: {error}"
        ));
    }
}

impl crate::atomic_core::EpochLaneReleaseOwner for FlowTopologyCoordinator {
    fn release_owned_epoch_lane(&self, lane_index: usize, epoch: u64) {
        self.release_reader(FlowReaderLane::new(lane_index), epoch);
    }
}

impl<'a> FlowTopologyReadLease<'a> {
    pub(crate) fn transaction_epoch(&self) -> u64 {
        self.transaction_epoch
    }

    pub(crate) fn is_current(&self) -> bool {
        self.coordinator.gate.load(Ordering::Acquire) & GATE_EPOCH_MASK == self.transaction_epoch
    }

    /// Runs one cold operation with flow authority released and reacquires the
    /// identical publication epoch before returning. No detached token or
    /// separately callable reacquisition phase exists.
    pub(crate) fn run_released<Output, OperationError>(
        mut self,
        operation: impl FnOnce() -> Result<Output, OperationError>,
    ) -> Result<(Self, Output), ReleasedFlowOperationError<OperationError>> {
        let coordinator = self.coordinator;
        let transaction_epoch = self.transaction_epoch;
        let lane = self.lane;
        self.authority.release();
        drop(self.lane_guard.take());
        let output = operation().map_err(ReleasedFlowOperationError::Operation)?;
        let lease = coordinator
            .try_read_lane_expected(lane, transaction_epoch)
            .map_err(ReleasedFlowOperationError::Reacquire)?;
        Ok((lease, output))
    }
}

impl Drop for FlowTopologyReadLease<'_> {
    fn drop(&mut self) {
        self.authority.release();
        drop(self.lane_guard.take());
    }
}

impl<'a> FlowTopologyWriteReservation<'a> {
    pub(crate) const fn previous_epoch(&self) -> u64 {
        self.previous_epoch
    }

    pub(crate) const fn publication_epoch(&self) -> u64 {
        self.next_epoch
    }

    #[cfg(test)]
    pub(crate) fn phase(&self) -> TransitionPhase {
        self.phase
    }

    fn advance_to(&mut self, phase: TransitionPhase) -> Result<(), FlowTopologyError> {
        if self.phase == TransitionPhase::Poisoned || self.phase == TransitionPhase::Published {
            return Err(FlowTopologyError::AlreadyCommitted);
        }
        if (phase as u8) != (self.phase as u8).saturating_add(1) {
            self.phase = TransitionPhase::Poisoned;
            return Err(self.coordinator.corrupt(FlowTopologyError::OwnershipLost));
        }
        self.phase = phase;
        Ok(())
    }

    pub(crate) fn socket_transitions_applied(
        self,
    ) -> Result<SocketTransitionsAppliedTopology<'a>, FlowTopologyError> {
        super::topology_typestate::ReservedTopologyTransaction::new(self)
            .socket_transitions_applied()
    }

    #[cfg(test)]
    pub(crate) fn prepare_for_session_commit(
        self,
    ) -> Result<PreparedTopology<'a>, FlowTopologyError> {
        self.socket_transitions_applied()?.manager_state_prepared()
    }

    pub(crate) fn publish_manager_only(mut self) -> Result<(), FlowTopologyError> {
        if self.phase != TransitionPhase::ManagerStatePrepared {
            self.phase = TransitionPhase::Poisoned;
            return Err(self.coordinator.corrupt(FlowTopologyError::OwnershipLost));
        }
        self.reopen()?;
        self.phase = TransitionPhase::Published;
        Ok(())
    }

    pub(crate) fn cancel(mut self) -> Result<(), FlowTopologyError> {
        if self.phase >= TransitionPhase::SessionCommitted {
            self.phase = TransitionPhase::Poisoned;
            return Err(self
                .coordinator
                .corrupt(FlowTopologyError::AlreadyCommitted));
        }
        self.rollback_internal()
    }

    #[cfg(test)]
    pub(crate) fn rollback(self) -> Result<(), FlowTopologyError> {
        self.cancel()
    }

    fn rollback_internal(&mut self) -> Result<(), FlowTopologyError> {
        self.reopen()?;
        self.phase = TransitionPhase::Published;
        Ok(())
    }

    fn reopen(&mut self) -> Result<(), FlowTopologyError> {
        crate::atomic_core::reopen_epoch_gate(
            &self.coordinator.gate,
            crate::atomic_core::ClosedEpochGate {
                previous_epoch: self.previous_epoch,
                next_epoch: self.next_epoch,
            },
            GATE_CLOSED_BIT,
        )
        .map_err(|_| self.coordinator.corrupt(FlowTopologyError::OwnershipLost))?;
        self.coordinator.release_reserved_reader_lanes()?;
        let writer_reservation = self
            .writer_reservation
            .take()
            .ok_or_else(|| self.coordinator.corrupt(FlowTopologyError::OwnershipLost))?;
        writer_reservation
            .commit()
            .map_err(|error| self.coordinator.map_reservation_error(error))?;
        if self.writer_announced {
            self.coordinator.withdraw_writer()?;
            self.writer_announced = false;
        } else {
            return Err(self.coordinator.corrupt(FlowTopologyError::OwnershipLost));
        }
        self.coordinator.wake.notify_all();
        Ok(())
    }
}

impl super::topology_typestate::TopologyTransactionOwner for FlowTopologyWriteReservation<'_> {
    type Error = FlowTopologyError;
    type Receipt = ResetReceipt;

    fn apply_socket_transitions(&mut self) -> Result<(), Self::Error> {
        self.advance_to(TransitionPhase::SocketTransitionsApplied)
    }

    fn prepare_manager_state(&mut self) -> Result<(), Self::Error> {
        self.advance_to(TransitionPhase::ManagerStatePrepared)
    }

    fn commit_session_state(
        &mut self,
        expected_flow_epoch: u64,
        resulting_flow_epoch: u64,
    ) -> Result<Self::Receipt, Self::Error> {
        self.advance_to(TransitionPhase::SessionCommitted)?;
        self.committed_flow_epochs = Some((expected_flow_epoch, resulting_flow_epoch));
        Ok(ResetReceipt {
            transaction_token: self.token,
            expected_flow_epoch,
            resulting_flow_epoch,
        })
    }

    fn publish_manager_state(self) -> Result<(), Self::Error> {
        self.publish_manager_only()
    }

    fn publish_committed_state(mut self, receipt: Self::Receipt) -> Result<(), Self::Error> {
        if self.phase != TransitionPhase::SessionCommitted
            || receipt.transaction_token != self.token
            || self.committed_flow_epochs
                != Some((receipt.expected_flow_epoch, receipt.resulting_flow_epoch))
            || receipt.resulting_flow_epoch < receipt.expected_flow_epoch
        {
            self.phase = TransitionPhase::Poisoned;
            return Err(self.coordinator.corrupt(FlowTopologyError::ForeignReceipt));
        }
        self.reopen()?;
        self.phase = TransitionPhase::Published;
        Ok(())
    }
}

impl Drop for FlowTopologyWriteReservation<'_> {
    fn drop(&mut self) {
        if self.phase < TransitionPhase::SessionCommitted && self.rollback_internal().is_err() {
            self.coordinator.corrupted.store(true, Ordering::Release);
            crate::runtime_support::publish_process_fatal(format_args!(
                "flow-topology reservation lost ownership before its irreversible point"
            ));
        } else if self.phase >= TransitionPhase::SessionCommitted
            && self.phase != TransitionPhase::Published
        {
            self.phase = TransitionPhase::Poisoned;
            self.coordinator.corrupted.store(true, Ordering::Release);
            crate::runtime_support::publish_process_fatal(format_args!(
                "flow-topology transaction was abandoned after its irreversible session commit"
            ));
        }
    }
}

#[cfg(test)]
mod tests;
