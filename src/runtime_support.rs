use crossbeam_channel::TrySendError;
use std::any::Any;
use std::fmt::{self, Write as _};
use std::io;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
#[cfg(not(test))]
use std::thread;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::shutdown_publication::{
    ControlOutcomeRole, SHUTDOWN_FATAL_PUBLISHED, SHUTDOWN_FATAL_PUBLISHING, SHUTDOWN_GRACEFUL,
    SHUTDOWN_KIND_MASK, SHUTDOWN_RUNNING, SHUTDOWN_VALUE_SHIFT, ShutdownPublicationCore,
    ShutdownSupervisionTransaction, ThreadOutcomeCore, WorkerOutcomeRole,
    WorkerTerminationDecision, WorkerTerminationTransaction,
};

const RUNTIME_WAIT_FALLBACK: Duration = Duration::from_millis(50);
const MAX_SHUTDOWN_WAIT_AUTHORITIES: usize = 4_096;
pub(crate) const RUNTIME_SHUTDOWN_DEADLINE: Duration = Duration::from_secs(2);
pub(crate) const CLEAN_EXIT: u32 = 1;
pub(crate) const FATAL_EXIT: u32 = 2;
pub(crate) const SIGINT_EXIT: u32 = 3;
#[cfg(not(test))]
const INVARIANT_EXIT_STATUS: i32 = 1;

static ACTIVE_SHUTDOWN: crate::authority::AuthorityOnceLock<
    crate::authority::tags::RuntimeSupervisor,
    Weak<ShutdownController>,
> = crate::authority::AuthorityOnceLock::new();
static NEXT_SHUTDOWN_WAIT_AUTHORITY: crate::authority::AuthorityAtomic<
    crate::authority::tags::RuntimeSupervisor,
    AtomicUsize,
> = crate::authority::AuthorityAtomic::new_usize(
    0,
    crate::authority::AtomicProtocolId::IdentityGeneration,
);
static SHUTDOWN_WAIT_AUTHORITIES: [crate::authority::AuthorityOnceLock<
    crate::authority::tags::RuntimeSupervisor,
    Weak<WaitAuthorityWake>,
>; MAX_SHUTDOWN_WAIT_AUTHORITIES] =
    [const { crate::authority::AuthorityOnceLock::new() }; MAX_SHUTDOWN_WAIT_AUTHORITIES];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FailureClass {
    RetryableContention,
    Shutdown,
    PacketRejected,
    OperationFailed,
    FatalInvariant,
}

pub(crate) fn format_debug<T: std::fmt::Debug>(
    value: &T,
    formatter: &mut std::fmt::Formatter<'_>,
) -> std::fmt::Result {
    write!(formatter, "{value:?}")
}

impl FailureClass {
    #[inline]
    pub(crate) const fn is_fatal(self) -> bool {
        matches!(self, Self::FatalInvariant)
    }
}

impl From<crate::worker_support::RejectionReason> for FailureClass {
    fn from(_: crate::worker_support::RejectionReason) -> Self {
        Self::PacketRejected
    }
}

pub(crate) struct WaitAuthorityWake {
    coordination: crate::authority::AuthorityMutex<crate::authority::tags::WaitCoordination, ()>,
    changed: crate::authority::AuthorityCondvar<crate::authority::tags::WaitCoordination>,
}

impl WaitAuthorityWake {
    pub(crate) fn new(wait: crate::authority::WaitId) -> Arc<Self> {
        let index = NEXT_SHUTDOWN_WAIT_AUTHORITY
            .try_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1)
            })
            .unwrap_or_else(|_| {
                fatal_invariant_or_shutdown(format_args!(
                    "shutdown wait-authority registration counter exhausted"
                ))
            });
        let instance_id = u64::try_from(index)
            .ok()
            .and_then(|value| value.checked_add(1))
            .unwrap_or_else(|| {
                fatal_invariant_or_shutdown(format_args!(
                    "wait-coordination authority instance exhausted"
                ))
            });
        let slot = SHUTDOWN_WAIT_AUTHORITIES.get(index).unwrap_or_else(|| {
            fatal_invariant_or_shutdown(format_args!(
                "shutdown wait-authority registration capacity exhausted"
            ))
        });
        let wake = Self {
            coordination: crate::authority::AuthorityMutex::new(
                (),
                crate::authority::AuthorityInstance {
                    id: crate::authority::AuthorityId::WaitCoordination,
                    flow: instance_id,
                    direction: 0,
                    kind: 0,
                    session: 0,
                },
            ),
            changed: crate::authority::AuthorityCondvar::new(wait),
        };
        wake.coordination.prewarm().unwrap_or_else(|error| {
            fatal_invariant_or_shutdown(format_args!(
                "wait-coordination authority prewarm failed: {error}"
            ))
        });
        wake.changed.prewarm();
        let wake = Arc::new(wake);
        if slot.set(Arc::downgrade(&wake)).is_err() {
            fatal_invariant_or_shutdown(format_args!(
                "shutdown wait-authority registration slot was reused"
            ));
        }
        wake
    }

    pub(crate) fn coordination_guard(
        &self,
    ) -> crate::authority::AuthorityMutexGuard<'_, crate::authority::tags::WaitCoordination, ()>
    {
        self.coordination.lock().unwrap_or_else(|error| {
            fatal_invariant_or_shutdown(format_args!("wait-coordination authority failed: {error}"))
        })
    }

    fn wait_timeout(
        &self,
        guard: crate::authority::AuthorityMutexGuard<
            '_,
            crate::authority::tags::WaitCoordination,
            (),
        >,
        timeout: Duration,
    ) {
        if let Err(error) = self.changed.wait_until(
            guard,
            Instant::now().checked_add(timeout).unwrap_or_else(|| {
                fatal_invariant_or_shutdown(format_args!("wait-coordination deadline overflowed"))
            }),
        ) {
            fatal_invariant_or_shutdown(format_args!(
                "wait-coordination authority failed: {error}"
            ));
        }
    }

    pub(crate) fn wait_until(&self, deadline: Instant, fallback: Duration) {
        let guard = self.coordination_guard();
        self.wait_guard_until(guard, deadline, fallback);
    }

    pub(crate) fn wait_guard_until(
        &self,
        guard: crate::authority::AuthorityMutexGuard<
            '_,
            crate::authority::tags::WaitCoordination,
            (),
        >,
        deadline: Instant,
        fallback: Duration,
    ) {
        let remaining = match deadline.checked_duration_since(Instant::now()) {
            Some(remaining) => remaining,
            None => Duration::ZERO,
        };
        self.wait_timeout(guard, remaining.min(fallback));
    }

    pub(crate) fn notify_all(&self) {
        self.changed.notify_all();
    }

    pub(crate) fn notify_all_synchronized(&self) {
        let guard = self.coordination_guard();
        self.changed.notify_all();
        drop(guard);
    }

    #[cfg(test)]
    pub(crate) fn coordination_mutex_is_available(&self) -> bool {
        self.coordination.is_available_for_test()
    }
}

fn wake_registered_wait_authorities() {
    let registered = NEXT_SHUTDOWN_WAIT_AUTHORITY
        .load(Ordering::Acquire)
        .min(MAX_SHUTDOWN_WAIT_AUTHORITIES);
    for slot in SHUTDOWN_WAIT_AUTHORITIES.iter().take(registered) {
        if let Some(wake) = slot.get().and_then(Weak::upgrade) {
            wake.notify_all();
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RuntimeFailureClass {
    FatalInvariant,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct BoundedFailureMessage {
    bytes: [u8; 120],
    len: u16,
}

impl BoundedFailureMessage {
    pub(crate) const REPORTING_FAILED: Self = Self::from_static("panic reporting failed");

    pub(crate) const fn from_static(message: &'static str) -> Self {
        let bytes = message.as_bytes();
        let mut output = [0_u8; 120];
        let mut index = 0;
        while index < bytes.len() && index < output.len() {
            output[index] = bytes[index];
            index += 1;
        }
        Self {
            bytes: output,
            len: index as u16,
        }
    }

    pub(crate) fn new(arguments: fmt::Arguments<'_>) -> Self {
        let mut message = Self {
            bytes: [0; 120],
            len: 0,
        };
        if message.write_fmt(arguments).is_err() {
            return Self::REPORTING_FAILED;
        }
        message
    }

    pub(crate) fn as_str(&self) -> &str {
        let Some(bytes) = self.bytes.get(..usize::from(self.len)) else {
            return "invalid failure text";
        };
        match std::str::from_utf8(bytes) {
            Ok(message) => message,
            Err(_) => "invalid failure text",
        }
    }
}

impl fmt::Write for BoundedFailureMessage {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let available = self.bytes.len().saturating_sub(usize::from(self.len));
        let copy_len = available.min(value.len());
        let end = usize::from(self.len) + copy_len;
        if let Some(destination) = self.bytes.get_mut(usize::from(self.len)..end) {
            let Some(source) = value.as_bytes().get(..copy_len) else {
                return Err(fmt::Error);
            };
            destination.copy_from_slice(source);
            self.len = u16::try_from(end).map_err(|_| fmt::Error)?;
            Ok(())
        } else {
            Err(fmt::Error)
        }
    }
}

impl fmt::Debug for BoundedFailureMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("BoundedFailureMessage")
            .field(&self.as_str())
            .finish()
    }
}

impl fmt::Display for BoundedFailureMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RuntimeFailure {
    pub(crate) class: RuntimeFailureClass,
    pub(crate) message: BoundedFailureMessage,
}

impl RuntimeFailure {
    pub(crate) fn fatal(arguments: fmt::Arguments<'_>) -> Self {
        Self {
            class: RuntimeFailureClass::FatalInvariant,
            message: BoundedFailureMessage::new(arguments),
        }
    }
}

impl fmt::Display for RuntimeFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.class, self.message)
    }
}

impl std::error::Error for RuntimeFailure {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ThreadRole {
    ClientWorker,
    UpstreamWorker,
    Watchdog,
    Reresolver,
    StatsPrinter,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ThreadOutcome {
    Completed,
    Failed(RuntimeFailure),
    Panicked(BoundedFailureMessage),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SupervisorEvent {
    ThreadTerminal(usize),
    ShutdownChanged,
}

pub(crate) struct SupervisorEventReceiver(
    crate::authority::SingleConsumerBootstrap<
        crate::authority::AuthorityChannelReceiver<
            crate::authority::tags::RuntimeSupervisor,
            SupervisorEvent,
        >,
    >,
);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SecondaryFailure {
    slot: usize,
    outcome: ThreadOutcome,
}

type RuntimeShutdownAtomic =
    crate::authority::AuthorityAtomic<crate::authority::tags::RuntimeSupervisor, AtomicU64>;
type RuntimeOutcomeState =
    crate::authority::AuthorityAtomic<crate::authority::tags::RuntimeSupervisor, AtomicU8>;
type RuntimeOutcomeStore =
    crate::authority::AuthorityOnceLock<crate::authority::tags::RuntimeSupervisor, ThreadOutcome>;
type RuntimeControlOutcomeCore =
    ThreadOutcomeCore<RuntimeOutcomeState, RuntimeOutcomeStore, ThreadOutcome, ControlOutcomeRole>;
type RuntimeWorkerOutcomeCore =
    ThreadOutcomeCore<RuntimeOutcomeState, RuntimeOutcomeStore, ThreadOutcome, WorkerOutcomeRole>;
type RuntimeWorkerTermination<'core> =
    WorkerTerminationTransaction<'core, RuntimeOutcomeState, RuntimeOutcomeStore, ThreadOutcome>;

pub(crate) struct ShutdownSupervision<'shutdown> {
    transaction: ShutdownSupervisionTransaction<'shutdown, RuntimeShutdownAtomic>,
}

impl ShutdownSupervision<'_> {
    pub(crate) fn complete<Result>(self, completion: impl FnOnce() -> Result) -> (Result, i32) {
        let (result, final_state) = self.transaction.complete(completion);
        (result, decode_exit_status(final_state).unwrap_or(1))
    }
}

struct ControlOutcomeSlot {
    core: RuntimeControlOutcomeCore,
}

impl ControlOutcomeSlot {
    const fn new() -> Self {
        Self {
            core: ThreadOutcomeCore::new_control(
                crate::authority::AuthorityAtomic::new_u8(
                    0,
                    crate::authority::AtomicProtocolId::ThreadOutcome,
                ),
                crate::authority::AuthorityOnceLock::new(),
            ),
        }
    }

    fn load(&self) -> Option<ThreadOutcome> {
        self.core.load()
    }
}

struct WorkerOutcomeSlot {
    core: RuntimeWorkerOutcomeCore,
}

impl WorkerOutcomeSlot {
    const fn new() -> Self {
        Self {
            core: ThreadOutcomeCore::new_worker(
                crate::authority::AuthorityAtomic::new_u8(
                    0,
                    crate::authority::AtomicProtocolId::ThreadOutcome,
                ),
                crate::authority::AuthorityOnceLock::new(),
            ),
        }
    }

    fn load(&self) -> Option<ThreadOutcome> {
        self.core.load()
    }

    fn load_terminal(&self) -> Option<ThreadOutcome> {
        self.core.load_terminal()
    }
}

struct WorkerCleanupLease<'shutdown> {
    shutdown: &'shutdown ShutdownController,
    slot: usize,
    transaction: RuntimeWorkerTermination<'shutdown>,
}

impl WorkerCleanupLease<'_> {
    fn complete<Resource>(self, resource: &mut Resource, cleanup: impl FnOnce(&mut Resource)) {
        let shutdown = self.shutdown;
        let slot = self.slot;
        let (_, terminal_published) = self.transaction.complete(|| {
            if let Err(payload) = catch_unwind(AssertUnwindSafe(|| cleanup(resource))) {
                shutdown.request_panic(panic_report(payload.as_ref()));
            }
        });
        if terminal_published {
            shutdown.notify_thread_terminal(slot);
        } else {
            fatal_invariant_or_shutdown(format_args!(
                "worker terminal cleanup lost its consuming publication token"
            ));
        }
        shutdown.wait_authority.notify_all();
    }
}

pub(crate) struct ShutdownController {
    publication: ShutdownPublicationCore<RuntimeShutdownAtomic>,
    control_outcome: ControlOutcomeSlot,
    worker_outcomes: Box<[WorkerOutcomeSlot]>,
    event_sender: crate::authority::AuthorityChannelSender<
        crate::authority::tags::RuntimeSupervisor,
        SupervisorEvent,
    >,
    shutdown_event_pending:
        crate::authority::AuthorityAtomic<crate::authority::tags::RuntimeSupervisor, AtomicBool>,
    secondary_failures: crate::authority::AuthorityQueue<
        crate::authority::tags::RuntimeSupervisor,
        SecondaryFailure,
    >,
    secondary_failure_overflow:
        crate::authority::AuthorityAtomic<crate::authority::tags::DiagnosticCounter, AtomicU64>,
    wait_authority: Arc<WaitAuthorityWake>,
    audit_workers: crate::authority::WorkerAuditRegistry,
}

impl ShutdownController {
    pub(crate) fn bootstrap(
        thread_slots: usize,
    ) -> io::Result<(Arc<Self>, SupervisorEventReceiver)> {
        let event_capacity = thread_slots
            .checked_add(1)
            .ok_or_else(|| io::Error::other("supervisor event capacity exceeds usize"))?;
        Self::bootstrap_with_event_capacity(thread_slots, event_capacity)
    }

    #[cfg(test)]
    pub(crate) fn new(thread_slots: usize) -> io::Result<Arc<Self>> {
        Self::bootstrap(thread_slots).map(|(shutdown, _events)| shutdown)
    }

    #[cfg(test)]
    fn bootstrap_with_event_capacity_for_test(
        thread_slots: usize,
        event_capacity: usize,
    ) -> io::Result<(Arc<Self>, SupervisorEventReceiver)> {
        Self::bootstrap_with_event_capacity(thread_slots, event_capacity)
    }

    fn bootstrap_with_event_capacity(
        thread_slots: usize,
        event_capacity: usize,
    ) -> io::Result<(Arc<Self>, SupervisorEventReceiver)> {
        if thread_slots == 0 {
            return Err(io::Error::other(
                "shutdown supervision requires a main outcome slot",
            ));
        }
        if event_capacity == 0 {
            return Err(io::Error::other(
                "shutdown supervision requires a nonzero event capacity",
            ));
        }
        let secondary_capacity = thread_slots
            .checked_mul(2)
            .ok_or_else(|| io::Error::other("secondary failure capacity exceeds usize"))?;
        let (event_sender, event_receiver) = crate::authority::bounded_authority_channel(
            event_capacity,
            crate::authority::AuthorityInstance::singleton(
                crate::authority::AuthorityId::RuntimeSupervisor,
            ),
            crate::authority::OperationId::SupervisorHintSend,
            crate::authority::OperationId::ChannelReceive,
        );
        let worker_slots = thread_slots
            .checked_sub(1)
            .ok_or_else(|| io::Error::other("shutdown supervision requires a main outcome slot"))?;
        let mut worker_outcomes = Vec::new();
        worker_outcomes
            .try_reserve_exact(worker_slots)
            .map_err(|_| io::Error::other("could not allocate supervised thread outcomes"))?;
        worker_outcomes.resize_with(worker_slots, WorkerOutcomeSlot::new);
        let shutdown = Arc::new(Self {
            publication: ShutdownPublicationCore::new(crate::authority::AuthorityAtomic::new_u64(
                SHUTDOWN_RUNNING,
                crate::authority::AtomicProtocolId::ShutdownPublication,
            )),
            control_outcome: ControlOutcomeSlot::new(),
            worker_outcomes: worker_outcomes.into_boxed_slice(),
            event_sender,
            shutdown_event_pending: crate::authority::AuthorityAtomic::new_bool(
                false,
                crate::authority::AtomicProtocolId::WakeCoalescing,
            ),
            secondary_failures: crate::authority::AuthorityQueue::new(
                secondary_capacity,
                crate::authority::AuthorityInstance::singleton(
                    crate::authority::AuthorityId::RuntimeSupervisor,
                ),
            ),
            secondary_failure_overflow: crate::authority::AuthorityAtomic::new_u64(
                0,
                crate::authority::AtomicProtocolId::DiagnosticCounter,
            ),
            wait_authority: WaitAuthorityWake::new(crate::authority::WaitId::SupervisorTerminal),
            audit_workers: crate::authority::WorkerAuditRegistry::new(thread_slots)?,
        });
        Ok((
            shutdown,
            SupervisorEventReceiver(crate::authority::SingleConsumerBootstrap::new(
                event_receiver,
            )),
        ))
    }

    #[cfg(any(test, feature = "authority-audit"))]
    pub(crate) fn audit_worker_records(
        &self,
    ) -> Result<Vec<crate::authority::AuditThreadRecord>, &'static str> {
        self.audit_workers.records()
    }

    #[inline]
    pub(crate) fn is_requested(&self) -> bool {
        self.publication.is_requested()
    }

    pub(crate) fn request_graceful(&self, status: i32) {
        let encoded = encode_shutdown(SHUTDOWN_GRACEFUL, normalize_exit_status(status));
        if !self.publication.request_graceful(encoded) {
            // A concurrent graceful or fatal publication already has authority.
        }
        self.notify_shutdown_changed();
    }

    pub(crate) fn request_fatal(&self, failure: RuntimeFailure) {
        let owner = 0;
        let outcome = ThreadOutcome::Failed(failure);
        let publication = self.publish_fatal(outcome);
        if !publication.cause_installed || !publication.primary_won {
            self.record_secondary_failure(owner, outcome);
        }
    }

    pub(crate) fn request_current_fatal(&self, failure: RuntimeFailure) {
        self.request_fatal(failure);
    }

    pub(crate) fn store(&self, publication: u32, _ordering: Ordering) {
        match publication {
            CLEAN_EXIT => self.request_graceful(0),
            SIGINT_EXIT => self.request_graceful(130),
            FATAL_EXIT => self.request_current_fatal(RuntimeFailure::fatal(format_args!(
                "worker requested fatal shutdown"
            ))),
            _ => self.request_current_fatal(RuntimeFailure::fatal(format_args!(
                "invalid shutdown publication {publication}"
            ))),
        }
    }

    fn request_panic(&self, report: BoundedFailureMessage) {
        let owner = 0;
        let outcome = ThreadOutcome::Panicked(report);
        let publication = self.publish_fatal(outcome);
        if !publication.cause_installed || !publication.primary_won {
            self.record_secondary_failure(owner, outcome);
        }
    }

    fn publish_fatal(
        &self,
        outcome: ThreadOutcome,
    ) -> crate::shutdown_publication::FatalPublication {
        let publication = self.publication.publish_fatal(
            &self.control_outcome.core,
            outcome,
            1_u64 << SHUTDOWN_VALUE_SHIFT,
        );
        self.notify_shutdown_changed();
        publication
    }

    fn begin_worker_termination(
        &self,
        slot: usize,
        role: ThreadRole,
        outcome: ThreadOutcome,
    ) -> WorkerCleanupLease<'_> {
        let owner = self.valid_worker_owner(slot);
        let encoded_owner = u64::try_from(owner)
            .ok()
            .and_then(|owner| owner.checked_add(1))
            .unwrap_or(1)
            << SHUTDOWN_VALUE_SHIFT;
        let destination = self.worker_outcome(owner).unwrap_or_else(|| {
            fatal_invariant_or_shutdown(format_args!(
                "worker termination selected an unavailable outcome slot"
            ))
        });
        let run_failure = (!matches!(outcome, ThreadOutcome::Completed)).then_some(outcome);
        let publication = self
            .publication
            .begin_worker_termination(
                &destination.core,
                &crate::authority::emergency_failure_source(),
                WorkerTerminationDecision::new(
                    run_failure,
                    ThreadOutcome::Completed,
                    ThreadOutcome::Failed(RuntimeFailure::fatal(format_args!(
                        "{role:?} exited before shutdown"
                    ))),
                    |emergency_code| {
                        ThreadOutcome::Failed(RuntimeFailure::fatal(format_args!(
                            "{role:?} stopped after {}",
                            crate::authority::emergency_failure_report(emergency_code)
                        )))
                    },
                    encoded_owner,
                ),
            )
            .unwrap_or_else(|error| {
                fatal_invariant_or_shutdown(format_args!(
                    "{role:?} terminal transaction lost ownership: {error:?}"
                ))
            });
        if let Some(fatal) = publication.fatal() {
            if !fatal.primary_won {
                self.record_secondary_failure(owner, publication.outcome());
            }
            self.notify_shutdown_changed();
        }
        WorkerCleanupLease {
            shutdown: self,
            slot: owner,
            transaction: publication,
        }
    }

    fn notify_shutdown_changed(&self) {
        self.wait_authority.notify_all();
        wake_registered_wait_authorities();
        if self
            .shutdown_event_pending
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            match self.event_sender.try_send(SupervisorEvent::ShutdownChanged) {
                Ok(()) | Err(TrySendError::Full(_)) => {}
                Err(TrySendError::Disconnected(_)) => {
                    self.shutdown_event_pending.store(false, Ordering::Release);
                }
            }
        }
    }

    fn notify_thread_terminal(&self, slot: usize) {
        match self
            .event_sender
            .try_send(SupervisorEvent::ThreadTerminal(slot))
        {
            Ok(()) | Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {}
        }
    }

    fn record_secondary_failure(&self, slot: usize, outcome: ThreadOutcome) {
        if self
            .secondary_failures
            .push(SecondaryFailure { slot, outcome })
            .is_err()
        {
            self.increment_secondary_failure_overflow();
        }
    }

    fn increment_secondary_failure_overflow(&self) {
        match self.secondary_failure_overflow.try_update(
            Ordering::Release,
            Ordering::Acquire,
            |count| count.checked_add(1),
        ) {
            Ok(_) => {}
            Err(_) => {
                // The counter is already at its exact representable maximum.
            }
        }
    }

    fn valid_worker_owner(&self, requested: usize) -> usize {
        if self.worker_outcome(requested).is_some() {
            return requested;
        }
        fatal_invariant_or_shutdown(format_args!(
            "worker termination selected an unavailable outcome slot"
        ))
    }

    fn worker_outcome(&self, slot: usize) -> Option<&WorkerOutcomeSlot> {
        slot.checked_sub(1)
            .and_then(|index| self.worker_outcomes.get(index))
    }

    fn has_worker_slot(&self, slot: usize) -> bool {
        self.worker_outcome(slot).is_some()
    }

    #[cfg(test)]
    pub(crate) fn outcome(&self, slot: usize) -> Option<ThreadOutcome> {
        if slot == 0 {
            self.control_outcome.load()
        } else {
            self.worker_outcome(slot).and_then(WorkerOutcomeSlot::load)
        }
    }

    fn terminal_outcome(&self, slot: usize) -> Option<ThreadOutcome> {
        self.worker_outcome(slot)
            .and_then(WorkerOutcomeSlot::load_terminal)
    }

    #[cfg(test)]
    fn secondary_failure_count(&self) -> usize {
        self.secondary_failures.len()
    }

    #[cfg(test)]
    fn secondary_failure_overflow(&self) -> u64 {
        self.secondary_failure_overflow.load(Ordering::Acquire)
    }

    pub(crate) fn begin_supervision(&self) -> Option<ShutdownSupervision<'_>> {
        self.publication
            .begin_supervision()
            .map(|transaction| ShutdownSupervision { transaction })
    }

    #[cfg(test)]
    pub(crate) fn exit_status(&self) -> Option<i32> {
        decode_exit_status(self.publication.state_snapshot())
    }

    pub(crate) fn primary_fatal_outcome(&self) -> Option<ThreadOutcome> {
        let owner = self.publication.fatal_owner_value()?.checked_sub(1)?;
        let slot = usize::try_from(owner).ok()?;
        if slot == 0 {
            self.control_outcome.load()
        } else {
            self.worker_outcome(slot).and_then(WorkerOutcomeSlot::load)
        }
    }

    pub(crate) fn wait_for_change(&self, deadline: Instant) {
        self.wait_authority
            .wait_until(deadline, RUNTIME_WAIT_FALLBACK);
    }
}

const fn decode_exit_status(state: u64) -> Option<i32> {
    match state & SHUTDOWN_KIND_MASK {
        SHUTDOWN_RUNNING => None,
        SHUTDOWN_GRACEFUL => Some(decode_shutdown_value(state) as i32),
        SHUTDOWN_FATAL_PUBLISHING | SHUTDOWN_FATAL_PUBLISHED => Some(1),
        _ => Some(1),
    }
}

pub(crate) fn register_shutdown_controller(shutdown: &Arc<ShutdownController>) -> io::Result<()> {
    ACTIVE_SHUTDOWN
        .set(Arc::downgrade(shutdown))
        .map_err(|_| io::Error::other("runtime shutdown controller was registered twice"))
}

pub(crate) fn publish_process_fatal(arguments: fmt::Arguments<'_>) {
    let _operation = crate::authority::AuditedOperationScope::enter_fatal_publication();
    if let Some(shutdown) = ACTIVE_SHUTDOWN.get().and_then(Weak::upgrade) {
        shutdown.request_current_fatal(RuntimeFailure::fatal(arguments));
    }
}

#[inline]
pub(crate) fn process_shutdown_requested() -> bool {
    crate::authority::emergency_failure_code() != 0
        || ACTIVE_SHUTDOWN
            .get()
            .and_then(Weak::upgrade)
            .is_some_and(|shutdown| shutdown.is_requested())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct InvariantError {
    authority: &'static str,
    cause: crate::authority::AuthorityError,
}

impl fmt::Display for InvariantError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} authority acquisition failed: {}",
            self.authority, self.cause
        )
    }
}

impl std::error::Error for InvariantError {}

/// Locks registered protocol authority without recovering poisoned state.
pub(crate) fn lock_authority<'a, Tag, T>(
    mutex: &'a crate::authority::AuthorityMutex<Tag, T>,
    authority: &'static str,
) -> Result<crate::authority::AuthorityMutexGuard<'a, Tag, T>, InvariantError>
where
    Tag: crate::authority::AuthoritySpec,
{
    mutex.lock().map_err(|lock_error| {
        let error = InvariantError {
            authority,
            cause: lock_error,
        };
        publish_process_fatal(format_args!("{error}"));
        error
    })
}

pub(crate) fn lock_authority_or_shutdown<'a, Tag, T>(
    mutex: &'a crate::authority::AuthorityMutex<Tag, T>,
    authority: &'static str,
) -> crate::authority::AuthorityMutexGuard<'a, Tag, T>
where
    Tag: crate::authority::AuthoritySpec,
{
    match lock_authority(mutex, authority) {
        Ok(guard) => guard,
        Err(error) => stop_poisoned_thread(error),
    }
}

#[cfg(not(test))]
pub(crate) fn fatal_invariant_or_shutdown(arguments: fmt::Arguments<'_>) -> ! {
    publish_process_fatal(arguments);
    stop_failing_thread()
}

#[cfg(test)]
pub(crate) fn fatal_invariant_or_shutdown(arguments: fmt::Arguments<'_>) -> ! {
    publish_process_fatal(arguments);
    panic!("{arguments}")
}

#[cfg(test)]
fn stop_poisoned_thread(error: InvariantError) -> ! {
    panic!("{error}");
}

#[cfg(not(test))]
fn stop_poisoned_thread(_error: InvariantError) -> ! {
    stop_failing_thread()
}

#[cfg(not(test))]
fn stop_failing_thread() -> ! {
    if ACTIVE_SHUTDOWN.get().and_then(Weak::upgrade).is_none() {
        immediate_exit(INVARIANT_EXIT_STATUS);
    }
    loop {
        // The supervisor owns the two-second terminal deadline. Parking
        // avoids CPU consumption and guarantees no poisoned mutation.
        thread::park_timeout(RUNTIME_WAIT_FALLBACK);
    }
}

struct SupervisedThread {
    slot: usize,
    role: ThreadRole,
    handle: Option<JoinHandle<()>>,
}

pub(crate) struct ThreadSupervisor {
    shutdown: Arc<ShutdownController>,
    events: crate::authority::AuthorityChannelReceiver<
        crate::authority::tags::RuntimeSupervisor,
        SupervisorEvent,
    >,
    threads: Vec<SupervisedThread>,
    next_slot: usize,
}

mod supervisor;

pub(crate) fn immediate_exit(status: i32) -> ! {
    let _operation =
        crate::authority::audited_operation(crate::authority::OperationId::ProcessImmediateExit);
    #[cfg(unix)]
    {
        // SAFETY: the bounded supervisor deadline has expired. `_exit` is the
        // reviewed process-fatal path that deliberately skips destructors and
        // potentially blocking stdio cleanup.
        unsafe { libc::_exit(status) }
    }
    #[cfg(windows)]
    {
        let status = u32::try_from(status).unwrap_or(1);
        // SAFETY: this is the Windows process-fatal equivalent of `_exit`.
        unsafe { windows_sys::Win32::System::Threading::ExitProcess(status) }
    }
    #[cfg(not(any(unix, windows)))]
    {
        std::process::exit(status)
    }
}

fn panic_report(payload: &(dyn Any + Send)) -> BoundedFailureMessage {
    let rendered = catch_unwind(AssertUnwindSafe(|| {
        if let Some(message) = payload.downcast_ref::<&str>() {
            BoundedFailureMessage::new(format_args!("{message}"))
        } else if let Some(message) = payload.downcast_ref::<String>() {
            BoundedFailureMessage::new(format_args!("{message}"))
        } else {
            BoundedFailureMessage::from_static("thread panicked with a non-string payload")
        }
    }));
    match rendered {
        Ok(report) => report,
        Err(_) => BoundedFailureMessage::REPORTING_FAILED,
    }
}

const fn encode_shutdown(kind: u64, value: u64) -> u64 {
    (value << SHUTDOWN_VALUE_SHIFT) | kind
}

const fn decode_shutdown_value(state: u64) -> u64 {
    state >> SHUTDOWN_VALUE_SHIFT
}

const fn normalize_exit_status(status: i32) -> u64 {
    if status < 0 {
        1
    } else if status > 255 {
        255
    } else {
        status as u64
    }
}

#[cfg(test)]
mod tests;
