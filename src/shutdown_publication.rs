use crate::atomic_core::{AtomicU8Authority, AtomicU64Authority, AtomicU64Value};

pub(crate) const SHUTDOWN_KIND_MASK: u64 = 0b11;
pub(crate) const SHUTDOWN_RUNNING: u64 = 0;
pub(crate) const SHUTDOWN_GRACEFUL: u64 = 1;
pub(crate) const SHUTDOWN_FATAL_PUBLISHING: u64 = 2;
pub(crate) const SHUTDOWN_FATAL_PUBLISHED: u64 = 3;
pub(crate) const SHUTDOWN_VALUE_SHIFT: u32 = 2;

const OUTCOME_EMPTY: u8 = 0;
const OUTCOME_CAUSE_READY_RUNNING_CLEANUP: u8 = 1;
const OUTCOME_CLEANUP_CLAIMED: u8 = 2;
const OUTCOME_TERMINAL_READY: u8 = 3;

#[must_use = "supervision must be completed through this origin-bound transaction"]
pub(crate) struct ShutdownSupervisionTransaction<'core, State> {
    core: &'core ShutdownPublicationCore<State>,
    observed_state: u64,
}

pub(crate) trait EmergencyFailureSource {
    fn load_acquire(&self) -> u64;
}

pub(crate) enum ControlOutcomeRole {}
pub(crate) enum WorkerOutcomeRole {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WorkerTerminationError {
    OutcomeAlreadyPublished,
    CleanupOwnershipLost,
}

#[must_use = "worker cleanup must be completed through this origin-bound transaction"]
pub(crate) struct WorkerTerminationTransaction<'core, State, Store, Outcome> {
    core: &'core ThreadOutcomeCore<State, Store, Outcome, WorkerOutcomeRole>,
    outcome: Outcome,
    fatal: Option<FatalPublication>,
}

pub(crate) struct WorkerTerminationDecision<Outcome, BuildEmergency> {
    run_failure: Option<Outcome>,
    completed: Outcome,
    unexpected: Outcome,
    build_emergency: BuildEmergency,
    encoded_owner: u64,
}

impl<Outcome, BuildEmergency> WorkerTerminationDecision<Outcome, BuildEmergency> {
    pub(crate) const fn new(
        run_failure: Option<Outcome>,
        completed: Outcome,
        unexpected: Outcome,
        build_emergency: BuildEmergency,
        encoded_owner: u64,
    ) -> Self {
        Self {
            run_failure,
            completed,
            unexpected,
            build_emergency,
            encoded_owner,
        }
    }
}

impl<State, Store, Outcome> WorkerTerminationTransaction<'_, State, Store, Outcome>
where
    State: AtomicU8Authority,
    Store: OutcomeStore<Outcome>,
    Outcome: Copy,
{
    pub(crate) const fn outcome(&self) -> Outcome {
        self.outcome
    }

    pub(crate) const fn fatal(&self) -> Option<FatalPublication> {
        self.fatal
    }

    /// Runs cleanup before publishing terminal readiness. Consuming `self`
    /// prevents duplicate completion or completion against a foreign slot.
    pub(crate) fn complete<Result>(self, cleanup: impl FnOnce() -> Result) -> (Result, bool) {
        let result = cleanup();
        let terminal_published = self
            .core
            .state
            .compare_release(OUTCOME_CLEANUP_CLAIMED, OUTCOME_TERMINAL_READY)
            .is_ok();
        (result, terminal_published)
    }
}

pub(crate) trait OutcomeStore<Outcome: Copy> {
    fn install(&self, outcome: Outcome) -> Result<(), Outcome>;
    fn load(&self) -> Option<Outcome>;
}

impl<Tag, Outcome> OutcomeStore<Outcome> for crate::authority::AuthorityOnceLock<Tag, Outcome>
where
    Tag: crate::authority::AuthoritySpec,
    Outcome: Copy,
{
    fn install(&self, outcome: Outcome) -> Result<(), Outcome> {
        self.set(outcome)
    }

    fn load(&self) -> Option<Outcome> {
        self.get().copied()
    }
}

pub(crate) struct ThreadOutcomeCore<State, Store, Outcome, Role> {
    state: State,
    outcome: Store,
    _outcome: std::marker::PhantomData<fn(Outcome, Role)>,
}

impl<State, Store, Outcome, Role> ThreadOutcomeCore<State, Store, Outcome, Role>
where
    State: AtomicU8Authority,
    Store: OutcomeStore<Outcome>,
    Outcome: Copy,
{
    const fn new(state: State, outcome: Store) -> Self {
        Self {
            state,
            outcome,
            _outcome: std::marker::PhantomData,
        }
    }

    pub(crate) fn load(&self) -> Option<Outcome> {
        (self.state.load_acquire() != OUTCOME_EMPTY)
            .then(|| self.outcome.load())
            .flatten()
    }

    pub(crate) fn load_terminal(&self) -> Option<Outcome> {
        (self.state.load_acquire() == OUTCOME_TERMINAL_READY)
            .then(|| self.outcome.load())
            .flatten()
    }
}

impl<State, Store, Outcome> ThreadOutcomeCore<State, Store, Outcome, ControlOutcomeRole>
where
    State: AtomicU8Authority,
    Store: OutcomeStore<Outcome>,
    Outcome: Copy,
{
    pub(crate) const fn new_control(state: State, outcome: Store) -> Self {
        Self::new(state, outcome)
    }
}

impl<State, Store, Outcome> ThreadOutcomeCore<State, Store, Outcome, WorkerOutcomeRole>
where
    State: AtomicU8Authority,
    Store: OutcomeStore<Outcome>,
    Outcome: Copy,
{
    pub(crate) const fn new_worker(state: State, outcome: Store) -> Self {
        Self::new(state, outcome)
    }
}

pub(crate) struct ShutdownPublicationCore<State> {
    state: State,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FatalPublication {
    pub(crate) cause_installed: bool,
    pub(crate) primary_won: bool,
}

impl<State> ShutdownPublicationCore<State>
where
    State: AtomicU64Authority + AtomicU64Value,
{
    pub(crate) const fn new(state: State) -> Self {
        Self { state }
    }

    fn raw_state(&self) -> u64 {
        AtomicU64Authority::load_acquire(&self.state)
    }

    pub(crate) fn is_requested(&self) -> bool {
        self.raw_state() & SHUTDOWN_KIND_MASK != SHUTDOWN_RUNNING
    }

    #[cfg(test)]
    pub(crate) fn state_snapshot(&self) -> u64 {
        self.raw_state()
    }

    pub(crate) fn fatal_owner_value(&self) -> Option<u64> {
        let state = self.raw_state();
        matches!(
            state & SHUTDOWN_KIND_MASK,
            SHUTDOWN_FATAL_PUBLISHING | SHUTDOWN_FATAL_PUBLISHED
        )
        .then_some(state >> SHUTDOWN_VALUE_SHIFT)
    }

    pub(crate) fn request_graceful(&self, encoded: u64) -> bool {
        self.state.compare_acqrel(SHUTDOWN_RUNNING, encoded).is_ok()
    }

    pub(crate) fn begin_supervision(&self) -> Option<ShutdownSupervisionTransaction<'_, State>> {
        let observed_state = self.raw_state();
        (observed_state & SHUTDOWN_KIND_MASK != SHUTDOWN_RUNNING).then_some(
            ShutdownSupervisionTransaction {
                core: self,
                observed_state,
            },
        )
    }

    pub(crate) fn publish_fatal<SlotState, Store, Outcome>(
        &self,
        slot: &ThreadOutcomeCore<SlotState, Store, Outcome, ControlOutcomeRole>,
        outcome: Outcome,
        encoded_owner: u64,
    ) -> FatalPublication
    where
        SlotState: AtomicU8Authority,
        Store: OutcomeStore<Outcome>,
        Outcome: Copy,
    {
        self.publish_fatal_from_slot(slot, outcome, encoded_owner)
    }

    fn publish_fatal_from_slot<SlotState, Store, Outcome, Role>(
        &self,
        slot: &ThreadOutcomeCore<SlotState, Store, Outcome, Role>,
        outcome: Outcome,
        encoded_owner: u64,
    ) -> FatalPublication
    where
        SlotState: AtomicU8Authority,
        Store: OutcomeStore<Outcome>,
        Outcome: Copy,
    {
        let cause_installed = slot.outcome.install(outcome).is_ok();
        if cause_installed {
            slot.state
                .store_release(OUTCOME_CAUSE_READY_RUNNING_CLEANUP);
        }
        let primary_won = cause_installed && self.publish_fatal_owner(encoded_owner);
        FatalPublication {
            cause_installed,
            primary_won,
        }
    }

    /// Selects and publishes one worker terminal cause, then returns the only
    /// token that may make the outcome terminal after resource cleanup.
    ///
    /// The emergency latch is read before any generic completion cause can be
    /// installed. A second acquire read closes the completed-worker decision
    /// window after the shutdown-state observation. Authority failures
    /// published by the returning worker therefore cannot be replaced by the
    /// less precise "exited before shutdown" cause.
    pub(crate) fn begin_worker_termination<
        'slot,
        SlotState,
        Store,
        Outcome,
        Emergency,
        BuildEmergency,
    >(
        &self,
        slot: &'slot ThreadOutcomeCore<SlotState, Store, Outcome, WorkerOutcomeRole>,
        emergency: &Emergency,
        decision: WorkerTerminationDecision<Outcome, BuildEmergency>,
    ) -> Result<
        WorkerTerminationTransaction<'slot, SlotState, Store, Outcome>,
        WorkerTerminationError,
    >
    where
        SlotState: AtomicU8Authority,
        Store: OutcomeStore<Outcome>,
        Outcome: Copy,
        Emergency: EmergencyFailureSource,
        BuildEmergency: FnOnce(u64) -> Outcome,
    {
        let WorkerTerminationDecision {
            run_failure,
            completed,
            unexpected,
            build_emergency,
            encoded_owner,
        } = decision;
        let first_emergency = emergency.load_acquire();
        let shutdown_state = self.raw_state();
        let final_emergency = if first_emergency == 0 && run_failure.is_none() {
            emergency.load_acquire()
        } else {
            first_emergency
        };

        let selected = if final_emergency != 0 {
            Some(build_emergency(final_emergency))
        } else {
            run_failure.or_else(|| {
                (shutdown_state & SHUTDOWN_KIND_MASK == SHUTDOWN_RUNNING).then_some(unexpected)
            })
        };

        if let Some(outcome) = selected {
            let fatal = self.publish_fatal_from_slot(slot, outcome, encoded_owner);
            if !fatal.cause_installed {
                return Err(WorkerTerminationError::OutcomeAlreadyPublished);
            }
            if slot
                .state
                .compare_acqrel(OUTCOME_CAUSE_READY_RUNNING_CLEANUP, OUTCOME_CLEANUP_CLAIMED)
                .is_err()
            {
                return Err(WorkerTerminationError::CleanupOwnershipLost);
            }
            Ok(WorkerTerminationTransaction {
                core: slot,
                outcome,
                fatal: Some(fatal),
            })
        } else {
            slot.outcome
                .install(completed)
                .map_err(|_| WorkerTerminationError::OutcomeAlreadyPublished)?;
            slot.state
                .compare_acqrel(OUTCOME_EMPTY, OUTCOME_CLEANUP_CLAIMED)
                .map_err(|_| WorkerTerminationError::CleanupOwnershipLost)?;
            Ok(WorkerTerminationTransaction {
                core: slot,
                outcome: completed,
                fatal: None,
            })
        }
    }

    fn publish_fatal_owner(&self, encoded_owner: u64) -> bool {
        let publishing = SHUTDOWN_FATAL_PUBLISHING | encoded_owner;
        let published = SHUTDOWN_FATAL_PUBLISHED | encoded_owner;
        loop {
            let current = AtomicU64Authority::load_acquire(&self.state);
            match current & SHUTDOWN_KIND_MASK {
                SHUTDOWN_FATAL_PUBLISHING | SHUTDOWN_FATAL_PUBLISHED => return false,
                SHUTDOWN_RUNNING | SHUTDOWN_GRACEFUL => {
                    if self.state.compare_acqrel(current, publishing).is_ok() {
                        self.state.store_release(published);
                        return true;
                    }
                }
                _ => return false,
            }
        }
    }
}

impl<State> ShutdownSupervisionTransaction<'_, State>
where
    State: AtomicU64Authority + AtomicU64Value,
{
    /// Runs supervisor finalization and only then acquires the shutdown state
    /// that is allowed to determine process exit. The transaction is bound to
    /// the core that created it and is consumed exactly once.
    pub(crate) fn complete<Result>(self, completion: impl FnOnce() -> Result) -> (Result, u64) {
        let result = completion();
        let final_state = self.core.raw_state();
        let terminal_state = if final_state & SHUTDOWN_KIND_MASK == SHUTDOWN_RUNNING {
            self.observed_state
        } else {
            final_state
        };
        (result, terminal_state)
    }
}

#[cfg(all(test, loom, not(miri), not(target_env = "musl")))]
mod loom_tests;
