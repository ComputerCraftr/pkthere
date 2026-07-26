use crate::atomic_core::{AtomicU64Authority, AtomicU64Value};

const PHASE_BITS: u32 = 3;
const COUNT_BITS: u32 = 9;
const EXPECTED_SHIFT: u32 = PHASE_BITS;
const PUBLISHED_SHIFT: u32 = EXPECTED_SHIFT + COUNT_BITS;
const COMPONENT_SHIFT: u32 = PUBLISHED_SHIFT + COUNT_BITS;
const COMPONENT_BITS: u32 = 8;
const COMPLETED_SHIFT: u32 = COMPONENT_SHIFT + COMPONENT_BITS;
const PHASE_MASK: u64 = (1_u64 << PHASE_BITS) - 1;
const COUNT_MASK: u64 = (1_u64 << COUNT_BITS) - 1;
const COMPONENT_MASK: u64 = (1_u64 << COMPONENT_BITS) - 1;
const STEP_RECEIVER: u8 = 0;
const STEP_MANAGER_METADATA: u8 = 1;
const STEP_MANAGER_VERSION: u8 = 2;
const STEP_SOCKET_TOPOLOGY: u8 = 3;
const STEP_MANAGER_RESERVATION: u8 = 4;
const STEP_FLOW_VISIBILITY: u8 = 5;
const STEP_FINISH: u8 = 6;

pub(super) const COMPONENT_DESCRIPTOR_ASSOCIATION: u8 = 1 << 0;
pub(super) const COMPONENT_RECEIVER: u8 = 1 << 1;
pub(super) const COMPONENT_MANAGER_METADATA: u8 = 1 << 2;
pub(super) const COMPONENT_MANAGER_VERSION: u8 = 1 << 3;
pub(super) const COMPONENT_SOCKET_GATES: u8 = 1 << 4;
pub(super) const COMPONENT_FLOW_VISIBILITY: u8 = 1 << 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum GroupPublicationPhase {
    SessionCommitted = 0,
    Publishing = 1,
    ReadyToPublish = 2,
    Published = 3,
    Poisoned = 4,
}

impl GroupPublicationPhase {
    pub(super) fn decode(value: u64) -> Option<Self> {
        match value & PHASE_MASK {
            0 => Some(Self::SessionCommitted),
            1 => Some(Self::Publishing),
            2 => Some(Self::ReadyToPublish),
            3 => Some(Self::Published),
            4 => Some(Self::Poisoned),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum GroupPublicationError {
    CapacityExceeded,
    Corrupted(u64),
    InvalidPhase(GroupPublicationPhase),
    ManagerOutOfOrder,
    MissingPublication,
}

pub(super) struct PublicationStep<'transaction, const STEP: u8> {
    _transaction: &'transaction (),
}

pub(super) trait CommittedGroupPublication {
    type Error;
    type Output;

    fn publish_receiver(
        &mut self,
        step: PublicationStep<'_, { STEP_RECEIVER }>,
    ) -> Result<(), Self::Error>;
    fn publish_manager_metadata(
        &mut self,
        step: PublicationStep<'_, { STEP_MANAGER_METADATA }>,
    ) -> Result<(), Self::Error>;
    fn publish_manager(
        &mut self,
        step: PublicationStep<'_, { STEP_MANAGER_VERSION }>,
        index: usize,
    ) -> Result<(), Self::Error>;
    fn publish_socket_topology(
        &mut self,
        step: PublicationStep<'_, { STEP_SOCKET_TOPOLOGY }>,
    ) -> Result<(), Self::Error>;
    fn commit_manager_reservations(
        &mut self,
        step: PublicationStep<'_, { STEP_MANAGER_RESERVATION }>,
    ) -> Result<(), Self::Error>;
    fn publish_flow_visibility(
        &mut self,
        step: PublicationStep<'_, { STEP_FLOW_VISIBILITY }>,
    ) -> Result<(), Self::Error>;
    fn finish(self, step: PublicationStep<'_, { STEP_FINISH }>) -> Self::Output;
}

pub(super) enum GroupCommitError<Error> {
    Core(GroupPublicationError),
    Mutation(Error),
}

impl<Error: std::fmt::Debug> std::fmt::Debug for GroupCommitError<Error> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Core(error) => formatter.debug_tuple("Core").field(error).finish(),
            Self::Mutation(error) => formatter.debug_tuple("Mutation").field(error).finish(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct GroupPublicationSnapshot {
    pub(super) phase: GroupPublicationPhase,
    pub(super) expected_managers: usize,
    pub(super) published_managers: usize,
    pub(super) required_components: u8,
    pub(super) completed_components: u8,
}

/// One ownership-bearing, post-session-commit publication machine.
///
/// Construction is delayed until the irreversible session receipt exists.
/// The core is then consumed by one complete resource publication. Loom
/// instantiates this same type with modeled atomics and tiny resources.
pub(super) struct GroupPublicationCore<State> {
    state: State,
}

/// Consuming owner of every staged resource participating in one grouped
/// publication. The backend contains the descriptor, receiver, manager, and
/// flow leases and cannot escape without reaching one terminal path.
struct GroupPublicationTransaction<State, Backend>
where
    State: AtomicU64Authority + AtomicU64Value,
    Backend: CommittedGroupPublication,
{
    core: GroupPublicationCore<State>,
    backend: Option<Backend>,
    terminal: bool,
}

impl<State, Backend> GroupPublicationTransaction<State, Backend>
where
    State: AtomicU64Authority + AtomicU64Value,
    Backend: CommittedGroupPublication,
{
    fn new(core: GroupPublicationCore<State>, backend: Backend) -> Self {
        Self {
            core,
            backend: Some(backend),
            terminal: false,
        }
    }

    fn publish(mut self) -> Result<Backend::Output, GroupCommitError<Backend::Error>> {
        let snapshot = self.core.snapshot().map_err(GroupCommitError::Core)?;
        if snapshot.phase != GroupPublicationPhase::SessionCommitted {
            return Err(GroupCommitError::Core(GroupPublicationError::InvalidPhase(
                snapshot.phase,
            )));
        }
        self.core
            .begin_publication()
            .map_err(GroupCommitError::Core)?;
        if snapshot.required_components & COMPONENT_RECEIVER != 0 {
            self.core
                .validate_component(COMPONENT_RECEIVER)
                .map_err(GroupCommitError::Core)?;
            self.backend_mut()
                .publish_receiver(PublicationStep { _transaction: &() })
                .map_err(GroupCommitError::Mutation)?;
            self.core
                .record_component(COMPONENT_RECEIVER)
                .map_err(GroupCommitError::Core)?;
        }
        if snapshot.required_components & COMPONENT_MANAGER_METADATA != 0 {
            self.core
                .validate_component(COMPONENT_MANAGER_METADATA)
                .map_err(GroupCommitError::Core)?;
            self.backend_mut()
                .publish_manager_metadata(PublicationStep { _transaction: &() })
                .map_err(GroupCommitError::Mutation)?;
            self.core
                .record_component(COMPONENT_MANAGER_METADATA)
                .map_err(GroupCommitError::Core)?;
        }
        for index in 0..snapshot.expected_managers {
            self.core
                .validate_manager(index)
                .map_err(GroupCommitError::Core)?;
            self.backend_mut()
                .publish_manager(PublicationStep { _transaction: &() }, index)
                .map_err(GroupCommitError::Mutation)?;
            self.core
                .record_manager(index)
                .map_err(GroupCommitError::Core)?;
        }
        let socket_components = COMPONENT_DESCRIPTOR_ASSOCIATION | COMPONENT_SOCKET_GATES;
        self.core
            .validate_component(socket_components)
            .map_err(GroupCommitError::Core)?;
        self.backend_mut()
            .publish_socket_topology(PublicationStep { _transaction: &() })
            .map_err(GroupCommitError::Mutation)?;
        self.core
            .record_component(socket_components)
            .map_err(GroupCommitError::Core)?;
        self.backend_mut()
            .commit_manager_reservations(PublicationStep { _transaction: &() })
            .map_err(GroupCommitError::Mutation)?;
        self.core
            .ready_to_publish()
            .map_err(GroupCommitError::Core)?;
        self.backend_mut()
            .publish_flow_visibility(PublicationStep { _transaction: &() })
            .map_err(GroupCommitError::Mutation)?;
        self.core
            .finish_visibility()
            .map_err(GroupCommitError::Core)?;
        let backend = self.backend.take().ok_or(GroupCommitError::Core(
            GroupPublicationError::MissingPublication,
        ))?;
        let output = backend.finish(PublicationStep { _transaction: &() });
        self.terminal = true;
        Ok(output)
    }

    fn backend_mut(&mut self) -> &mut Backend {
        match self.backend.as_mut() {
            Some(backend) => backend,
            None => {
                self.core.poison();
                crate::runtime_support::fatal_invariant_or_shutdown(format_args!(
                    "group publication transaction lost its staged resource bundle"
                ));
            }
        }
    }
}

impl<State, Backend> Drop for GroupPublicationTransaction<State, Backend>
where
    State: AtomicU64Authority + AtomicU64Value,
    Backend: CommittedGroupPublication,
{
    fn drop(&mut self) {
        if !self.terminal {
            self.core.poison();
        }
    }
}

pub(super) type ProductionGroupPublicationCore = GroupPublicationCore<
    crate::authority::AuthorityAtomic<
        crate::authority::tags::ManagerState,
        std::sync::atomic::AtomicU64,
    >,
>;

pub(super) fn production_group_publication(
    expected_managers: usize,
    required_components: u8,
) -> Result<ProductionGroupPublicationCore, GroupPublicationError> {
    GroupPublicationCore::new(
        crate::authority::AuthorityAtomic::new_u64(
            0,
            crate::authority::AtomicProtocolId::ManagerPublication,
        ),
        expected_managers,
        required_components,
    )
}

pub(super) fn fail_group_publication(
    operation: &'static str,
    error: impl std::fmt::Debug,
) -> super::ManagerError {
    crate::runtime_support::publish_process_fatal(format_args!(
        "grouped client-flow publication failed after its irreversible point during {operation}: {error:?}"
    ));
    super::ManagerError::Poisoned {
        authority: "grouped client-flow publication",
    }
}

pub(super) fn prepare_clear_publication(
    may_need_publication: &[bool],
    receiver_changed: bool,
) -> Result<(Vec<super::PublishedUpdate>, usize, u8), super::ManagerError> {
    let changed_manager_count = may_need_publication
        .iter()
        .filter(|changed| **changed)
        .count();
    let mut required_components =
        COMPONENT_DESCRIPTOR_ASSOCIATION | COMPONENT_SOCKET_GATES | COMPONENT_FLOW_VISIBILITY;
    if changed_manager_count != 0 {
        required_components |= COMPONENT_MANAGER_METADATA | COMPONENT_MANAGER_VERSION;
    }
    if receiver_changed {
        required_components |= COMPONENT_RECEIVER;
    }
    let mut updates = Vec::new();
    updates
        .try_reserve_exact(changed_manager_count)
        .map_err(|_| {
            super::ManagerError::io(
                "prepare shared client-flow clear publication",
                std::io::Error::other("could not reserve publication output"),
            )
        })?;
    Ok((updates, changed_manager_count, required_components))
}

impl<State> GroupPublicationCore<State>
where
    State: AtomicU64Authority + AtomicU64Value,
{
    pub(super) fn new(
        state: State,
        expected_managers: usize,
        required_components: u8,
    ) -> Result<Self, GroupPublicationError> {
        let expected = u64::try_from(expected_managers)
            .ok()
            .filter(|count| *count <= COUNT_MASK)
            .ok_or(GroupPublicationError::CapacityExceeded)?;
        if u64::from(required_components) > COMPONENT_MASK {
            return Err(GroupPublicationError::CapacityExceeded);
        }
        let encoded = expected << EXPECTED_SHIFT
            | u64::from(required_components) << COMPONENT_SHIFT
            | GroupPublicationPhase::SessionCommitted as u64;
        state.store_release(encoded);
        Ok(Self { state })
    }

    pub(super) fn publish_committed<Backend>(
        self,
        backend: Backend,
    ) -> Result<Backend::Output, GroupCommitError<Backend::Error>>
    where
        Backend: CommittedGroupPublication,
    {
        GroupPublicationTransaction::new(self, backend).publish()
    }

    fn validate_manager(&self, index: usize) -> Result<(), GroupPublicationError> {
        let snapshot = self.snapshot()?;
        if snapshot.phase != GroupPublicationPhase::Publishing {
            return Err(GroupPublicationError::InvalidPhase(snapshot.phase));
        }
        if snapshot.published_managers != index || index >= snapshot.expected_managers {
            return Err(GroupPublicationError::ManagerOutOfOrder);
        }
        Ok(())
    }

    fn record_manager(&self, index: usize) -> Result<(), GroupPublicationError> {
        loop {
            let state = AtomicU64Authority::load_acquire(&self.state);
            let snapshot = decode(state)?;
            if snapshot.phase != GroupPublicationPhase::Publishing {
                return Err(GroupPublicationError::InvalidPhase(snapshot.phase));
            }
            if snapshot.published_managers != index || index >= snapshot.expected_managers {
                return Err(GroupPublicationError::ManagerOutOfOrder);
            }
            let mut next = state
                .checked_add(1_u64 << PUBLISHED_SHIFT)
                .ok_or(GroupPublicationError::Corrupted(state))?;
            if index + 1 == snapshot.expected_managers
                && snapshot.required_components & COMPONENT_MANAGER_VERSION != 0
            {
                let completed = snapshot.completed_components | COMPONENT_MANAGER_VERSION;
                next = (next & !(COMPONENT_MASK << COMPLETED_SHIFT))
                    | u64::from(completed) << COMPLETED_SHIFT;
            }
            if self.state.compare_acqrel(state, next).is_ok() {
                return Ok(());
            }
        }
    }

    fn validate_component(&self, component: u8) -> Result<(), GroupPublicationError> {
        let snapshot = self.snapshot()?;
        if snapshot.phase != GroupPublicationPhase::Publishing {
            return Err(GroupPublicationError::InvalidPhase(snapshot.phase));
        }
        if component == 0 || component & !snapshot.required_components != 0 {
            return Err(GroupPublicationError::MissingPublication);
        }
        Ok(())
    }

    fn record_component(&self, component: u8) -> Result<(), GroupPublicationError> {
        loop {
            let state = AtomicU64Authority::load_acquire(&self.state);
            let snapshot = decode(state)?;
            if snapshot.phase != GroupPublicationPhase::Publishing {
                return Err(GroupPublicationError::InvalidPhase(snapshot.phase));
            }
            if component == 0 || component & !snapshot.required_components != 0 {
                return Err(GroupPublicationError::MissingPublication);
            }
            let completed = snapshot.completed_components | component;
            let next = (state & !(COMPONENT_MASK << COMPLETED_SHIFT))
                | u64::from(completed) << COMPLETED_SHIFT;
            if self.state.compare_acqrel(state, next).is_ok() {
                return Ok(());
            }
        }
    }

    fn ready_to_publish(&self) -> Result<(), GroupPublicationError> {
        let snapshot = self.snapshot()?;
        if snapshot.phase != GroupPublicationPhase::Publishing {
            return Err(GroupPublicationError::InvalidPhase(snapshot.phase));
        }
        let pre_visibility_components = snapshot.required_components & !COMPONENT_FLOW_VISIBILITY;
        if snapshot.published_managers != snapshot.expected_managers
            || snapshot.completed_components != pre_visibility_components
        {
            return Err(GroupPublicationError::MissingPublication);
        }
        self.advance(
            GroupPublicationPhase::Publishing,
            GroupPublicationPhase::ReadyToPublish,
        )
    }

    fn begin_publication(&self) -> Result<(), GroupPublicationError> {
        self.advance(
            GroupPublicationPhase::SessionCommitted,
            GroupPublicationPhase::Publishing,
        )
    }

    fn finish_visibility(&self) -> Result<(), GroupPublicationError> {
        loop {
            let state = AtomicU64Authority::load_acquire(&self.state);
            let snapshot = decode(state)?;
            if snapshot.phase != GroupPublicationPhase::ReadyToPublish {
                return Err(GroupPublicationError::InvalidPhase(snapshot.phase));
            }
            let completed = snapshot.completed_components | COMPONENT_FLOW_VISIBILITY;
            if completed != snapshot.required_components {
                return Err(GroupPublicationError::MissingPublication);
            }
            let published = (state & !(PHASE_MASK | (COMPONENT_MASK << COMPLETED_SHIFT)))
                | u64::from(completed) << COMPLETED_SHIFT
                | GroupPublicationPhase::Published as u64;
            if self.state.compare_acqrel(state, published).is_ok() {
                return Ok(());
            }
        }
    }

    fn poison(&self) {
        loop {
            let state = AtomicU64Authority::load_acquire(&self.state);
            if GroupPublicationPhase::decode(state) == Some(GroupPublicationPhase::Poisoned) {
                return;
            }
            let poisoned = (state & !PHASE_MASK) | GroupPublicationPhase::Poisoned as u64;
            if self.state.compare_acqrel(state, poisoned).is_ok() {
                return;
            }
        }
    }

    fn snapshot(&self) -> Result<GroupPublicationSnapshot, GroupPublicationError> {
        decode(AtomicU64Authority::load_acquire(&self.state))
    }

    fn advance(
        &self,
        expected: GroupPublicationPhase,
        next: GroupPublicationPhase,
    ) -> Result<(), GroupPublicationError> {
        loop {
            let state = AtomicU64Authority::load_acquire(&self.state);
            let observed = GroupPublicationPhase::decode(state)
                .ok_or(GroupPublicationError::Corrupted(state))?;
            if observed != expected {
                return Err(GroupPublicationError::InvalidPhase(observed));
            }
            let updated = (state & !PHASE_MASK) | next as u64;
            if self.state.compare_acqrel(state, updated).is_ok() {
                return Ok(());
            }
        }
    }
}

fn decode(state: u64) -> Result<GroupPublicationSnapshot, GroupPublicationError> {
    let phase =
        GroupPublicationPhase::decode(state).ok_or(GroupPublicationError::Corrupted(state))?;
    let expected = (state >> EXPECTED_SHIFT) & COUNT_MASK;
    let published = (state >> PUBLISHED_SHIFT) & COUNT_MASK;
    let required = (state >> COMPONENT_SHIFT) & COMPONENT_MASK;
    let completed = (state >> COMPLETED_SHIFT) & COMPONENT_MASK;
    Ok(GroupPublicationSnapshot {
        phase,
        expected_managers: usize::try_from(expected)
            .map_err(|_| GroupPublicationError::Corrupted(state))?,
        published_managers: usize::try_from(published)
            .map_err(|_| GroupPublicationError::Corrupted(state))?,
        required_components: u8::try_from(required)
            .map_err(|_| GroupPublicationError::Corrupted(state))?,
        completed_components: u8::try_from(completed)
            .map_err(|_| GroupPublicationError::Corrupted(state))?,
    })
}
