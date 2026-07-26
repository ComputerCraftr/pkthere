use super::{
    ATOMIC_PROTOCOL_RECORDS, AUTHORITY_RECORDS, AtomicProtocolId, AuditThreadRecord,
    AuthorityError, AuthorityId, AuthorityInstance, BLOCKING_EDGES, COHOLD_RULES, InstanceKeyKind,
    InstancePolicy, MemoryOrdering, OPERATION_RECORDS, OperationId, SHARED_RMW_RECORDS,
    SharedRmwDisposition, WaitId, WorkerAuditIdentity,
};
#[cfg(all(feature = "authority-audit", not(test)))]
use super::{
    EMERGENCY_EXPECTED_INSTANCE_SHIFT, EMERGENCY_EXPECTED_SHIFT, EMERGENCY_INSTANCE_MASK,
    EMERGENCY_MISSING_ORDINAL, EMERGENCY_OBSERVED_INSTANCE_SHIFT, EMERGENCY_OBSERVED_SHIFT,
};
use std::cell::Cell;
use std::sync::atomic::{AtomicU64, Ordering};

const MAX_AUDIT_STACK_DEPTH: usize = 64;
#[cfg(all(feature = "authority-audit", not(test)))]
const RELEASE_MISMATCH_CODE: u64 = 1;
#[cfg(all(feature = "authority-audit", not(test)))]
const OPERATION_MISMATCH_CODE: u64 = 2;
static EMERGENCY_FAILURE_CODE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy)]
struct FixedAuditStack<T: Copy> {
    entries: [Option<T>; MAX_AUDIT_STACK_DEPTH],
    len: usize,
}

impl<T: Copy> FixedAuditStack<T> {
    const fn new() -> Self {
        Self {
            entries: [None; MAX_AUDIT_STACK_DEPTH],
            len: 0,
        }
    }

    fn push(&mut self, value: T) -> Result<(), AuthorityError> {
        let Some(slot) = self.entries.get_mut(self.len) else {
            mark_failed();
            return Err(AuthorityError::AuditViolation);
        };
        *slot = Some(value);
        self.len += 1;
        Ok(())
    }

    fn pop(&mut self) -> Option<T> {
        let index = self.len.checked_sub(1)?;
        self.len = index;
        self.entries.get_mut(index)?.take()
    }

    fn last(&self) -> Option<T> {
        self.len
            .checked_sub(1)
            .and_then(|index| self.entries.get(index))
            .copied()
            .flatten()
    }

    fn iter(&self) -> impl Iterator<Item = T> + '_ {
        self.entries[..self.len].iter().copied().flatten()
    }

    fn remove_first(&mut self, mut predicate: impl FnMut(T) -> bool) -> bool {
        let Some(index) = self.iter().position(&mut predicate) else {
            return false;
        };
        for source in (index + 1)..self.len {
            self.entries[source - 1] = self.entries[source];
        }
        self.len -= 1;
        self.entries[self.len] = None;
        true
    }
}

#[derive(Clone, Copy)]
struct HeldAuthority {
    instance: AuthorityInstance,
    acquisition_line: u32,
}

impl HeldAuthority {
    fn new(instance: AuthorityInstance, location: &'static std::panic::Location<'static>) -> Self {
        Self {
            instance,
            acquisition_line: location.line(),
        }
    }
}

thread_local! {
    static HELD: Cell<FixedAuditStack<HeldAuthority>> =
        const { Cell::new(FixedAuditStack::new()) };
    static OPERATIONS: Cell<FixedAuditStack<OperationId>> =
        const { Cell::new(FixedAuditStack::new()) };
    static FAILED: Cell<bool> = const { Cell::new(false) };
    static ACQUISITIONS: Cell<[u64; AuthorityId::COUNT]> =
        const { Cell::new([0; AuthorityId::COUNT]) };
    static SHARED_RMWS: Cell<[u64; AuthorityId::COUNT]> =
        const { Cell::new([0; AuthorityId::COUNT]) };
    static PROTOCOL_RMWS: Cell<[u64; AtomicProtocolId::COUNT]> =
        const { Cell::new([0; AtomicProtocolId::COUNT]) };
    static WAITS: Cell<[u64; WaitId::COUNT]> =
        const { Cell::new([0; WaitId::COUNT]) };
    static OPERATION_COUNTS: Cell<[u64; OperationId::COUNT]> =
        const { Cell::new([0; OperationId::COUNT]) };
    static ALLOCATION_VIOLATIONS: Cell<u64> = const { Cell::new(0) };
    static ALLOCATION_VIOLATIONS_BY_AUTHORITY: Cell<[u64; AuthorityId::COUNT]> =
        const { Cell::new([0; AuthorityId::COUNT]) };
    static WORKER_IDENTITY: Cell<Option<WorkerAuditIdentity>> = const { Cell::new(None) };
    static PIPELINE_STAGES: Cell<[u64; 8]> = const { Cell::new([0; 8]) };
    static WORKER_ALLOCATIONS: Cell<u64> = const { Cell::new(0) };
    static WORKER_PAYLOAD_COPIES: Cell<u64> = const { Cell::new(0) };
    static WORKER_ENDPOINT_NORMALIZATIONS: Cell<u64> = const { Cell::new(0) };
    static FORBIDDEN_REFCOUNT_RMWS: Cell<u64> = const { Cell::new(0) };
    static FORBIDDEN_AUTHORITY_ACQUISITIONS: Cell<u64> = const { Cell::new(0) };
    static FORBIDDEN_SHARED_RMWS: Cell<u64> = const { Cell::new(0) };
    static VIOLATION_CODE: Cell<u64> = const { Cell::new(0) };
}

#[track_caller]
fn mark_failed() {
    let caller_line = u64::from(std::panic::Location::caller().line());
    FAILED.with(|failed| failed.set(true));
    VIOLATION_CODE.with(|code| {
        if code.get() == 0 {
            code.set(caller_line);
        }
    });
}

#[cold]
#[inline(never)]
fn mark_atomic_failed(
    authority: AuthorityId,
    protocol: AtomicProtocolId,
    ordering: MemoryOrdering,
) {
    const ATOMIC_FAILURE_CLASS: u64 = 1_u64 << 63;
    let code = ATOMIC_FAILURE_CLASS
        | ((authority as u64) << 16)
        | ((protocol as u64) << 8)
        | ordering as u64;
    FAILED.with(|failed| failed.set(true));
    VIOLATION_CODE.with(|current| {
        if current.get() == 0 {
            current.set(code);
        }
    });
}

#[cold]
#[inline(never)]
fn mark_allocation_failed(authority: HeldAuthority) {
    const ALLOCATION_FAILURE_CLASS: u64 = 2_u64 << 62;
    let code = ALLOCATION_FAILURE_CLASS
        | ((authority.instance.id as u64) << 32)
        | u64::from(authority.acquisition_line);
    FAILED.with(|failed| failed.set(true));
    VIOLATION_CODE.with(|current| {
        if current.get() == 0 {
            current.set(code);
        }
    });
}

pub(super) fn acquire(
    instance: AuthorityInstance,
    location: &'static std::panic::Location<'static>,
) -> Result<(), AuthorityError> {
    validate_acquisition_at(instance, location.line())?;
    HELD.with(|held| {
        let mut stack = held.get();
        stack.push(HeldAuthority::new(instance, location))?;
        held.set(stack);
        Ok(())
    })?;
    ACQUISITIONS.with(|counts| {
        let mut values = counts.get();
        let Some(next) = values[instance.id as usize].checked_add(1) else {
            mark_failed();
            return;
        };
        values[instance.id as usize] = next;
        counts.set(values);
    });
    Ok(())
}

pub(super) fn validate_acquisition(instance: AuthorityInstance) -> Result<(), AuthorityError> {
    validate_acquisition_at(instance, 0)
}

fn validate_acquisition_at(
    instance: AuthorityInstance,
    requested_at: u32,
) -> Result<(), AuthorityError> {
    let operation_conflict = OPERATIONS.with(|operations| {
        operations.get().iter().find(|operation| {
            OPERATION_RECORDS
                .iter()
                .find(|record| record.id == *operation)
                .is_none_or(|record| !record.permitted_while_held.contains(&instance.id))
        })
    });
    if let Some(operation) = operation_conflict {
        increment_worker_counter(WorkerCounter::ForbiddenAuthorityAcquisition);
        mark_failed();
        return Err(AuthorityError::OperationAcquisitionConflict {
            operation,
            requested: instance.id,
        });
    }
    let conflicting = HELD.with(|held| {
        held.get().iter().find(|current| {
            let cohold = COHOLD_RULES
                .iter()
                .any(|rule| rule.held == current.instance.id && rule.acquired == instance.id);
            let edge = reachable(current.instance.id, instance.id);
            let ordered_instance = instance_precedes(current.instance, instance);
            !(cohold && edge && ordered_instance)
        })
    });
    if let Some(held) = conflicting {
        increment_worker_counter(WorkerCounter::ForbiddenAuthorityAcquisition);
        mark_failed();
        return Err(AuthorityError::AcquisitionConflict {
            held: held.instance,
            held_at: held.acquisition_line,
            requested: instance,
            requested_at,
        });
    }
    Ok(())
}

pub(super) fn record_rmw(id: AuthorityId, protocol: AtomicProtocolId) {
    let stable_path_approved = SHARED_RMW_RECORDS.iter().any(|record| {
        record.authority == id
            && record.protocol == protocol
            && record.stable_path
            && record.disposition == SharedRmwDisposition::Approved
    });
    let hot_path_authority = AUTHORITY_RECORDS
        .iter()
        .find(|record| record.id == id)
        .is_some_and(|record| record.hot_path);
    if hot_path_authority && !stable_path_approved {
        increment_worker_counter(WorkerCounter::ForbiddenSharedRmw);
        mark_failed();
    }
    SHARED_RMWS.with(|counts| {
        let mut values = counts.get();
        let Some(next) = values[id as usize].checked_add(1) else {
            mark_failed();
            return;
        };
        values[id as usize] = next;
        counts.set(values);
    });
    PROTOCOL_RMWS.with(|counts| {
        let mut values = counts.get();
        let Some(next) = values[protocol as usize].checked_add(1) else {
            mark_failed();
            return;
        };
        values[protocol as usize] = next;
        counts.set(values);
    });
}

pub(super) fn validate_atomic_access(
    authority: AuthorityId,
    protocol: AtomicProtocolId,
    ordering: std::sync::atomic::Ordering,
) {
    let ordering = match ordering {
        std::sync::atomic::Ordering::Relaxed => MemoryOrdering::Relaxed,
        std::sync::atomic::Ordering::Acquire => MemoryOrdering::Acquire,
        std::sync::atomic::Ordering::Release => MemoryOrdering::Release,
        std::sync::atomic::Ordering::AcqRel => MemoryOrdering::AcqRel,
        std::sync::atomic::Ordering::SeqCst => MemoryOrdering::SeqCst,
        _ => {
            mark_failed();
            return;
        }
    };
    let valid = ATOMIC_PROTOCOL_RECORDS
        .iter()
        .find(|record| record.id == protocol)
        .is_some_and(|record| {
            record.allowed_authorities.contains(&authority)
                && record.allowed_orderings.contains(&ordering)
        });
    if !valid {
        mark_atomic_failed(authority, protocol, ordering);
    }
}

pub(super) fn record_access(id: AuthorityId) {
    ACQUISITIONS.with(|counts| {
        let mut values = counts.get();
        let Some(next) = values[id as usize].checked_add(1) else {
            mark_failed();
            return;
        };
        values[id as usize] = next;
        counts.set(values);
    });
}

pub(super) fn record_wait(id: WaitId) {
    WAITS.with(|counts| {
        let mut values = counts.get();
        let Some(next) = values[id as usize].checked_add(1) else {
            mark_failed();
            return;
        };
        values[id as usize] = next;
        counts.set(values);
    });
}

pub(super) fn validate_wait(id: WaitId) -> Result<(), AuthorityError> {
    let Some(record) = super::WAIT_RECORDS.iter().find(|record| record.id == id) else {
        mark_failed();
        return Err(AuthorityError::MissingWaitContract { wait: id });
    };
    if let Some(retained) = record.retained {
        let held = HELD.with(|held| {
            held.get()
                .iter()
                .any(|authority| authority.instance.id == retained)
        });
        if !held {
            mark_failed();
            return Err(AuthorityError::MissingRetainedWaitAuthority {
                wait: id,
                required: retained,
            });
        }
    }
    Ok(())
}

fn reachable(from: AuthorityId, to: AuthorityId) -> bool {
    let mut pending = [from; AuthorityId::COUNT];
    let mut pending_len = 1_usize;
    let mut visited = [false; AuthorityId::COUNT];
    visited[from as usize] = true;
    while pending_len != 0 {
        pending_len -= 1;
        let current = pending[pending_len];
        if current == to {
            return true;
        }
        for edge in BLOCKING_EDGES.iter().filter(|edge| edge.from == current) {
            if !visited[edge.to as usize] {
                visited[edge.to as usize] = true;
                pending[pending_len] = edge.to;
                pending_len += 1;
            }
        }
    }
    false
}

fn instance_precedes(current: AuthorityInstance, requested: AuthorityInstance) -> bool {
    if current.id != requested.id {
        return true;
    }
    let Some(record) = AUTHORITY_RECORDS
        .iter()
        .find(|record| record.id == current.id)
    else {
        return false;
    };
    match record.instance_policy() {
        InstancePolicy::SingletonNonReentrant | InstancePolicy::AtMostOne => false,
        InstancePolicy::StrictAscending(key) => {
            ordered_instance_key(current, key) < ordered_instance_key(requested, key)
        }
    }
}

fn ordered_instance_key(instance: AuthorityInstance, key: InstanceKeyKind) -> [u64; 4] {
    let direction = u64::from(instance.direction);
    let kind = u64::from(instance.kind);
    match key {
        InstanceKeyKind::Flow => [instance.flow, direction, kind, instance.session],
        InstanceKeyKind::SocketSlot => [instance.flow, direction, kind, instance.session],
        InstanceKeyKind::Direction => [instance.flow, direction, kind, instance.session],
        InstanceKeyKind::Worker => [instance.session, direction, kind, instance.flow],
        InstanceKeyKind::Session => [instance.flow, direction, instance.session, kind],
        InstanceKeyKind::ReservationTicket => [instance.flow, instance.session, direction, kind],
    }
}

pub(super) fn release(instance: AuthorityInstance) {
    let (valid, observed) = HELD.with(|held| {
        let mut stack = held.get();
        let result = if stack
            .last()
            .is_some_and(|current| current.instance == instance)
        {
            stack.pop();
            (true, None)
        } else {
            let observed = stack.last();
            // The production authority is being released even when its audit
            // order is invalid. Remove that exact audit entry while retaining
            // the fatal mismatch latch; otherwise a ghost entry masks the
            // original defect as an unrelated conflict on the next acquire.
            let _removed = stack.remove_first(|held| held.instance == instance);
            (false, observed)
        };
        held.set(stack);
        result
    });
    if !valid {
        mark_failed();
        report_release_mismatch(instance, observed);
    }
}

#[cfg(all(feature = "authority-audit", not(test)))]
fn report_release_mismatch(instance: AuthorityInstance, observed: Option<HeldAuthority>) {
    let observed_instance = observed.map(|authority| authority.instance);
    latch_emergency_failure(encode_authority_failure(
        RELEASE_MISMATCH_CODE,
        instance,
        observed_instance,
    ));
}

#[cfg(all(feature = "authority-audit", not(test)))]
const fn authority_instance_signature(instance: AuthorityInstance) -> u64 {
    (instance.flow
        ^ instance.session.rotate_left(17)
        ^ ((instance.direction as u64) << 8)
        ^ instance.kind as u64)
        & EMERGENCY_INSTANCE_MASK
}

#[cfg(all(feature = "authority-audit", not(test)))]
const fn encode_authority_failure(
    kind: u64,
    expected: AuthorityInstance,
    observed: Option<AuthorityInstance>,
) -> u64 {
    let observed_id = match observed {
        Some(instance) => instance.id as u64,
        None => EMERGENCY_MISSING_ORDINAL,
    };
    let observed_signature = match observed {
        Some(instance) => authority_instance_signature(instance),
        None => EMERGENCY_INSTANCE_MASK,
    };
    encode_emergency_failure(kind, expected.id as u64, observed_id)
        | (authority_instance_signature(expected) << EMERGENCY_EXPECTED_INSTANCE_SHIFT)
        | (observed_signature << EMERGENCY_OBSERVED_INSTANCE_SHIFT)
}

#[cfg(all(feature = "authority-audit", not(test)))]
const fn observed_operation_ordinal(observed: Option<OperationId>) -> u64 {
    match observed {
        Some(operation) => operation as u64,
        None => EMERGENCY_MISSING_ORDINAL,
    }
}

#[cfg(all(feature = "authority-audit", not(test)))]
fn report_operation_mismatch(expected: OperationId, observed: Option<OperationId>) {
    latch_emergency_failure(encode_emergency_failure(
        OPERATION_MISMATCH_CODE,
        expected as u64,
        observed_operation_ordinal(observed),
    ));
}

#[cfg(not(all(feature = "authority-audit", not(test))))]
fn report_operation_mismatch(_expected: OperationId, _observed: Option<OperationId>) {}

#[cfg(not(all(feature = "authority-audit", not(test))))]
fn report_release_mismatch(_instance: AuthorityInstance, _observed: Option<HeldAuthority>) {}

pub(super) fn release_for_wait(instance: AuthorityInstance) {
    release(instance);
}

pub(super) fn reacquire_after_wait(
    instance: AuthorityInstance,
    location: &'static std::panic::Location<'static>,
) -> Result<(), AuthorityError> {
    acquire(instance, location)
}

pub(super) fn enter_operation(id: OperationId) -> Result<(), AuthorityError> {
    let Some(record) = OPERATION_RECORDS.iter().find(|record| record.id == id) else {
        mark_failed();
        return Err(AuthorityError::AuditViolation);
    };
    let conflicting = HELD.with(|held| {
        held.get()
            .iter()
            .find(|authority| !record.permitted_while_held.contains(&authority.instance.id))
            .map(|authority| (authority.instance.id, authority.acquisition_line))
    });
    if let Some((held, _acquisition_line)) = conflicting {
        if matches!(
            id,
            OperationId::RefcountClone | OperationId::RefcountUpgrade
        ) {
            increment_worker_counter(WorkerCounter::ForbiddenRefcountRmw);
        }
        mark_failed();
        return Err(AuthorityError::OperationConflict {
            operation: id,
            held,
        });
    }
    if let Some(requirement) = super::OPERATION_REQUIREMENTS
        .iter()
        .find(|requirement| requirement.operation == id)
    {
        let required_held = HELD.with(|held| {
            held.get()
                .iter()
                .any(|authority| authority.instance.id == requirement.authority)
        });
        if !required_held {
            mark_failed();
            return Err(AuthorityError::MissingOperationAuthority {
                operation: id,
                required: requirement.authority,
            });
        }
    }
    OPERATIONS.with(|operations| {
        let mut stack = operations.get();
        stack.push(id)?;
        operations.set(stack);
        Ok(())
    })?;
    OPERATION_COUNTS.with(|counts| {
        let mut values = counts.get();
        let Some(next) = values[id as usize].checked_add(1) else {
            mark_failed();
            return;
        };
        values[id as usize] = next;
        counts.set(values);
    });
    Ok(())
}

pub(super) fn leave_operation(id: OperationId) {
    let observed = OPERATIONS.with(|operations| {
        let mut stack = operations.get();
        let observed = stack.pop();
        operations.set(stack);
        observed
    });
    let valid = observed.is_some_and(|held| held == id);
    if !valid {
        mark_failed();
        report_operation_mismatch(id, observed);
    }
}

pub(super) fn allocator_boundary() {
    let Some(record) = OPERATION_RECORDS
        .iter()
        .find(|record| record.id == OperationId::Allocator)
    else {
        mark_failed();
        return;
    };
    let (conflicts, first_conflict) = HELD.with(|held| {
        let mut conflicts = [false; AuthorityId::COUNT];
        let mut first_conflict = None;
        for authority in held.get().iter() {
            if !record.permitted_while_held.contains(&authority.instance.id) {
                conflicts[authority.instance.id as usize] = true;
                if first_conflict.is_none() {
                    first_conflict = Some(authority);
                }
            }
        }
        (conflicts, first_conflict)
    });
    if let Some(first_conflict) = first_conflict {
        increment_worker_counter(WorkerCounter::Allocation);
        mark_allocation_failed(first_conflict);
        ALLOCATION_VIOLATIONS.with(|violations| {
            let Some(next) = violations.get().checked_add(1) else {
                mark_failed();
                return;
            };
            violations.set(next);
        });
        ALLOCATION_VIOLATIONS_BY_AUTHORITY.with(|counts| {
            let mut values = counts.get();
            for (index, conflict) in conflicts.into_iter().enumerate() {
                if conflict {
                    let Some(next) = values[index].checked_add(1) else {
                        mark_failed();
                        continue;
                    };
                    values[index] = next;
                }
            }
            counts.set(values);
        });
    }
    OPERATION_COUNTS.with(|counts| {
        let mut values = counts.get();
        let Some(next) = values[OperationId::Allocator as usize].checked_add(1) else {
            mark_failed();
            return;
        };
        values[OperationId::Allocator as usize] = next;
        counts.set(values);
    });
}

enum WorkerCounter {
    Allocation,
    PayloadCopy,
    ForbiddenAuthorityAcquisition,
    ForbiddenRefcountRmw,
    ForbiddenSharedRmw,
}

fn increment_worker_counter(counter: WorkerCounter) {
    let registered = WORKER_IDENTITY.with(|identity| identity.get().is_some());
    if !registered {
        return;
    }
    match counter {
        WorkerCounter::Allocation => WORKER_ALLOCATIONS.with(increment_counter_cell),
        WorkerCounter::PayloadCopy => WORKER_PAYLOAD_COPIES.with(increment_counter_cell),
        WorkerCounter::ForbiddenAuthorityAcquisition => {
            FORBIDDEN_AUTHORITY_ACQUISITIONS.with(increment_counter_cell);
        }
        WorkerCounter::ForbiddenRefcountRmw => FORBIDDEN_REFCOUNT_RMWS.with(increment_counter_cell),
        WorkerCounter::ForbiddenSharedRmw => {
            FORBIDDEN_SHARED_RMWS.with(increment_counter_cell);
        }
    }
}

fn increment_counter_cell(count: &Cell<u64>) {
    match count.get().checked_add(1) {
        Some(next) => count.set(next),
        None => mark_failed(),
    }
}

pub(super) fn record_pipeline_stage(direction: bool, stage: usize) {
    let registered = WORKER_IDENTITY.with(|identity| identity.get().is_some());
    if !registered {
        #[cfg(test)]
        return;
        #[cfg(not(test))]
        {
            mark_failed();
            return;
        }
    }
    let identity_matches = WORKER_IDENTITY.with(|identity| {
        identity.get().is_some_and(|identity| {
            matches!(
                (identity.direction, direction),
                (super::AuditDirection::ClientToUpstream, true)
                    | (super::AuditDirection::UpstreamToClient, false)
            )
        })
    });
    if !identity_matches {
        mark_failed();
        return;
    }
    PIPELINE_STAGES.with(|stages| {
        let mut values = stages.get();
        let Some(current) = values.get_mut(stage) else {
            mark_failed();
            return;
        };
        let Some(next) = current.checked_add(1) else {
            mark_failed();
            return;
        };
        *current = next;
        stages.set(values);
    });
}

pub(super) fn record_payload_copy() {
    if packet_authority_is_held() {
        increment_worker_counter(WorkerCounter::PayloadCopy);
        mark_failed();
    }
}

fn packet_authority_is_held() -> bool {
    HELD.with(|held| {
        held.get().iter().any(|authority| {
            matches!(
                authority.instance.id,
                AuthorityId::FlowRead
                    | AuthorityId::SocketIo
                    | AuthorityId::ProtocolTransmit
                    | AuthorityId::ProtocolReceive
            )
        })
    })
}

pub(super) fn begin_worker(identity: WorkerAuditIdentity) {
    FAILED.set(false);
    ACQUISITIONS.set([0; AuthorityId::COUNT]);
    SHARED_RMWS.set([0; AuthorityId::COUNT]);
    PROTOCOL_RMWS.set([0; AtomicProtocolId::COUNT]);
    WAITS.set([0; WaitId::COUNT]);
    OPERATION_COUNTS.set([0; OperationId::COUNT]);
    ALLOCATION_VIOLATIONS.set(0);
    ALLOCATION_VIOLATIONS_BY_AUTHORITY.set([0; AuthorityId::COUNT]);
    PIPELINE_STAGES.set([0; 8]);
    WORKER_ALLOCATIONS.set(0);
    WORKER_PAYLOAD_COPIES.set(0);
    WORKER_ENDPOINT_NORMALIZATIONS.set(0);
    FORBIDDEN_REFCOUNT_RMWS.set(0);
    FORBIDDEN_AUTHORITY_ACQUISITIONS.set(0);
    FORBIDDEN_SHARED_RMWS.set(0);
    VIOLATION_CODE.set(0);
    let clean = HELD.with(|held| held.get().len == 0)
        && OPERATIONS.with(|operations| operations.get().len == 0)
        && WORKER_IDENTITY.with(|current| current.replace(Some(identity)).is_none());
    if !clean {
        mark_failed();
    }
}

pub(super) fn seal_worker() -> Result<AuditThreadRecord, &'static str> {
    if HELD.with(|held| held.get().len != 0)
        || OPERATIONS.with(|operations| operations.get().len != 0)
    {
        mark_failed();
    }
    let identity = WORKER_IDENTITY
        .with(|current| current.replace(None))
        .ok_or("worker audit thread was not registered")?;
    Ok(AuditThreadRecord {
        identity,
        pipeline_stages: PIPELINE_STAGES.get(),
        allocations: WORKER_ALLOCATIONS.get(),
        payload_copies: WORKER_PAYLOAD_COPIES.get(),
        endpoint_normalizations: WORKER_ENDPOINT_NORMALIZATIONS.get(),
        authority_acquisitions: ACQUISITIONS.get(),
        operation_counts: OPERATION_COUNTS.get(),
        shared_rmws: SHARED_RMWS.get(),
        protocol_rmws: PROTOCOL_RMWS.get(),
        wait_counts: WAITS.get(),
        forbidden_refcount_rmws: FORBIDDEN_REFCOUNT_RMWS.get(),
        forbidden_authority_acquisitions: FORBIDDEN_AUTHORITY_ACQUISITIONS.get(),
        forbidden_shared_rmws: FORBIDDEN_SHARED_RMWS.get(),
        allocation_violations_by_authority: ALLOCATION_VIOLATIONS_BY_AUTHORITY.get(),
        violation_code: VIOLATION_CODE.get(),
    })
}

#[cfg(test)]
pub(super) fn failed() -> bool {
    FAILED.with(Cell::get)
}

#[cfg(test)]
pub(super) fn is_held(id: AuthorityId) -> bool {
    HELD.with(|held| {
        held.get()
            .iter()
            .any(|authority| authority.instance.id == id)
    })
}

#[cfg(test)]
pub(super) fn acquisition_count(id: AuthorityId) -> u64 {
    ACQUISITIONS.with(|counts| counts.get()[id as usize])
}

#[cfg(test)]
pub(super) fn shared_rmw_count(id: AuthorityId) -> u64 {
    SHARED_RMWS.with(|counts| counts.get()[id as usize])
}

#[cfg(test)]
pub(super) fn wait_count(id: WaitId) -> u64 {
    WAITS.with(|counts| counts.get()[id as usize])
}

#[cfg(test)]
pub(super) fn operation_count(id: OperationId) -> u64 {
    OPERATION_COUNTS.with(|counts| counts.get()[id as usize])
}

#[cfg(test)]
pub(super) fn allocation_violation_count() -> u64 {
    ALLOCATION_VIOLATIONS.with(Cell::get)
}

#[cfg(test)]
pub(super) fn allocation_violation_count_for_authority(id: AuthorityId) -> u64 {
    ALLOCATION_VIOLATIONS_BY_AUTHORITY.with(|counts| counts.get()[id as usize])
}

#[cfg(all(feature = "authority-audit", not(test)))]
fn latch_emergency_failure(code: u64) {
    let _result =
        EMERGENCY_FAILURE_CODE.compare_exchange(0, code, Ordering::Release, Ordering::Relaxed);
}

#[cfg(all(feature = "authority-audit", not(test)))]
const fn encode_emergency_failure(kind: u64, expected: u64, observed: u64) -> u64 {
    kind | (expected << EMERGENCY_EXPECTED_SHIFT) | (observed << EMERGENCY_OBSERVED_SHIFT)
}

pub(super) fn emergency_failure_code() -> u64 {
    EMERGENCY_FAILURE_CODE.load(Ordering::Acquire)
}
