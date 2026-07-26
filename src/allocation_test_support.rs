#[cfg(any(test, feature = "authority-audit"))]
use std::alloc::{GlobalAlloc, Layout, System};
#[cfg(test)]
use std::cell::Cell;

#[cfg(test)]
const STABLE_FORWARD_FORBIDDEN_AUTHORITIES: [crate::authority::AuthorityId; 15] = [
    crate::authority::AuthorityId::FlowReservation,
    crate::authority::AuthorityId::FlowClaim,
    crate::authority::AuthorityId::FlowWrite,
    crate::authority::AuthorityId::ManagerTransaction,
    crate::authority::AuthorityId::ManagerState,
    crate::authority::AuthorityId::SocketTopology,
    crate::authority::AuthorityId::SocketAssociation,
    crate::authority::AuthorityId::SocketDescriptor,
    crate::authority::AuthorityId::ControlObservation,
    crate::authority::AuthorityId::ResetBudget,
    crate::authority::AuthorityId::SessionControl,
    crate::authority::AuthorityId::Maintenance,
    crate::authority::AuthorityId::ReceiverClaim,
    crate::authority::AuthorityId::WaitCoordination,
    crate::authority::AuthorityId::RuntimeSupervisor,
];

#[cfg(any(test, feature = "authority-audit"))]
#[global_allocator]
static TEST_ALLOCATOR: CountingAllocator = CountingAllocator;

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StableForwardAuthoritySnapshot {
    counts: [(u64, u64); STABLE_FORWARD_FORBIDDEN_AUTHORITIES.len()],
}

#[cfg(test)]
impl StableForwardAuthoritySnapshot {
    pub(crate) fn capture() -> Self {
        Self {
            counts: STABLE_FORWARD_FORBIDDEN_AUTHORITIES.map(|authority| {
                (
                    crate::authority::acquisition_count_for_test(authority),
                    crate::authority::shared_rmw_count_for_test(authority),
                )
            }),
        }
    }

    pub(crate) fn assert_unchanged(self) {
        let after = Self::capture();
        if self != after {
            let changes = STABLE_FORWARD_FORBIDDEN_AUTHORITIES
                .into_iter()
                .zip(self.counts)
                .zip(after.counts)
                .filter_map(|((authority, before), after)| {
                    (before != after).then_some((authority, before, after))
                })
                .collect::<Vec<_>>();
            panic!(
                "stable forwarding acquired a transition/global authority or performed its shared RMW: {changes:?}"
            );
        }
    }
}

#[cfg(test)]
thread_local! {
    static TRACKING: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
    static TRACKING_PAYLOAD_COPIES: Cell<bool> = const { Cell::new(false) };
    static PAYLOAD_COPIES: Cell<usize> = const { Cell::new(0) };
    static TRACKING_ENDPOINT_NORMALIZATIONS: Cell<bool> = const { Cell::new(false) };
    static ENDPOINT_NORMALIZATIONS: Cell<usize> = const { Cell::new(0) };
    static TRACKING_LOCK_CANDIDATES: Cell<bool> = const { Cell::new(false) };
    static LOCK_CANDIDATES: Cell<usize> = const { Cell::new(0) };
}

#[cfg(test)]
struct CounterScope {
    kind: CounterKind,
    previous_tracking: bool,
    previous_count: usize,
}

#[cfg(test)]
impl CounterScope {
    fn enter(kind: CounterKind) -> Self {
        let previous_tracking = kind.replace_tracking(true);
        let previous_count = kind.replace_count(0);
        Self {
            kind,
            previous_tracking,
            previous_count,
        }
    }

    fn current(&self) -> usize {
        self.kind.count()
    }
}

#[cfg(test)]
impl Drop for CounterScope {
    fn drop(&mut self) {
        let nested_count = self.kind.count();
        let restored_count = if self.previous_tracking {
            self.previous_count.saturating_add(nested_count)
        } else {
            self.previous_count
        };
        self.kind.replace_count(restored_count);
        self.kind.replace_tracking(self.previous_tracking);
    }
}

#[cfg(test)]
#[derive(Clone, Copy)]
enum CounterKind {
    Allocation,
    PayloadCopy,
    EndpointNormalization,
    LockCandidate,
}

#[cfg(test)]
impl CounterKind {
    fn replace_tracking(self, value: bool) -> bool {
        match self {
            Self::Allocation => TRACKING.with(|cell| cell.replace(value)),
            Self::PayloadCopy => TRACKING_PAYLOAD_COPIES.with(|cell| cell.replace(value)),
            Self::EndpointNormalization => {
                TRACKING_ENDPOINT_NORMALIZATIONS.with(|cell| cell.replace(value))
            }
            Self::LockCandidate => TRACKING_LOCK_CANDIDATES.with(|cell| cell.replace(value)),
        }
    }

    fn replace_count(self, value: usize) -> usize {
        match self {
            Self::Allocation => ALLOCATIONS.with(|cell| cell.replace(value)),
            Self::PayloadCopy => PAYLOAD_COPIES.with(|cell| cell.replace(value)),
            Self::EndpointNormalization => ENDPOINT_NORMALIZATIONS.with(|cell| cell.replace(value)),
            Self::LockCandidate => LOCK_CANDIDATES.with(|cell| cell.replace(value)),
        }
    }

    fn count(self) -> usize {
        match self {
            Self::Allocation => ALLOCATIONS.with(Cell::get),
            Self::PayloadCopy => PAYLOAD_COPIES.with(Cell::get),
            Self::EndpointNormalization => ENDPOINT_NORMALIZATIONS.with(Cell::get),
            Self::LockCandidate => LOCK_CANDIDATES.with(Cell::get),
        }
    }
}

#[cfg(any(test, feature = "authority-audit"))]
struct CountingAllocator;

#[cfg(any(test, feature = "authority-audit"))]
impl CountingAllocator {
    fn record_allocation() {
        crate::authority::audit_allocator_boundary();
        #[cfg(test)]
        // TLS may already be tearing down; lost test accounting must not
        // alter the system allocator's required behavior.
        let _tracking_result = TRACKING.try_with(|tracking| {
            if tracking.get() {
                let _allocation_result =
                    ALLOCATIONS.try_with(|count| count.set(count.get().saturating_add(1)));
            }
        });
    }
}

// SAFETY: every allocation operation delegates unchanged to the system
// allocator; the wrapper records only thread-local audit metadata.
#[cfg(any(test, feature = "authority-audit"))]
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        Self::record_allocation();
        // SAFETY: the GlobalAlloc caller supplies a valid Layout, which is
        // forwarded unchanged to the system allocator.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        Self::record_allocation();
        // SAFETY: the GlobalAlloc caller supplies a valid Layout, which is
        // forwarded unchanged to the system allocator.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: GlobalAlloc requires callers to return a pointer with
        // the matching Layout; both are forwarded unchanged.
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        Self::record_allocation();
        // SAFETY: pointer/Layout provenance and the requested size are
        // forwarded unchanged under GlobalAlloc's caller contract.
        unsafe { System.realloc(pointer, layout, new_size) }
    }
}

#[cfg(test)]
pub(crate) fn count_allocations<T>(operation: impl FnOnce() -> T) -> (T, usize) {
    let scope = CounterScope::enter(CounterKind::Allocation);
    let result = operation();
    let allocations = scope.current();
    drop(scope);
    (result, allocations)
}

#[cfg(any(test, feature = "authority-audit"))]
pub(crate) fn record_payload_copy() {
    crate::authority::record_payload_copy();
    #[cfg(test)]
    TRACKING_PAYLOAD_COPIES.with(|tracking| {
        if tracking.get() {
            PAYLOAD_COPIES.with(|count| count.set(count.get().saturating_add(1)));
        }
    });
}

#[cfg(test)]
pub(crate) fn count_payload_copies<T>(operation: impl FnOnce() -> T) -> (T, usize) {
    let scope = CounterScope::enter(CounterKind::PayloadCopy);
    let result = operation();
    let copies = scope.current();
    drop(scope);
    (result, copies)
}

#[cfg(test)]
pub(crate) fn record_endpoint_normalization() {
    if TRACKING_ENDPOINT_NORMALIZATIONS.get() {
        ENDPOINT_NORMALIZATIONS.set(ENDPOINT_NORMALIZATIONS.get().saturating_add(1));
    }
}

#[cfg(test)]
pub(crate) fn count_endpoint_normalizations<T>(operation: impl FnOnce() -> T) -> (T, usize) {
    let scope = CounterScope::enter(CounterKind::EndpointNormalization);
    let result = operation();
    let count = scope.current();
    drop(scope);
    (result, count)
}

#[cfg(test)]
pub(crate) fn record_lock_candidate_construction() {
    if TRACKING_LOCK_CANDIDATES.get() {
        LOCK_CANDIDATES.set(LOCK_CANDIDATES.get().saturating_add(1));
    }
}

#[cfg(test)]
pub(crate) fn count_lock_candidate_constructions<T>(operation: impl FnOnce() -> T) -> (T, usize) {
    let scope = CounterScope::enter(CounterKind::LockCandidate);
    let result = operation();
    let count = scope.current();
    drop(scope);
    (result, count)
}
