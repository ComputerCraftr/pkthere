use super::{
    AtomicProtocolId, AuthorityError, AuthorityId, AuthorityInstance, OperationId, WaitId,
};

#[inline]
pub(super) fn acquire(
    _instance: AuthorityInstance,
    _location: &'static std::panic::Location<'static>,
) -> Result<(), AuthorityError> {
    Ok(())
}

#[inline]
pub(super) fn validate_acquisition(_instance: AuthorityInstance) -> Result<(), AuthorityError> {
    Ok(())
}

#[inline]
pub(super) fn release(_instance: AuthorityInstance) {}

#[inline]
pub(super) fn release_for_wait(_instance: AuthorityInstance) {}

#[inline]
pub(super) fn reacquire_after_wait(
    _instance: AuthorityInstance,
    _location: &'static std::panic::Location<'static>,
) -> Result<(), AuthorityError> {
    Ok(())
}

#[inline]
pub(super) fn enter_operation(_id: OperationId) -> Result<(), AuthorityError> {
    Ok(())
}

#[inline]
pub(super) fn leave_operation(_id: OperationId) {}

#[inline]
pub(super) fn record_rmw(_id: AuthorityId, _protocol: AtomicProtocolId) {}
pub(super) fn validate_atomic_access(
    _authority: AuthorityId,
    _protocol: AtomicProtocolId,
    _ordering: std::sync::atomic::Ordering,
) {
}
pub(super) fn record_access(_id: AuthorityId) {}
pub(super) fn record_wait(_id: WaitId) {}
pub(super) fn validate_wait(_id: WaitId) -> Result<(), AuthorityError> {
    Ok(())
}

pub(super) const fn emergency_failure_code() -> u64 {
    0
}
