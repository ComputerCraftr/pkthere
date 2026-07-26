use super::StateVersion;
use super::version::VersionClock;
use crate::net::sock_mgr::ManagerError;

#[test]
fn stale_capacity_never_returns_a_usable_version() {
    let clock = VersionClock::new();
    let first = clock.precheck_capacity().expect("first capacity");
    let stale = clock.precheck_capacity().expect("stale capacity");
    assert_eq!(
        clock.publish_prechecked(first).expect("first publication"),
        StateVersion(1)
    );
    assert!(matches!(
        clock.publish_prechecked(stale),
        Err(ManagerError::VersionPublicationFailed {
            expected: StateVersion::INITIAL,
            actual: Some(StateVersion(1)),
        })
    ));
    assert_eq!(clock.current(), StateVersion(1));
}
