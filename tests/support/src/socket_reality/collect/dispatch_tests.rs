use super::dispatch::validate_collection_authority;
use crate::socket_reality::case::RealityOperation;
use crate::socket_reality::requirement::CollectionAuthority;

#[test]
fn raw_receive_accepts_only_explicit_direct_or_privileged_fallback_authority() {
    assert!(
        validate_collection_authority(
            RealityOperation::RawReceiveEvidence,
            CollectionAuthority::DirectSocket,
        )
        .is_ok()
    );
    assert!(
        validate_collection_authority(
            RealityOperation::RawReceiveEvidence,
            CollectionAuthority::DirectSocketOrPreparedPrivilegedForwarder,
        )
        .is_ok()
    );
    assert!(
        validate_collection_authority(
            RealityOperation::RawReceiveEvidence,
            CollectionAuthority::PreparedForwarder,
        )
        .is_err()
    );
}
