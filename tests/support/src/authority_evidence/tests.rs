use super::require_complete_worker_authority_evidence;

const CLEAN_RECORDS: &str = concat!(
    "authority-worker-evidence worker=0 direction=ClientToUpstream receive=9 send=8 completed=8 allocations=0 allocation_authority_mask=0x0 payload_copies=0 endpoint_normalizations=0 forbidden_authorities=0 forbidden_rmws=0 refcount_rmws=0 violation=0\n",
    "authority-worker-evidence worker=0 direction=UpstreamToClient receive=8 send=8 completed=8 allocations=0 allocation_authority_mask=0x0 payload_copies=0 endpoint_normalizations=0 forbidden_authorities=0 forbidden_rmws=0 refcount_rmws=0 violation=0\n",
);

#[test]
fn accepts_complete_clean_worker_pair() {
    assert!(require_complete_worker_authority_evidence(CLEAN_RECORDS, 1, 4).is_ok());
}

#[test]
fn rejects_missing_or_violating_worker_evidence() {
    assert!(require_complete_worker_authority_evidence("", 1, 4).is_err());
    let violating = CLEAN_RECORDS.replacen("refcount_rmws=0", "refcount_rmws=1", 1);
    assert!(require_complete_worker_authority_evidence(&violating, 1, 4).is_err());
    let violating_mask = CLEAN_RECORDS.replacen(
        "allocation_authority_mask=0x0",
        "allocation_authority_mask=0x1",
        1,
    );
    assert!(require_complete_worker_authority_evidence(&violating_mask, 1, 4).is_err());
}
