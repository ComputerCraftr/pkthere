use super::audit;
use super::{
    AUTHORITY_RECORDS, AuthorityId, BLOCKING_EDGES, COHOLD_RULES,
    EMERGENCY_EXPECTED_INSTANCE_SHIFT, EMERGENCY_EXPECTED_SHIFT, EMERGENCY_INSTANCE_MASK,
    EMERGENCY_KIND_MASK, EMERGENCY_MISSING_ORDINAL, EMERGENCY_OBSERVED_INSTANCE_SHIFT,
    EMERGENCY_OBSERVED_SHIFT, OPERATION_RECORDS, OPERATION_REQUIREMENTS, OperationId,
    PUBLICATION_RECORDS, PublicationId, SHARED_RMW_RECORDS, SharedRmwId, ThreadOwned, WAIT_RECORDS,
    WaitId, tags,
};
use std::fmt;

pub(crate) struct EmergencyFailureSource;

impl crate::shutdown_publication::EmergencyFailureSource for EmergencyFailureSource {
    fn load_acquire(&self) -> u64 {
        audit::emergency_failure_code()
    }
}

pub(crate) const fn emergency_failure_source() -> EmergencyFailureSource {
    EmergencyFailureSource
}

pub(crate) struct EmergencyFailureReport(u64);

impl fmt::Display for EmergencyFailureReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = self.0;
        let kind = code & EMERGENCY_KIND_MASK;
        let expected = (code >> EMERGENCY_EXPECTED_SHIFT) & EMERGENCY_KIND_MASK;
        let observed = (code >> EMERGENCY_OBSERVED_SHIFT) & EMERGENCY_KIND_MASK;
        if kind == 1 {
            let expected_authority = AuthorityId::from_index(expected as usize);
            let observed_authority = (observed != EMERGENCY_MISSING_ORDINAL)
                .then(|| AuthorityId::from_index(observed as usize))
                .flatten();
            let expected_instance =
                (code >> EMERGENCY_EXPECTED_INSTANCE_SHIFT) & EMERGENCY_INSTANCE_MASK;
            let observed_instance =
                (code >> EMERGENCY_OBSERVED_INSTANCE_SHIFT) & EMERGENCY_INSTANCE_MASK;
            write!(
                formatter,
                "authority release mismatch expected={expected_authority:?} instance={expected_instance} observed={observed_authority:?} instance={observed_instance} code={code}"
            )
        } else if kind == 2 {
            write!(
                formatter,
                "operation release mismatch expected_ordinal={expected} observed_ordinal={observed} code={code}"
            )
        } else {
            write!(formatter, "unknown authority audit emergency code {code}")
        }
    }
}

pub(crate) const fn emergency_failure_report(code: u64) -> EmergencyFailureReport {
    EmergencyFailureReport(code)
}

pub(crate) fn emergency_failure_code() -> u64 {
    crate::shutdown_publication::EmergencyFailureSource::load_acquire(&emergency_failure_source())
}

pub(crate) fn validate_catalog() -> Result<(), &'static str> {
    super::catalog_validation::validate_extended_catalogs()?;
    ThreadOwned::<tags::WaitCoordination, ()>::new(()).into_inner();
    if tags::RECORDS.len() != AuthorityId::COUNT {
        return Err("sealed authority-tag inventory is incomplete");
    }
    let mut seen = [false; AuthorityId::COUNT];
    for record in AUTHORITY_RECORDS {
        let index = record.id as usize;
        if seen[index] {
            return Err("duplicate authority record");
        }
        if record.instance_rule.is_empty()
            || record.invalidation.is_empty()
            || record.publication.is_empty()
        {
            return Err("authority contract is incomplete");
        }
        seen[index] = true;
    }
    if seen.into_iter().any(|present| !present) {
        return Err("authority record is missing");
    }
    let mut tag_seen = [false; AuthorityId::COUNT];
    for tag_record in tags::RECORDS {
        let index = tag_record.id as usize;
        if tag_seen[index] {
            return Err("sealed authority tags share one authority ID");
        }
        let Some(catalog_record) = AUTHORITY_RECORDS
            .iter()
            .find(|record| record.id == tag_record.id)
        else {
            return Err("sealed authority tag lacks a catalog record");
        };
        if tag_record != catalog_record {
            return Err("sealed authority tag disagrees with its catalog record");
        }
        tag_seen[index] = true;
    }
    if tag_seen.into_iter().any(|present| !present) {
        return Err("authority ID lacks a sealed tag");
    }
    if WAIT_RECORDS
        .iter()
        .any(|record| !record.bounded || !record.shutdown_wake || record.waker.is_empty())
    {
        return Err("wait contract is incomplete");
    }
    let mut wait_seen = [false; WaitId::COUNT];
    for record in WAIT_RECORDS {
        if wait_seen[record.id as usize] {
            return Err("duplicate wait contract");
        }
        wait_seen[record.id as usize] = true;
    }
    if wait_seen.into_iter().any(|present| !present) {
        return Err("wait contract is missing");
    }
    if PUBLICATION_RECORDS.iter().any(|record| {
        record.linearization.is_empty()
            || record.ordering.is_empty()
            || record.overflow.is_empty()
            || record.aba_prevention.is_empty()
            || record.shutdown_interaction.is_empty()
            || !record.stale_rejected
    }) {
        return Err("publication contract is incomplete");
    }
    let mut publication_seen = [false; PublicationId::COUNT];
    for record in PUBLICATION_RECORDS {
        if publication_seen[record.id as usize] {
            return Err("duplicate publication contract");
        }
        publication_seen[record.id as usize] = true;
    }
    if publication_seen.into_iter().any(|present| !present) {
        return Err("publication contract is missing");
    }
    let mut operation_seen = [false; OperationId::COUNT];
    for record in OPERATION_RECORDS {
        if operation_seen[record.id as usize] {
            return Err("duplicate implicit operation scope");
        }
        operation_seen[record.id as usize] = true;
    }
    if operation_seen.into_iter().any(|present| !present)
        || OPERATION_RECORDS.iter().any(|record| {
            matches!(
                record.id,
                OperationId::SocketSend | OperationId::SocketReceive
            ) && record.blocking
        })
    {
        return Err("implicit operation-scope catalog is incomplete");
    }
    let mut operation_requirement_seen = [false; OperationId::COUNT];
    for requirement in OPERATION_REQUIREMENTS {
        let index = requirement.operation as usize;
        if operation_requirement_seen[index] {
            return Err("operation has duplicate required-authority contracts");
        }
        if !AUTHORITY_RECORDS
            .iter()
            .any(|record| record.id == requirement.authority)
        {
            return Err("operation requires an unregistered authority");
        }
        operation_requirement_seen[index] = true;
    }
    let mut rmw_seen = [false; SharedRmwId::COUNT];
    for record in SHARED_RMW_RECORDS {
        if record.contract.is_empty() || rmw_seen[record.id as usize] {
            return Err("invalid or duplicate shared-RMW contract");
        }
        rmw_seen[record.id as usize] = true;
    }
    if rmw_seen.into_iter().any(|present| !present) {
        return Err("shared-RMW contract is missing");
    }

    let mut indegree = [0_u8; AuthorityId::COUNT];
    let mut adjacency = [[false; AuthorityId::COUNT]; AuthorityId::COUNT];
    for edge in BLOCKING_EDGES {
        let from = edge.from as usize;
        let to = edge.to as usize;
        if from == to || adjacency[from][to] {
            return Err("invalid or duplicate blocking edge");
        }
        adjacency[from][to] = true;
        indegree[to] = indegree[to]
            .checked_add(1)
            .ok_or("authority graph indegree overflow")?;
        if !COHOLD_RULES
            .iter()
            .any(|rule| rule.held == edge.from && rule.acquired == edge.to)
        {
            return Err("blocking edge lacks an explicit co-hold rule");
        }
    }
    let mut removed = 0_usize;
    let mut pending = [true; AuthorityId::COUNT];
    loop {
        let mut progressed = false;
        for node in 0..AuthorityId::COUNT {
            if !pending[node] || indegree[node] != 0 {
                continue;
            }
            pending[node] = false;
            removed += 1;
            progressed = true;
            for target in 0..AuthorityId::COUNT {
                if adjacency[node][target] {
                    indegree[target] -= 1;
                }
            }
        }
        if !progressed {
            break;
        }
    }
    if removed != AuthorityId::COUNT {
        return Err("blocking authority graph contains a cycle");
    }

    let mut reachable = adjacency;
    for intermediate in 0..AuthorityId::COUNT {
        for from in 0..AuthorityId::COUNT {
            for to in 0..AuthorityId::COUNT {
                reachable[from][to] |= reachable[from][intermediate] && reachable[intermediate][to];
            }
        }
    }
    let mut cohold_seen = [[false; AuthorityId::COUNT]; AuthorityId::COUNT];
    for rule in COHOLD_RULES {
        let held = rule.held as usize;
        let acquired = rule.acquired as usize;
        if cohold_seen[held][acquired] {
            return Err("duplicate co-hold rule");
        }
        cohold_seen[held][acquired] = true;
        if held != acquired && !reachable[held][acquired] {
            return Err("co-hold rule contradicts the transitive authority order");
        }
        if held != acquired && reachable[acquired][held] {
            return Err("co-hold rule permits a transitive authority inversion");
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn is_held_for_test(id: AuthorityId) -> bool {
    audit::is_held(id)
}

#[cfg(test)]
pub(crate) fn acquisition_count_for_test(id: AuthorityId) -> u64 {
    audit::acquisition_count(id)
}

#[cfg(test)]
pub(crate) fn shared_rmw_count_for_test(id: AuthorityId) -> u64 {
    audit::shared_rmw_count(id)
}

#[cfg(test)]
pub(crate) fn wait_count_for_test(id: WaitId) -> u64 {
    audit::wait_count(id)
}

#[cfg(test)]
pub(crate) fn operation_count_for_test(id: OperationId) -> u64 {
    audit::operation_count(id)
}

#[cfg(test)]
pub(crate) fn allocation_violation_count_for_test() -> u64 {
    audit::allocation_violation_count()
}

#[cfg(test)]
pub(crate) fn allocation_violation_count_for_authority_for_test(id: AuthorityId) -> u64 {
    audit::allocation_violation_count_for_authority(id)
}
