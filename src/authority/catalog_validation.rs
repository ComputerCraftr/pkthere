use super::{
    ATOMIC_PROTOCOL_RECORDS, AUTHORITY_RECORDS, AtomicProtocolId, BLOCKING_CONTRACTS,
    BlockingClass, DiagnosticClass, DropClass, EffectSet, InterruptMechanism, InvariantId,
    LIFECYCLE_OWNERSHIP_RECORDS, LoomEvidenceClass, MemoryOrdering, NEGATIVE_CONTROL_EXPECTATIONS,
    OPERATION_RECORDS, OperationId, REFERENCE_COUNT_OWNERSHIP_RECORDS, ResourceIdentity,
    SHARED_RMW_RECORDS, TypeIdentity, WAIT_PROTOCOL_RECORDS, WAIT_RECORDS, WaitId, WatchdogOwner,
    tags,
};

pub(super) fn validate_extended_catalogs() -> Result<(), &'static str> {
    validate_atomic_protocols()?;
    validate_lifecycle_ownership()?;
    validate_blocking_contracts()?;
    validate_wait_protocols()?;
    validate_reference_counts()?;
    validate_loom_evidence()?;
    validate_operation_effects()?;
    validate_policy_domains()?;
    Ok(())
}

fn validate_loom_evidence() -> Result<(), &'static str> {
    let mut covered = [false; InvariantId::COUNT];
    for lifecycle in LIFECYCLE_OWNERSHIP_RECORDS {
        if lifecycle.loom_class != LoomEvidenceClass::ProductionCore {
            return Err("release Loom evidence is not a production core");
        }
        let index = lifecycle.invariant as usize;
        if covered[index] {
            return Err("duplicate production-core Loom evidence");
        }
        covered[index] = true;
    }
    if covered.into_iter().any(|present| !present) {
        return Err("lifecycle lacks registered production-core Loom evidence");
    }
    if NEGATIVE_CONTROL_EXPECTATIONS.is_empty() {
        return Err("negative-control registry is empty");
    }
    for expectation in NEGATIVE_CONTROL_EXPECTATIONS {
        if !covered[expectation.invariant as usize]
            || (expectation.offending_edge.is_none()
                && expectation.resource.is_none()
                && expectation.bad_terminal_state.is_none())
        {
            return Err("negative control lacks exact invariant failure identity");
        }
        let _identity = (
            expectation.diagnostic_class,
            expectation.source,
            expectation.offending_edge,
            expectation.resource,
            expectation.bad_terminal_state,
        );
    }
    Ok(())
}

fn validate_wait_protocols() -> Result<(), &'static str> {
    let mut seen = [false; WaitId::COUNT];
    for protocol in WAIT_PROTOCOL_RECORDS {
        let index = protocol.wait as usize;
        if seen[index] {
            return Err("duplicate wait protocol record");
        }
        if !WAIT_RECORDS.iter().any(|record| record.id == protocol.wait)
            || !LIFECYCLE_OWNERSHIP_RECORDS
                .iter()
                .any(|record| record.invariant == protocol.loom_invariant)
        {
            return Err("wait protocol lacks its wait or actual-core lifecycle evidence");
        }
        let methods = [
            protocol.predicate_read,
            protocol.waiter_registration,
            protocol.post_registration_recheck,
            protocol.notification,
            protocol.cancellation,
            protocol.teardown,
        ];
        if methods.windows(2).all(|pair| pair[0] == pair[1])
            && protocol.notification == protocol.waiter_registration
        {
            return Err("wait protocol does not distinguish waiter and waker ownership");
        }
        seen[index] = true;
    }
    if seen.into_iter().any(|present| !present) {
        return Err("wait protocol record is missing");
    }
    Ok(())
}

fn validate_policy_domains() -> Result<(), &'static str> {
    for record in AUTHORITY_RECORDS {
        let _policy = record.instance_policy();
        if super::AuthorityId::from_index(record.id as usize) != Some(record.id) {
            return Err("authority instance-key index mapping is incomplete");
        }
    }
    let blocking_classes = [
        BlockingClass::Nonblocking,
        BlockingClass::BoundedByDeadline,
        BlockingClass::KernelBoundedFallback,
        BlockingClass::PotentiallyUninterruptible,
    ];
    let watchdogs = [
        WatchdogOwner::RuntimeSupervisor,
        WatchdogOwner::ParentProcess,
    ];
    let interrupts = [
        InterruptMechanism::NoneRequired,
        InterruptMechanism::WakeDescriptor,
        InterruptMechanism::ConditionVariableNotification,
        InterruptMechanism::ProcessTermination,
    ];
    let drop_classes = [
        DropClass::Trivial,
        DropClass::BoundedInfallible,
        DropClass::AuthorityCleanup,
        DropClass::PotentiallyAllocating,
        DropClass::PotentiallyBlocking,
        DropClass::UnboundedContainer,
    ];
    let loom_classes = [
        LoomEvidenceClass::ProductionCore,
        LoomEvidenceClass::PrimitiveOnly,
        LoomEvidenceClass::NegativeControl,
        LoomEvidenceClass::ExplanatoryModel,
    ];
    let diagnostic_classes = [
        DiagnosticClass::AuthorityEdge,
        DiagnosticClass::ResourceOwnership,
        DiagnosticClass::BadTerminalState,
    ];
    let bad_states = [
        super::BadStateId::StrandedDeferredControl,
        super::BadStateId::MixedReresolvePublication,
    ];
    if blocking_classes.len() != 4
        || watchdogs.len() != 2
        || interrupts.len() != 4
        || drop_classes.len() != 6
        || loom_classes.len() != 4
        || diagnostic_classes.len() != 3
        || bad_states.len() != 2
    {
        return Err("authority policy domain inventory is incomplete");
    }
    Ok(())
}

fn validate_atomic_protocols() -> Result<(), &'static str> {
    let mut seen = [false; AtomicProtocolId::COUNT];
    for record in ATOMIC_PROTOCOL_RECORDS {
        let index = record.id as usize;
        if seen[index] {
            return Err("duplicate atomic protocol record");
        }
        if record.state_encoding.is_empty()
            || record.allowed_orderings.is_empty()
            || record.allowed_authorities.is_empty()
        {
            return Err("atomic protocol state or ordering contract is empty");
        }
        if record.allowed_authorities.iter().any(|authority| {
            !AUTHORITY_RECORDS
                .iter()
                .any(|registered| registered.id == *authority)
        }) {
            return Err("atomic protocol references an unregistered authority");
        }
        if record.allowed_writers.is_empty()
            || record.allowed_readers.is_empty()
            || record.linearization_points.is_empty()
        {
            return Err("atomic protocol reader/writer ownership is incomplete");
        }
        for transition in record.allowed_transitions {
            if transition.from.is_empty()
                || transition.to.is_empty()
                || !record.allowed_writers.contains(&transition.linearization)
                || !record
                    .linearization_points
                    .contains(&transition.linearization)
            {
                return Err("atomic transition lacks its registered writer linearization point");
            }
        }
        if record.allowed_orderings.contains(&MemoryOrdering::SeqCst)
            && !record.loom_invariants.is_empty()
        {
            return Err("Loom-backed protocol cannot depend on true sequential consistency");
        }
        seen[index] = true;
    }
    if seen.into_iter().any(|present| !present) {
        return Err("atomic protocol record is missing");
    }
    for tag in tags::RECORDS {
        let protocol = super::atomic_protocol_for_authority(tag.id);
        if !ATOMIC_PROTOCOL_RECORDS
            .iter()
            .any(|record| record.id == protocol && record.allowed_authorities.contains(&tag.id))
        {
            return Err("authority tag references an incompatible atomic protocol");
        }
    }
    for rmw in SHARED_RMW_RECORDS {
        if !ATOMIC_PROTOCOL_RECORDS
            .iter()
            .any(|record| record.id == rmw.protocol)
            || !AUTHORITY_RECORDS
                .iter()
                .any(|record| record.id == rmw.authority)
        {
            return Err("shared RMW references an unregistered protocol or authority");
        }
    }
    Ok(())
}

fn validate_lifecycle_ownership() -> Result<(), &'static str> {
    let mut seen = [false; InvariantId::COUNT];
    for record in LIFECYCLE_OWNERSHIP_RECORDS {
        let index = record.invariant as usize;
        if seen[index] {
            return Err("duplicate lifecycle ownership invariant");
        }
        if record.resources.is_empty()
            || record.mutation_methods.is_empty()
            || record.terminal_methods.is_empty()
            || record.runtime_entry_points.is_empty()
            || record.loom_entry_points.is_empty()
        {
            return Err("lifecycle ownership contract is incomplete");
        }
        for resource in record.resources {
            match resource {
                ResourceIdentity::OwnedField { owner, .. } if *owner != record.owner => {
                    return Err("lifecycle record claims a field owned by another type");
                }
                ResourceIdentity::OwnedField {
                    source_field: "", ..
                } => {
                    return Err("lifecycle resource lacks its canonical Rust field name");
                }
                ResourceIdentity::ExclusiveLease { lease, .. } if *lease != record.owner => {
                    return Err("lifecycle record claims another owner's exclusive lease");
                }
                ResourceIdentity::AtomicProtocol(protocol)
                    if !ATOMIC_PROTOCOL_RECORDS.iter().any(|candidate| {
                        candidate.id == *protocol && candidate.owner == record.owner
                    }) =>
                {
                    return Err("lifecycle record claims an atomic protocol owned elsewhere");
                }
                _ => {}
            }
        }
        if !record
            .terminal_methods
            .iter()
            .all(|method| record.mutation_methods.contains(method))
        {
            return Err("lifecycle terminal method is outside its mutation surface");
        }
        seen[index] = true;
    }
    if seen.into_iter().any(|present| !present) {
        return Err("lifecycle ownership invariant is missing");
    }
    let group = LIFECYCLE_OWNERSHIP_RECORDS
        .iter()
        .find(|record| record.invariant == InvariantId::GroupPublication)
        .ok_or("group publication lifecycle is missing")?;
    for required in [
        TypeIdentity::DescriptorOwner,
        TypeIdentity::ManagedReceiver,
        TypeIdentity::ManagerMetadata,
        TypeIdentity::FlowSnapshot,
    ] {
        if !group.resources.iter().any(|resource| {
            matches!(resource, ResourceIdentity::ExclusiveLease { resource_type, .. } if *resource_type == required)
        }) {
            return Err("group publication does not own its complete staged resource bundle");
        }
    }
    Ok(())
}

fn validate_blocking_contracts() -> Result<(), &'static str> {
    let mut seen = [false; OperationId::COUNT];
    for contract in BLOCKING_CONTRACTS {
        let index = contract.operation as usize;
        if seen[index] {
            return Err("duplicate blocking contract");
        }
        let operation = OPERATION_RECORDS
            .iter()
            .find(|record| record.id == contract.operation)
            .ok_or("blocking contract references an unknown operation")?;
        if !operation.blocking || contract.blocking_class == BlockingClass::Nonblocking {
            return Err("blocking contract disagrees with the operation catalog");
        }
        if matches!(
            contract.blocking_class,
            BlockingClass::KernelBoundedFallback | BlockingClass::PotentiallyUninterruptible
        ) && (contract.watchdog_owner != WatchdogOwner::ParentProcess
            || contract.interrupt_mechanism != InterruptMechanism::ProcessTermination)
        {
            return Err("kernel fallback lacks an external process watchdog contract");
        }
        seen[index] = true;
    }
    for operation in OPERATION_RECORDS {
        if operation.blocking != seen[operation.id as usize] {
            return Err("blocking operation lacks exactly one deadline-owner contract");
        }
    }
    Ok(())
}

fn validate_reference_counts() -> Result<(), &'static str> {
    if REFERENCE_COUNT_OWNERSHIP_RECORDS.is_empty() {
        return Err("reference-count ownership catalog is empty");
    }
    for record in REFERENCE_COUNT_OWNERSHIP_RECORDS {
        if record.clone_methods.is_empty() && record.upgrade_methods.is_empty() {
            return Err("reference-count wrapper has no registered ownership operation");
        }
        if matches!(
            record.final_drop_class,
            DropClass::PotentiallyAllocating
                | DropClass::PotentiallyBlocking
                | DropClass::UnboundedContainer
        ) && !record.permitted_authorities.is_empty()
        {
            return Err("potentially unbounded final reference drop is permitted under authority");
        }
        if record.retirement_owner != record.final_drop_owner
            && record.final_drop_class != DropClass::BoundedInfallible
        {
            return Err("complex final reference drop is detached from its retirement owner");
        }
    }
    let finalization = OPERATION_RECORDS
        .iter()
        .find(|record| record.id == OperationId::RefcountFinalize)
        .ok_or("reference-count finalization operation is missing")?;
    if finalization.effects.contains(EffectSet::MAY_DROP_UNBOUNDED)
        || finalization.effects.contains(EffectSet::MAY_BLOCK)
    {
        return Err("reference-count finalization has an unbounded effect");
    }
    Ok(())
}

fn validate_operation_effects() -> Result<(), &'static str> {
    for operation in OPERATION_RECORDS {
        if !EffectSet::ALL.contains(operation.effects) {
            return Err("operation contains an unknown effect bit");
        }
        if operation.blocking && !operation.effects.contains(EffectSet::MAY_BLOCK) {
            return Err("blocking operation omits MAY_BLOCK from its effect set");
        }
    }
    Ok(())
}
