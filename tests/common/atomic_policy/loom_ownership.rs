use super::loom_ownership_tests::assert_exact_positive_loom_test_contracts;
use pkthere_test_support::test_paths as path_policy;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::common::source_layout_policy::{
    production_rust_source_paths_under as production_rust_sources,
    rust_source_paths_under as rust_sources,
};

pub(super) use super::loom_contract_types::{
    CallPattern, CoreBinding, CoreContractId, TransactionKind,
};
pub(super) use super::loom_syntax::{
    SyntaxFacts, calls_from_module, declared_resource_fields, defines_symbol,
    free_function_call_graph, has_forbidden_model_name, loom_test_names,
    positive_test_uses_registered_core, reachable_function_facts, syntax_facts,
};

const ATOMIC_CORE: &str = "src/atomic_core.rs";
const PRIMITIVE_LOOM_SOURCES: &[&str] = &[
    "src/atomic_core/loom_backend.rs",
    "src/atomic_core/loom_semantic_tests.rs",
];
const PRIMITIVE_LOOM_TESTS: &[(&str, &str)] = &[
    (
        "src/atomic_core/loom_semantic_tests.rs",
        "primitive_descriptor_revocation_ack_follows_cached_descriptor_drop",
    ),
    (
        "src/atomic_core/loom_semantic_tests.rs",
        "primitive_descriptor_unregister_publishes_only_after_descriptor_drop",
    ),
    (
        "src/atomic_core/loom_tests.rs",
        "primitive_writer_count_cannot_lose_a_concurrent_announcement",
    ),
    (
        "src/atomic_core/loom_tests.rs",
        "primitive_core_allocates_unique_bounded_tickets",
    ),
    (
        "src/atomic_core/loom_tests.rs",
        "primitive_core_rejects_stale_version_publication",
    ),
    (
        "src/atomic_core/loom_tests.rs",
        "primitive_lane_handshake_never_hides_an_admitted_reader_from_a_closed_gate",
    ),
    (
        "src/atomic_core/loom_tests.rs",
        "weakened_lane_store_and_scan_recreates_hidden_reader",
    ),
    (
        "src/atomic_core/loom_tests.rs",
        "primitive_epoch_lane_guard_releases_during_unwind",
    ),
    (
        "src/atomic_core/loom_tests.rs",
        "primitive_lane_drain_never_sleeps_past_the_last_reader_wake",
    ),
    (
        "src/atomic_core/loom_tests.rs",
        "primitive_activity_lane_never_exposes_a_mixed_epoch_and_tick",
    ),
    (
        "src/atomic_core/loom_tests.rs",
        "primitive_observation_publication_never_exposes_a_mixed_binding",
    ),
    (
        "src/atomic_core/loom_tests.rs",
        "primitive_wake_pending_clear_requires_authoritative_recheck",
    ),
    (
        "src/atomic_core/loom_tests.rs",
        "production_core_model_detects_weakened_release_publication",
    ),
];

const CORE_BINDINGS: &[CoreBinding] = &[
    CoreBinding::associated(
        CoreContractId::ReresolvePublication,
        "src/worker_support/reresolve_publication_loom.rs",
        "src/worker_support/reresolve_publication.rs",
        "ReresolvePublicationCore",
        "src/worker_support/lifecycle.rs",
        "ReresolvePublicationCore",
        "new",
    ),
    CoreBinding::free(
        CoreContractId::FlowClaimOwnership,
        "src/flow_claim/core_loom.rs",
        "src/flow_claim/core.rs",
        "reserve_flow_claim",
        "src/flow_claim.rs",
        CallPattern::free("reserve_flow_claim"),
    ),
    CoreBinding::calls(
        CoreContractId::AuditSlotPublication,
        "src/authority/worker_audit_core_loom.rs",
        "src/authority/worker_audit_core.rs",
        "AuditSlotPublicationCore",
        CallPattern::associated("Core", "new"),
        "src/authority/worker_audit.rs",
        CallPattern::associated("AuditSlotPublicationCore", "new"),
    ),
    CoreBinding::associated(
        CoreContractId::SingleConsumerTransfer,
        "src/authority/single_consumer_loom.rs",
        "src/authority/scopes.rs",
        "SingleConsumerBootstrap",
        "src/runtime_support.rs",
        "SingleConsumerBootstrap",
        "new",
    ),
    CoreBinding::associated(
        CoreContractId::AssociationState,
        "src/net/managed_socket/association_state_loom.rs",
        "src/net/managed_socket.rs",
        "AssociationAuthorityState",
        "src/net/managed_socket/api.rs",
        "AssociationAuthorityState",
        "new",
    ),
    CoreBinding::associated(
        CoreContractId::FlowTopologyTypestate,
        "src/flow_state/topology_typestate_loom.rs",
        "src/flow_state/topology_typestate.rs",
        "ReservedTopologyTransaction",
        "src/flow_state/topology.rs",
        "ReservedTopologyTransaction",
        "new",
    ),
    CoreBinding::calls(
        CoreContractId::SocketRetirementTypestate,
        "src/net/managed_socket/retirement_core_loom.rs",
        "src/net/managed_socket/retirement_core.rs",
        "SocketRetirementTransaction",
        CallPattern::free("retire_socket"),
        "src/net/managed_socket/association_reservation.rs",
        CallPattern::free("retire_socket"),
    ),
    CoreBinding::free(
        CoreContractId::IdleTransition,
        "src/atomic_core/loom_tests.rs",
        "src/atomic_core.rs",
        "attempt_idle_transition",
        "src/worker_support/lifecycle.rs",
        CallPattern::free("attempt_idle_transition"),
    ),
    CoreBinding::associated(
        CoreContractId::DescriptorCache,
        "src/atomic_core/loom_tests.rs",
        "src/atomic_core/descriptor_cache.rs",
        "DescriptorCacheCore",
        "src/net/managed_socket.rs",
        "DescriptorCacheCore",
        "new",
    ),
    CoreBinding::associated(
        CoreContractId::FlowSnapshotPublication,
        "src/atomic_core/loom_tests.rs",
        "src/atomic_core.rs",
        "FlowSnapshotPublicationCore",
        "src/flow_state/reservation.rs",
        "FlowSnapshotPublicationCore",
        "new",
    ),
    CoreBinding::free(
        CoreContractId::WaitReacquire,
        "src/authority/wait_core_loom.rs",
        "src/authority/wait_core.rs",
        "wait_reacquire",
        "src/authority/synchronization.rs",
        CallPattern::free("wait_reacquire"),
    ),
    CoreBinding::associated(
        CoreContractId::HandshakeCommit,
        "src/flow_state/handshake/commit_core_loom.rs",
        "src/flow_state/handshake/commit_core.rs",
        "HandshakeCommitCore",
        "src/flow_state/handshake.rs",
        "HandshakeCommitCore",
        "new",
    ),
    CoreBinding::associated(
        CoreContractId::ControlSend,
        "src/flow_state/handshake/control_send_core_loom.rs",
        "src/flow_state/session_lifecycles.rs",
        "ControlSendCore",
        "src/flow_state/handshake.rs",
        "ControlSendCore",
        "new",
    ),
    CoreBinding::associated(
        CoreContractId::ControlObservation,
        "src/flow_state/observation_core_loom.rs",
        "src/flow_state/observation_core.rs",
        "ObservationLifecycleCore",
        "src/flow_state/observations.rs",
        "ObservationLifecycleCore",
        "new",
    ),
    CoreBinding::associated(
        CoreContractId::ReceiveCandidateAck,
        "src/flow_state/receive_candidate_ack_loom.rs",
        "src/flow_state/session_lifecycles.rs",
        "ReceiveCandidateAckCore",
        "src/flow_state/session_state.rs",
        "ReceiveCandidateAckCore",
        "new",
    ),
    CoreBinding::associated(
        CoreContractId::RecoverySend,
        "src/flow_state/recovery_core_loom.rs",
        "src/flow_state/recovery_core.rs",
        "RecoverySendCore",
        "src/flow_state/runtime/recovery.rs",
        "RecoverySendCore",
        "new",
    ),
    CoreBinding::associated(
        CoreContractId::SyncPayload,
        "src/flow_state/sync_slot/sync_slot_loom.rs",
        "src/flow_state/sync_slot.rs",
        "SyncPayloadSlot",
        "src/flow_state/session_authority.rs",
        "SyncPayloadSlot",
        "default",
    ),
    CoreBinding::calls(
        CoreContractId::SendCompletion,
        "src/net/icmp_sequence/send_completion_loom.rs",
        "src/net/icmp_sequence/send_completion.rs",
        "SendCompletionCore",
        CallPattern::associated("SendCompletionCore", "new"),
        "src/net/icmp_sequence.rs",
        CallPattern::associated("ProductionCompletionCore", "new"),
    ),
    CoreBinding::associated(
        CoreContractId::FifoReservation,
        "src/net/sock_mgr/fifo_core_loom.rs",
        "src/net/sock_mgr/fifo_core.rs",
        "FifoReservationCore",
        "src/net/sock_mgr/transaction_lock.rs",
        "FifoReservationCore",
        "new",
    ),
    CoreBinding::calls(
        CoreContractId::GroupPublication,
        "src/net/sock_mgr/group_publication_loom.rs",
        "src/net/sock_mgr/group_publication.rs",
        "GroupPublicationCore",
        CallPattern::associated("GroupPublicationCore", "new"),
        "src/net/sock_mgr/manager_client_flow.rs",
        CallPattern::free("production_group_publication"),
    ),
    CoreBinding::associated(
        CoreContractId::TopologyReservationBatch,
        "src/net/managed_socket/topology_batch_loom.rs",
        "src/net/managed_socket/topology_batch.rs",
        "TopologyReservationBatch",
        "src/net/sock_mgr/manager_reresolve.rs",
        "TopologyReservationBatch",
        "try_with_capacity",
    ),
    CoreBinding::calls(
        CoreContractId::WorkerStateTransaction,
        "src/worker_support/cache/transaction_loom.rs",
        "src/worker_support/cache.rs",
        "WorkerStateTransaction",
        CallPattern::associated("WorkerStateTransaction", "run"),
        "src/worker_support/cache.rs",
        CallPattern::associated("WorkerStateTransaction", "run"),
    )
    .requiring_loom_calls(&[
        CallPattern::free("release_epoch_lane"),
        CallPattern::free("reacquire_expected_epoch_lane"),
    ]),
    CoreBinding::associated(
        CoreContractId::DiagnosticCapture,
        "src/stats/diagnostic_capture_loom.rs",
        "src/stats/diagnostic_capture.rs",
        "DiagnosticCaptureTransaction",
        "src/stats/render.rs",
        "DiagnosticCaptureTransaction",
        "run",
    ),
    CoreBinding::associated(
        CoreContractId::ReceiverTransfer,
        "src/net/sock_mgr/receiver_transfer_loom.rs",
        "src/net/sock_mgr/receiver_transfer.rs",
        "ReceiverTransferCore",
        "src/net/sock_mgr/receiver_slot.rs",
        "ReceiverTransferCore",
        "new",
    ),
    CoreBinding::associated(
        CoreContractId::ThreadOutcome,
        "src/shutdown_publication/loom_tests.rs",
        "src/shutdown_publication.rs",
        "ThreadOutcomeCore",
        "src/runtime_support.rs",
        "ThreadOutcomeCore",
        "new_worker",
    ),
    CoreBinding::associated(
        CoreContractId::ShutdownPublication,
        "src/shutdown_publication/loom_tests.rs",
        "src/shutdown_publication.rs",
        "ShutdownPublicationCore",
        "src/runtime_support.rs",
        "ShutdownPublicationCore",
        "new",
    ),
    CoreBinding::calls(
        CoreContractId::StatsFinality,
        "src/stats/finality_core_loom.rs",
        "src/stats/finality_core.rs",
        "StatsSealingTransaction",
        CallPattern::associated("StatsSealingTransaction", "begin"),
        "src/stats/recorder.rs",
        CallPattern::associated("StatsSealingTransaction", "begin"),
    ),
    CoreBinding::associated(
        CoreContractId::StatsQueuePublication,
        "src/stats/finality_core_loom.rs",
        "src/stats/finality_core.rs",
        "StatsFinalityCore",
        "src/stats/publication.rs",
        "StatsFinalityCore",
        "new",
    ),
    CoreBinding::associated(
        CoreContractId::StaleAssociationRetry,
        "src/worker_support/stale_association_loom.rs",
        "src/worker_support/stale_association.rs",
        "ObservedStaleRetry",
        "src/worker_support/client_process.rs",
        "ObservedStaleRetry",
        "new",
    ),
    CoreBinding::associated(
        CoreContractId::StableSend,
        "src/worker_support/stale_association_loom.rs",
        "src/worker_support/context.rs",
        "StableSendCore",
        "src/worker_support/dispatch.rs",
        "StableSendCore",
        "new",
    ),
    CoreBinding::associated(
        CoreContractId::Pacing,
        "src/atomic_core/pacing_loom.rs",
        "src/atomic_core/pacing.rs",
        "PacingCore",
        "src/worker_support/pacing.rs",
        "PacingCore",
        "new",
    ),
    CoreBinding::associated(
        CoreContractId::MaintenanceRepair,
        "src/atomic_core/loom_tests.rs",
        "src/atomic_core/maintenance_repair.rs",
        "MaintenanceRepairCore",
        "src/flow_state/runtime.rs",
        "MaintenanceRepairCore",
        "new",
    ),
];

pub(super) const fn core_bindings() -> &'static [CoreBinding] {
    CORE_BINDINGS
}

pub(super) const fn primitive_loom_tests() -> &'static [(&'static str, &'static str)] {
    PRIMITIVE_LOOM_TESTS
}

pub(super) fn assert_loom_cores_have_production_callers(root: &Path) {
    let parsed = parse_sources(root, &rust_sources(&[root.join("src")]));
    let registered_loom = CORE_BINDINGS
        .iter()
        .map(|binding| binding.loom_source)
        .chain(PRIMITIVE_LOOM_SOURCES.iter().copied())
        .collect::<BTreeSet<_>>();

    for (source, syntax) in &parsed {
        let has_loom = syntax_facts(syntax, false).loom_reference;
        assert!(
            !has_loom || registered_loom.contains(source.as_str()),
            "{source}: Loom evidence source is not registered to a production core"
        );
        assert!(
            !has_forbidden_model_name(syntax),
            "{source}: explanatory synchronization models cannot be release tests"
        );
    }

    for source in &registered_loom {
        let syntax = parsed
            .get(*source)
            .unwrap_or_else(|| panic!("registered Loom source is missing: {source}"));
        assert!(
            syntax_facts(syntax, false).loom_reference,
            "{source}: registered Loom source contains no parsed loom path"
        );
    }
    for binding in CORE_BINDINGS {
        assert_binding(&parsed, binding);
    }
    assert_lifecycle_catalog_owns_declared_fields(&parsed);
    assert_exact_positive_loom_test_contracts();
    super::ownership_typestate::assert_non_clone_ownership_typestate(&parsed);
    assert_atomic_core_calls_reach_production(root, &parsed);
}

pub(super) fn parse_sources(root: &Path, sources: &[PathBuf]) -> BTreeMap<String, syn::File> {
    sources
        .iter()
        .map(|source| {
            let relative = path_policy::render_repo_relative_path(root, source);
            let syntax = crate::common::rust_semantics::parse_file(source);
            (relative, syntax)
        })
        .collect()
}

fn assert_binding(parsed: &BTreeMap<String, syn::File>, binding: &CoreBinding) {
    let core = parsed
        .get(binding.core_source)
        .unwrap_or_else(|| panic!("missing production core {}", binding.core_source));
    assert!(
        defines_symbol(core, binding.core_symbol),
        "{} does not define registered production core {}",
        binding.core_source,
        binding.core_symbol
    );

    let production = parsed
        .get(binding.production_source)
        .unwrap_or_else(|| panic!("missing production caller {}", binding.production_source));
    assert!(
        syntax_facts(production, true).calls(binding.production_call),
        "{} has no non-test AST call to Loom-tested core {} through {:?}",
        binding.production_source,
        binding.core_symbol,
        binding.production_call
    );

    let transactions = binding.id.consuming_transactions();
    for transaction in transactions.into_iter().flatten() {
        assert!(
            crate::common::rust_semantics::parameter_is_consumed(
                core,
                transaction.function,
                transaction.parameter,
                matches!(transaction.kind, TransactionKind::Method),
            ),
            "{}::{} must consume `{}` for {:?}",
            binding.core_source,
            transaction.function,
            transaction.parameter,
            binding.id
        );
    }
}

fn assert_lifecycle_catalog_owns_declared_fields(parsed: &BTreeMap<String, syn::File>) {
    let catalog = parsed
        .get("src/authority/catalog/lifecycles.rs")
        .expect("production lifecycle ownership catalog");
    let resources = declared_resource_fields(catalog);
    assert!(
        !resources.is_empty(),
        "production lifecycle ownership catalog contains no physical resources"
    );
    for resource in resources {
        let owners = parsed
            .iter()
            .filter_map(|(source, syntax)| {
                let fields =
                    crate::common::rust_semantics::named_struct_fields(syntax, &resource.owner);
                (!fields.is_empty()).then_some((source, fields))
            })
            .collect::<Vec<_>>();
        assert_eq!(
            owners.len(),
            1,
            "{}::{:?}: lifecycle owner must resolve to exactly one production struct, found {:?}",
            resource.owner,
            resource.identity,
            owners.iter().map(|(source, _)| *source).collect::<Vec<_>>()
        );
        let (source, fields) = &owners[0];
        assert!(
            fields.contains(&resource.source_field),
            "{source}: {} does not physically own `{}` declared by {}",
            resource.owner,
            resource.source_field,
            resource.identity
        );
    }
}

fn assert_atomic_core_calls_reach_production(root: &Path, parsed: &BTreeMap<String, syn::File>) {
    let core = parsed
        .get(ATOMIC_CORE)
        .unwrap_or_else(|| panic!("missing {ATOMIC_CORE}"));
    let core_call_graph = free_function_call_graph(core);
    let core_functions = core_call_graph.keys().cloned().collect::<BTreeSet<_>>();
    let production_sources = production_rust_sources(&[root.join("src")])
        .iter()
        .map(|source| path_policy::render_repo_relative_path(root, source))
        .collect::<BTreeSet<_>>();
    let production_calls = parsed
        .iter()
        .filter(|(source, _)| {
            source.as_str() != ATOMIC_CORE && production_sources.contains(source.as_str())
        })
        .flat_map(|(_, syntax)| calls_from_module(syntax, &["crate", "atomic_core"], true))
        .collect::<BTreeSet<_>>();
    let mut production_reachable = production_calls
        .intersection(&core_functions)
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut pending = production_reachable.iter().cloned().collect::<Vec<_>>();
    while let Some(function) = pending.pop() {
        let Some(calls) = core_call_graph.get(&function) else {
            continue;
        };
        for called in calls.intersection(&core_functions) {
            if production_reachable.insert(called.clone()) {
                pending.push(called.clone());
            }
        }
    }

    for binding in CORE_BINDINGS.iter().filter(|binding| {
        binding.core_source.starts_with("src/atomic_core") && binding.loom_call.owner.is_none()
    }) {
        let loom_source = binding.loom_source;
        let loom = parsed
            .get(loom_source)
            .unwrap_or_else(|| panic!("missing atomic Loom source {loom_source}"));
        for test in binding.id.positive_tests() {
            let facts = reachable_function_facts(loom, test);
            let tested = primitive_calls(&facts)
                .filter(|function| core_functions.contains(*function))
                .cloned()
                .collect::<BTreeSet<_>>();
            assert!(
                !tested.is_empty(),
                "{loom_source}::{test}: no production primitive"
            );
            for function in tested {
                assert!(
                    production_reachable.contains(&function),
                    "{loom_source}::{test}: Loom-tested atomic core {function} is not reachable from a non-test production AST caller"
                );
            }
        }
    }
}

fn primitive_calls(facts: &SyntaxFacts) -> impl Iterator<Item = &String> {
    facts.free_calls.iter()
}
