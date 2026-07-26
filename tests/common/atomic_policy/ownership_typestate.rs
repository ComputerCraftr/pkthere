use std::collections::{BTreeMap, BTreeSet};
use syn::visit::Visit;

const NON_CLONE_OWNERS: &[(&str, &str)] = &[
    (
        "src/shutdown_publication.rs",
        "WorkerTerminationTransaction",
    ),
    (
        "src/shutdown_publication.rs",
        "ShutdownSupervisionTransaction",
    ),
    ("src/flow_state/topology.rs", "FlowTopologyReadLease"),
    ("src/flow_state/topology.rs", "FlowTopologyWriteReservation"),
    ("src/flow_state/topology.rs", "ResetReceipt"),
    (
        "src/flow_state/reservation.rs",
        "ClientFlowSocketTransitionsApplied",
    ),
    (
        "src/flow_state/reservation.rs",
        "PreparedClientFlowTopology",
    ),
    (
        "src/flow_state/reservation.rs",
        "CommittedClientFlowTopology",
    ),
    ("src/flow_claim.rs", "FlowClaim"),
    ("src/flow_claim.rs", "CommittedFlowClaim"),
    ("src/flow_state/observations.rs", "ControlObservationGuard"),
    (
        "src/flow_state/observations.rs",
        "ControlObservationReservation",
    ),
    ("src/worker_support/context.rs", "StableForwardPermit"),
    ("src/flow_state.rs", "ClientCandidateAckLease"),
    ("src/flow_state.rs", "ReplyIdControlSendLease"),
    ("src/flow_state.rs", "ReplyIdHandshakeCommitToken"),
    ("src/flow_state/session_lifecycles.rs", "ControlSendAttempt"),
    (
        "src/flow_state/session_lifecycles.rs",
        "ReceiveCandidateAckPermit",
    ),
    (
        "src/flow_state/session_state.rs",
        "RecoveryPayloadSendToken",
    ),
    ("src/flow_state/recovery_core.rs", "RecoverySendLease"),
    ("src/flow_state/sync_slot.rs", "SyncSendLease"),
    (
        "src/flow_state/handshake/commit_core.rs",
        "HandshakeManagerReceipt",
    ),
    (
        "src/flow_state/handshake/commit_core.rs",
        "HandshakeActivationLease",
    ),
    (
        "src/flow_state/handshake/commit_core.rs",
        "HandshakePayloadLease",
    ),
    ("src/net/sock_mgr/fifo_core.rs", "FifoReservationLease"),
    ("src/net/managed_socket.rs", "TopologyAuthorityLease"),
    ("src/net/managed_socket.rs", "ActiveIoGuard"),
    ("src/net/managed_socket.rs", "ManagedSendLease"),
    ("src/net/managed_socket.rs", "ManagedReceiver"),
    ("src/net/managed_socket.rs", "TopologyReservation"),
    (
        "src/net/managed_socket/retirement_core.rs",
        "SocketRetirementTransaction",
    ),
    (
        "src/net/managed_socket/retirement_core.rs",
        "RetiredSocketTransaction",
    ),
    (
        "src/net/managed_socket/retirement_core.rs",
        "ReplacementBoundSocketTransaction",
    ),
    (
        "src/flow_state/topology_typestate.rs",
        "ReservedTopologyTransaction",
    ),
    (
        "src/flow_state/topology_typestate.rs",
        "SocketTransitionsAppliedTopology",
    ),
    ("src/flow_state/topology_typestate.rs", "PreparedTopology"),
    (
        "src/flow_state/topology_typestate.rs",
        "SessionCommittedTopology",
    ),
    ("src/stats/finality_core.rs", "StatsSealingTransaction"),
    ("src/authority/scopes.rs", "SingleConsumerBootstrap"),
    (
        "src/authority/worker_audit_core.rs",
        "AuditSlotPublicationCore",
    ),
    ("src/net/sock_mgr/receiver_slot.rs", "ReceiverClaim"),
    ("src/net/sock_mgr/version.rs", "VersionCapacityGuard"),
    (
        "src/net/sock_mgr/manager_reresolve.rs",
        "GroupTopologyReservations",
    ),
    (
        "src/net/sock_mgr/transaction_lock.rs",
        "ManagerTransactionGuard",
    ),
];

const FIELD_TYPE_CONTRACTS: &[(&str, &str, &str, &str)] = &[
    (
        "src/flow_state.rs",
        "ReplyIdControlSendLease",
        "attempt",
        "ControlSendAttempt",
    ),
    (
        "src/flow_state.rs",
        "ClientCandidateAckLease",
        "permit",
        "ReceiveCandidateAckPermit",
    ),
    (
        "src/net/sock_mgr/transaction_lock.rs",
        "ManagerTransactionGuard",
        "lease",
        "FifoReservationLease",
    ),
    (
        "src/flow_state/recovery_core.rs",
        "RecoverySendLease",
        "token",
        "RecoveryPayloadSendToken",
    ),
    (
        "src/flow_state/topology_typestate.rs",
        "SessionCommittedTopology",
        "receipt",
        "Receipt",
    ),
    (
        "src/net/managed_socket/retirement_core.rs",
        "RetiredSocketTransaction",
        "owner",
        "Owner",
    ),
    (
        "src/net/managed_socket/retirement_core.rs",
        "ReplacementBoundSocketTransaction",
        "owner",
        "Owner",
    ),
    (
        "src/stats/finality_core.rs",
        "StatsSealingTransaction",
        "owner",
        "Owner",
    ),
    (
        "src/authority/scopes.rs",
        "SingleConsumerBootstrap",
        "value",
        "T",
    ),
    (
        "src/authority/worker_audit_core.rs",
        "AuditSlotPublicationCore",
        "payload",
        "Payload",
    ),
    ("src/flow_claim.rs", "FlowClaim", "table", "FlowClaimTable"),
    (
        "src/flow_claim.rs",
        "CommittedFlowClaim",
        "table",
        "FlowClaimTable",
    ),
];

const RETURN_TYPE_CONTRACTS: &[(&str, &str, &str, &str)] = &[
    (
        "src/flow_state/session_lifecycles.rs",
        "ControlSendCore",
        "lease_due",
        "ControlSendAttempt",
    ),
    (
        "src/flow_state/session_lifecycles.rs",
        "ReceiveCandidateAckTransaction",
        "begin_send",
        "ReceiveCandidateAckPermit",
    ),
];

pub(super) fn assert_non_clone_ownership_typestate(parsed: &BTreeMap<String, syn::File>) {
    for (source, owner) in NON_CLONE_OWNERS {
        let item = find_struct(parsed, source, owner);
        let derives = derived_traits(&item.attrs);
        assert!(
            derives.is_disjoint(&BTreeSet::from(["Clone".into(), "Copy".into()])),
            "{source}: ownership-bearing `{owner}` must not derive Clone or Copy; found {derives:?}",
        );
    }

    for (source, owner, field, required_type) in FIELD_TYPE_CONTRACTS {
        let item = find_struct(parsed, source, owner);
        let ty = item
            .fields
            .iter()
            .find(|candidate| candidate.ident.as_ref().is_some_and(|ident| ident == field))
            .map(|candidate| &candidate.ty)
            .unwrap_or_else(|| panic!("{source}: `{owner}` has no `{field}` ownership field"));
        assert!(
            type_references(ty, required_type),
            "{source}: `{owner}.{field}` must own `{required_type}` rather than copied metadata",
        );
    }

    for (source, owner, method, required_type) in RETURN_TYPE_CONTRACTS {
        let syntax = parsed
            .get(*source)
            .unwrap_or_else(|| panic!("missing typestate source {source}"));
        let output = syntax.items.iter().find_map(|item| {
            let syn::Item::Impl(item) = item else {
                return None;
            };
            if crate::common::rust_semantics::type_name(&item.self_ty).as_deref() != Some(*owner) {
                return None;
            }
            item.items.iter().find_map(|item| match item {
                syn::ImplItem::Fn(function) if function.sig.ident == *method => {
                    Some(&function.sig.output)
                }
                _ => None,
            })
        });
        let syn::ReturnType::Type(_, ty) = output.unwrap_or_else(|| {
            panic!("{source}: `{owner}::{method}` has no typed ownership result")
        }) else {
            panic!("{source}: `{owner}::{method}` must return `{required_type}`")
        };
        assert!(
            type_references(ty, required_type),
            "{source}: `{owner}::{method}` must return `{required_type}`",
        );
    }

    for (source, syntax) in parsed {
        let mut calls = MethodCallFinder::default();
        calls.visit_file(syntax);
        if source != "src/net/managed_socket/association_reservation.rs"
            && source != "src/net/managed_socket/retirement_core.rs"
        {
            for method in [
                "mark_replacement_bound",
                "retire_descriptor_for_replacement",
                "publish_retired",
                "retire_descriptor",
                "bind_replacement",
                "publish_retirement",
            ] {
                assert!(
                    !calls.names.contains(method),
                    "{source}: `{method}` bypasses the consuming socket-retirement transaction",
                );
            }
        }
        if source != "src/flow_state/topology.rs"
            && source != "src/flow_state/topology_typestate.rs"
        {
            for method in [
                "apply_socket_transitions",
                "prepare_manager_state",
                "commit_session_state",
                "publish_manager_state",
                "publish_committed_state",
            ] {
                assert!(
                    !calls.names.contains(method),
                    "{source}: `{method}` bypasses the consuming flow-topology transaction",
                );
            }
        }
    }
}

#[derive(Default)]
struct MethodCallFinder {
    names: BTreeSet<String>,
}

impl<'ast> Visit<'ast> for MethodCallFinder {
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.names.insert(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = call.func.as_ref()
            && let Some(segment) = path.path.segments.last()
        {
            self.names.insert(segment.ident.to_string());
        }
        syn::visit::visit_expr_call(self, call);
    }
}

fn find_struct<'a>(
    parsed: &'a BTreeMap<String, syn::File>,
    source: &str,
    owner: &str,
) -> &'a syn::ItemStruct {
    parsed
        .get(source)
        .unwrap_or_else(|| panic!("missing ownership source {source}"))
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Struct(item) if item.ident == owner => Some(item),
            _ => None,
        })
        .unwrap_or_else(|| panic!("{source}: missing ownership type `{owner}`"))
}

fn derived_traits(attrs: &[syn::Attribute]) -> BTreeSet<String> {
    let mut derived = BTreeSet::new();
    for attr in attrs.iter().filter(|attr| attr.path().is_ident("derive")) {
        attr.parse_nested_meta(|meta| {
            if let Some(segment) = meta.path.segments.last() {
                derived.insert(segment.ident.to_string());
            }
            Ok(())
        })
        .expect("derive attribute must parse");
    }
    derived
}

fn type_references(ty: &syn::Type, required: &str) -> bool {
    struct References<'a> {
        required: &'a str,
        found: bool,
    }

    impl<'ast> Visit<'ast> for References<'_> {
        fn visit_type_path(&mut self, path: &'ast syn::TypePath) {
            self.found |= path
                .path
                .segments
                .iter()
                .any(|segment| segment.ident == self.required);
            syn::visit::visit_type_path(self, path);
        }
    }

    let mut references = References {
        required,
        found: false,
    };
    references.visit_type(ty);
    references.found
}

#[test]
fn non_clone_owner_check_uses_derive_ast() {
    let clone_owner = syn::parse_file("#[derive(Debug, Clone)] struct Lease { token: u64 }")
        .expect("parse clone fixture");
    let item = clone_owner.items.iter().find_map(|item| match item {
        syn::Item::Struct(item) => Some(item),
        _ => None,
    });
    assert!(
        derived_traits(&item.expect("fixture owner").attrs).contains("Clone"),
        "negative fixture must prove comments and variable names cannot hide Clone ownership",
    );
}
