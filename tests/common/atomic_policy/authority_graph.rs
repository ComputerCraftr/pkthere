use super::attrs_are_test_context;
use super::authority_ownership::{
    assert_consuming_flow_reservation_shape, assert_thread_owned_recorder_shape, named_struct,
};
use pkthere_test_support::test_paths as path_policy;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::common::source_layout_policy::{
    production_rust_source_paths_under as production_rust_sources,
    rust_source_paths_under as rust_sources,
};

const STABLE_SEND_ROOTS: [&str; 6] = [
    "send_user_payload_event",
    "send_user_payload_event_once",
    "send_payload_event_now_stable",
    "send_payload_event_now_with_accounting_inner",
    "send_sync_payload_or_cadence",
    "forward_upstream_event",
];

pub fn assert_transaction_recovery_authorities_are_unique() {
    let root_path = crate::common::policy::repository_root();
    let root = root_path.as_path();
    let production = rust_sources(&[root.join("src")])
        .into_iter()
        .filter(|path| !is_test_support_source(path))
        .collect::<Vec<_>>();
    assert_symbol_owners(
        root,
        &production,
        "TransactionJournalEntry",
        &[
            "src/net/sock_mgr/error.rs",
            "src/net/sock_mgr/manager.rs",
            "src/net/sock_mgr/manager_client_flow.rs",
            "src/net/sock_mgr/manager_reresolve.rs",
            "src/net/sock_mgr/manager_reresolve_apply.rs",
            "src/net/sock_mgr/manager_types.rs",
            "src/net/sock_mgr/mod.rs",
        ],
    );
    let journal_syntax =
        crate::common::rust_semantics::parse_file(&root.join("src/net/sock_mgr/error.rs"));
    let journal_is_cloneable = journal_syntax.items.iter().any(|item| match item {
        syn::Item::Struct(item) if item.ident == "TransactionJournalEntry" => {
            item.attrs.iter().any(|attribute| {
                let mut clone = false;
                if attribute.path().is_ident("derive") {
                    let _ = attribute.parse_nested_meta(|meta| {
                        clone |= meta.path.is_ident("Clone");
                        Ok(())
                    });
                }
                clone
            })
        }
        syn::Item::Impl(item) => item.trait_.as_ref().is_some_and(|(path, _)| {
            path.segments
                .last()
                .is_some_and(|segment| segment.ident == "Clone")
                && crate::common::rust_semantics::type_references_ident(
                    &item.self_ty,
                    "TransactionJournalEntry",
                )
        }),
        _ => false,
    });
    assert!(
        !journal_is_cloneable,
        "transaction journals must be move-only diagnostics so they cannot become a second recovery authority"
    );
    assert_symbol_owners(
        root,
        &production,
        "rollback_upstream_reply_id_handshake",
        &[
            "src/flow_state/runtime/handshake_runtime.rs",
            "src/worker_support/upstream_ack.rs",
        ],
    );
    assert_definition_owners(
        root,
        &production,
        "RecoverySendCore",
        &["src/flow_state/recovery_core.rs"],
    );
    let syntax =
        crate::common::rust_semantics::parse_file(&root.join("src/flow_state/session_state.rs"));
    let recovery_fields = syntax
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Struct(item) if item.ident == "RecoveryPayload" => Some(
                item.fields
                    .iter()
                    .filter_map(|field| field.ident.as_ref().map(ToString::to_string))
                    .collect::<BTreeSet<_>>(),
            ),
            _ => None,
        })
        .expect("RecoveryPayload definition");
    assert_eq!(
        recovery_fields,
        BTreeSet::from([
            "deadline".to_owned(),
            "send".to_owned(),
            "sequence".to_owned(),
            "session".to_owned(),
        ]),
        "recovery payload lifecycle must remain delegated to RecoverySendCore"
    );
    assert_consuming_flow_reservation_shape(root);
    assert_thread_owned_recorder_shape(root);
    assert_fragmented_flow_lifecycles_are_encapsulated(root, &syntax);
}

fn assert_fragmented_flow_lifecycles_are_encapsulated(root: &Path, session_state: &syn::File) {
    let lifecycles = crate::common::rust_semantics::parse_file(
        &root.join("src/flow_state/session_lifecycles.rs"),
    );
    let control = named_struct(&lifecycles, "ControlSendCore");
    assert!(
        control
            .fields
            .iter()
            .all(|field| matches!(field.vis, syn::Visibility::Inherited)),
        "handshake control evidence must be mutable only through ControlSendCore methods"
    );
    let candidate = named_struct(session_state, "ReceiveCandidate");
    let candidate_fields = candidate
        .fields
        .iter()
        .filter_map(|field| field.ident.as_ref().map(ToString::to_string))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        candidate_fields,
        BTreeSet::from([
            "ack".to_owned(),
            "session_key".to_owned(),
            "transaction_key".to_owned(),
        ]),
        "candidate ACK state and deadline must remain delegated to ReceiveCandidateAckCore"
    );
    let ack = named_struct(&lifecycles, "ReceiveCandidateAckCore");
    assert!(
        ack.fields
            .iter()
            .all(|field| matches!(field.vis, syn::Visibility::Inherited)),
        "candidate ACK state must not expose direct field mutation"
    );
}

pub fn assert_shared_worker_flow_authorities_are_unique() {
    let root_path = crate::common::policy::repository_root();
    let root = root_path.as_path();
    let production = rust_sources(&[root.join("src")])
        .into_iter()
        .filter(|path| !is_test_support_source(path))
        .collect::<Vec<_>>();

    for source in &production {
        let relative = path_policy::render_repo_relative_path(root, source);
        let contents = crate::common::rust_semantics::parse_file(source);
        assert!(
            !crate::common::rust_semantics::references_ident(&contents, "latest_sync_payload"),
            "{relative}: synchronized payload ownership must remain in FlowRuntimeState"
        );
        if crate::common::rust_semantics::calls(&contents, &["reset_sequence_state"])
            || crate::common::rust_semantics::calls(
                &contents,
                &["reset_sequence_state_and_seed_receive"],
            )
        {
            assert!(
                matches!(
                    relative.as_str(),
                    "src/net/icmp_sequence.rs"
                        | "src/net/icmp_sequence/reset.rs"
                        | "src/net/sync_icmp.rs"
                        | "src/worker_support/client_lock.rs"
                ),
                "{relative}: logical-flow sequence reset is owned by the client-lock transaction"
            );
        }
    }
    assert_symbol_owners(
        root,
        &production,
        "SyncPayloadSlot",
        &[
            "src/flow_state.rs",
            "src/flow_state/session_authority.rs",
            "src/flow_state/sync_slot.rs",
            "src/flow_state/sync_slot/sync_slot_loom.rs",
        ],
    );
    assert_definition_owners(
        root,
        &production,
        "BufferedPayload",
        &["src/net/payload.rs"],
    );
    assert_definition_owners(
        root,
        &production,
        "SyncPayloadSlot",
        &["src/flow_state/sync_slot.rs"],
    );
    assert_definition_owners(
        root,
        &production,
        "TransmitSequenceWindow",
        &["src/net/icmp_sequence.rs"],
    );
    assert_definition_owners(root, &production, "DataSequenceEvidence", &[]);
}

pub fn assert_stable_forwarding_requires_directional_permits() {
    let root_path = crate::common::policy::repository_root();
    let root = root_path.as_path();
    let graph = ProductionAuthorityGraph::load(root);
    graph.assert_stable_permit_contracts();
    graph.assert_send_authority_order();
    graph.assert_transition_and_stable_paths_are_disjoint();
    graph.assert_no_raw_blocking_authority_in_stable_handlers();
    graph.assert_descriptor_reconciliation_is_cold_path_only();
    graph.assert_stale_retry_revalidates_before_mutation();

    let context =
        crate::common::rust_semantics::parse_file(&root.join("src/worker_support/context.rs"));
    assert!(
        crate::common::rust_semantics::has_nested_type(&context, "PhantomData", "Rc"),
        "StableForwardPermit must remain non-Send and non-Clone"
    );

    let managed_socket =
        crate::common::rust_semantics::parse_file(&root.join("src/net/managed_socket.rs"));
    let worker_cache =
        crate::common::rust_semantics::parse_file(&root.join("src/worker_support/cache.rs"));
    let receiver_slot =
        crate::common::rust_semantics::parse_file(&root.join("src/net/sock_mgr/receiver_slot.rs"));
    assert!(
        crate::common::rust_semantics::defines(&managed_socket, "WorkerDescriptorCache")
            && crate::common::rust_semantics::defines(
                &managed_socket,
                "request_descriptor_cache_revocation_after_io_drain",
            )
            && crate::common::rust_semantics::references_ident(
                &managed_socket,
                "revocation_acknowledged",
            )
            && crate::common::rust_semantics::struct_has_field_type(
                &worker_cache,
                "CachedClientState",
                "descriptor_cache",
                &["WorkerDescriptorCache"],
            )
            && crate::common::rust_semantics::struct_has_field_type(
                &receiver_slot,
                "ReceiverClaim",
                "descriptor_cache",
                &["WorkerDescriptorCache"],
            )
            && !crate::common::rust_semantics::references_ident(&managed_socket, "UnsafeCell")
            && !crate::common::rust_semantics::has_unsafe_impl(&managed_socket, "Sync"),
        "descriptor ownership must be uniquely worker-owned and explicitly acknowledged before retirement"
    );

    let diagnostics = crate::common::rust_semantics::parse_file(
        &root.join("src/worker_support/packet_dump/diagnostic_store.rs"),
    );
    assert!(
        crate::common::rust_semantics::references_ident(&diagnostics, "AuthorityQueue")
            && crate::common::rust_semantics::defines(&diagnostics, "CompletedPacketDisposition",)
            && !crate::common::rust_semantics::references_ident(&diagnostics, "ArrayQueue"),
        "cross-thread diagnostic completion must use the governed bounded fixed-record queue"
    );
    assert!(
        !crate::common::rust_semantics::has_nested_type(&diagnostics, "Mutex", "HashMap"),
        "packet diagnostics may not use one process-wide worker map mutex"
    );

    let pipeline = crate::common::rust_semantics::parse_file(
        &root.join("src/worker_support/pipeline_audit.rs"),
    );
    for stage in [
        "FlowLaneAcquired",
        "SnapshotValidated",
        "ReceiveCompleted",
        "ReplayAdmitted",
        "DestinationSocketAcquired",
        "SequenceReserved",
        "BeforeSend",
        "AfterSend",
    ] {
        assert!(
            crate::common::rust_semantics::enum_has_variant(&pipeline, "PipelineStage", stage),
            "production pipeline audit is missing stage {stage}"
        );
    }
    assert!(
        !crate::common::rust_semantics::callback_parameter_named(
            &pipeline,
            &["callback", "hook", "handler"],
        ),
        "production pipeline barriers may not execute arbitrary callbacks while authority is held"
    );
    let graph = ProductionAuthorityGraph::load(root);
    for stage in [
        "FlowLaneAcquired",
        "SnapshotValidated",
        "ReceiveCompleted",
        "ReplayAdmitted",
        "DestinationSocketAcquired",
        "SequenceReserved",
        "BeforeSend",
        "AfterSend",
    ] {
        assert!(
            graph.functions.iter().any(|function| {
                function
                    .events
                    .iter()
                    .any(|event| event == &format!("checkpoint:{stage}"))
            }),
            "stage {stage} is declared but no production checkpoint call uses it"
        );
    }
}

#[derive(Debug)]
struct ProductionFunction {
    name: String,
    source: String,
    signature_identifiers: BTreeSet<String>,
    body_identifiers: BTreeSet<String>,
    calls: Vec<String>,
    direct_calls: Vec<String>,
    events: Vec<String>,
}

impl ProductionFunction {
    fn stable_permit_parameter(&self) -> bool {
        self.signature_identifiers.contains("StableForwardPermit")
    }

    fn calls(&self, name: &str) -> bool {
        self.calls.iter().any(|call| call == name)
    }

    fn event_positions<'a>(&'a self, event: &'a str) -> impl Iterator<Item = usize> + 'a {
        self.events
            .iter()
            .enumerate()
            .filter_map(move |(index, candidate)| (candidate == event).then_some(index))
    }
}

struct ProductionAuthorityGraph {
    functions: Vec<ProductionFunction>,
    by_name: BTreeMap<String, Vec<usize>>,
}

impl ProductionAuthorityGraph {
    fn load(root: &Path) -> Self {
        let mut functions = Vec::new();
        for source in production_rust_sources(&[root.join("src")]) {
            let relative = path_policy::render_repo_relative_path(root, &source);
            let syntax = crate::common::rust_semantics::parse_file(&source);
            let mut collector = FunctionCollector {
                source: &relative,
                functions: &mut functions,
            };
            syn::visit::Visit::visit_file(&mut collector, &syntax);
        }
        Self::from_functions(functions)
    }

    fn from_functions(functions: Vec<ProductionFunction>) -> Self {
        let mut by_name = BTreeMap::<String, Vec<usize>>::new();
        for (index, function) in functions.iter().enumerate() {
            by_name
                .entry(function.name.clone())
                .or_default()
                .push(index);
        }
        Self { functions, by_name }
    }

    fn unique(&self, name: &str) -> &ProductionFunction {
        let owners = self
            .by_name
            .get(name)
            .unwrap_or_else(|| panic!("production authority graph is missing {name}"));
        assert_eq!(
            owners.len(),
            1,
            "{name} must have one unambiguous production authority owner"
        );
        &self.functions[owners[0]]
    }

    fn reachable_from(&self, root: &ProductionFunction) -> Vec<&ProductionFunction> {
        let root_index = self
            .functions
            .iter()
            .position(|function| std::ptr::eq(function, root))
            .expect("root belongs to production authority graph");
        let mut pending = vec![root_index];
        let mut visited = BTreeSet::new();
        while let Some(index) = pending.pop() {
            if !visited.insert(index) {
                continue;
            }
            for call in &self.functions[index].direct_calls {
                if let Some(owners) = self.by_name.get(call)
                    && owners.len() == 1
                {
                    pending.push(owners[0]);
                }
            }
        }
        visited
            .into_iter()
            .map(|index| &self.functions[index])
            .collect()
    }

    fn assert_stable_permit_contracts(&self) {
        for name in STABLE_SEND_ROOTS {
            let function = self.unique(name);
            assert!(
                function.stable_permit_parameter(),
                "{} in {} must require StableForwardPermit in its type signature",
                function.name,
                function.source
            );
        }
    }

    fn assert_send_authority_order(&self) {
        let mut checked = 0_usize;
        for function in &self.functions {
            if !function.calls("acquire_socket")
                || !function.calls("reserve_protocol")
                || !function.calls("perform")
            {
                continue;
            }
            checked += 1;
            if let Some(error) = send_authority_order_error(function) {
                panic!("{error}");
            }
        }
        assert!(
            checked > 0,
            "the production graph did not discover any ICMP send authority owners"
        );
    }

    fn assert_transition_and_stable_paths_are_disjoint(&self) {
        let forbidden = [
            "try_reserve_client_flow",
            "perform_sync_session_transition",
            "handoff_upstream_session",
            "begin_upstream_rekey",
            "begin_upstream_reply_id_handshake",
        ];
        for root in STABLE_SEND_ROOTS.map(|name| self.unique(name)) {
            for function in self.reachable_from(root) {
                for call in forbidden {
                    assert!(
                        !function.calls(call),
                        "{} in {} reaches transition {call} through stable root {}",
                        function.name,
                        function.source,
                        root.name
                    );
                }
            }
        }
    }

    fn assert_no_raw_blocking_authority_in_stable_handlers(&self) {
        let forbidden = [
            "ClientFlowReservation",
            "FlowSessionState",
            "lock_authority_or_shutdown",
            "lock",
            "try_lock",
        ];
        for root in STABLE_SEND_ROOTS.map(|name| self.unique(name)) {
            for function in self.reachable_from(root) {
                for identifier in forbidden {
                    assert!(
                        !function.body_identifiers.contains(identifier),
                        "{} in {} reaches blocking authority {identifier} through stable root {}",
                        function.name,
                        function.source,
                        root.name
                    );
                }
            }
        }
    }

    fn assert_descriptor_reconciliation_is_cold_path_only(&self) {
        let owners = self
            .functions
            .iter()
            .filter(|function| {
                function.source == "src/net/managed_socket/api.rs" && function.calls("upgrade")
            })
            .collect::<Vec<_>>();
        assert!(
            !owners.is_empty(),
            "descriptor generation reconciliation must retain one reviewed Weak::upgrade owner"
        );
        assert!(
            owners.iter().all(|function| {
                matches!(
                    function.name.as_str(),
                    "upgrade_for_descriptor_cache" | "transition_descriptor"
                ) && function.source == "src/net/managed_socket/api.rs"
            }),
            "descriptor reference-count reconciliation escaped the generation-mismatch cache owner: {owners:?}"
        );
        for function in self
            .functions
            .iter()
            .filter(|function| function.name == "acquire_io_lease_after_increment")
        {
            assert!(
                !function.calls("upgrade") && !function.calls("clone"),
                "stable socket-lane acquisition performs a reference-count RMW"
            );
        }

        let syntax = crate::common::rust_semantics::parse_file(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("src/net/managed_socket.rs"),
        );
        let guard = syntax
            .items
            .iter()
            .find_map(|item| match item {
                syn::Item::Struct(item) if item.ident == "ActiveIoGuard" => Some(item),
                _ => None,
            })
            .expect("locate ActiveIoGuard definition");
        let borrowed_inner = guard.fields.iter().any(|field| {
            matches!(&field.ty, syn::Type::Reference(reference) if reference.lifetime.as_ref().is_some_and(|lifetime| lifetime.ident == "socket") && crate::common::rust_semantics::type_references_ident(&reference.elem, "ManagedSocketInner"))
        });
        assert!(
            borrowed_inner
                && !guard.fields.iter().any(|field| {
                    crate::common::rust_semantics::type_references_ident(&field.ty, "NonNull")
                        || crate::common::rust_semantics::type_references_ident(&field.ty, "Arc")
                }),
            "bounded I/O leases must use a checked borrow of the manager-owned allocation without raw pointers or per-packet Arc RMWs"
        );

        let single_writer_lane = self
            .functions
            .iter()
            .find(|function| {
                function.source == "src/atomic_core.rs" && function.name == "acquire_epoch_lane"
            })
            .expect("locate the production single-writer lane kernel");
        assert!(
            single_writer_lane.calls("compare_acqrel")
                && single_writer_lane.calls("compare_release")
                && !single_writer_lane.calls("store_seqcst"),
            "packet lanes must use explicit CAS ownership and Acquire/Release publication"
        );
        let contended_lane = self
            .functions
            .iter()
            .find(|function| {
                function.source == "src/atomic_core.rs"
                    && function.name == "acquire_contended_epoch_lane"
            })
            .expect("locate the cold contended control-lane kernel");
        assert!(
            contended_lane.calls("acquire_epoch_lane"),
            "the contended control lane must delegate to the same exact ownership core"
        );
    }

    fn assert_stale_retry_revalidates_before_mutation(&self) {
        for (source, function_name) in [
            (
                "src/worker_support/client_process.rs",
                "handle_stale_association",
            ),
            ("src/worker_support/upstream_retry.rs", "retry"),
        ] {
            let function = self
                .functions
                .iter()
                .find(|function| function.source == source && function.name == function_name)
                .unwrap_or_else(|| {
                    panic!("missing stale-association owner {source}::{function_name}")
                });
            let positions = [
                "packet_snapshot_under",
                "authorize_transition",
                "reconcile_stale_send_association",
                "reconciled",
            ]
            .map(|event| {
                function
                    .event_positions(event)
                    .next()
                    .unwrap_or_else(|| panic!("{source}::{function_name} is missing {event}"))
            });
            assert!(
                positions.windows(2).all(|pair| pair[0] < pair[1]),
                "{source}::{function_name} must revalidate flow identity before socket mutation and reconcile the exact association afterward"
            );
        }
    }
}

fn send_authority_order_error(function: &ProductionFunction) -> Option<String> {
    let error = |message: &str| {
        Some(format!(
            "{} in {} {message}",
            function.name, function.source
        ))
    };
    let socket = ["acquire_send_lease", "acquire_prepared_send"]
        .into_iter()
        .flat_map(|event| function.event_positions(event))
        .min();
    let Some(socket) = socket else {
        return error("reserves a sequence without a destination socket lane");
    };
    let Some(socket_typestate) = function.event_positions("acquire_socket").next() else {
        return error("does not transfer its destination lane into stable-send typestate");
    };
    let Some(sequence) = function.event_positions("reserve_protocol").next() else {
        return error("has no protocol reservation transaction");
    };
    let send = function
        .event_positions("perform")
        .chain(function.event_positions("send_payload_with_lease"))
        .min();
    let Some(send) = send else {
        return error("has no bounded send event");
    };
    if !(socket < socket_typestate && socket_typestate < sequence && sequence < send) {
        return error("must acquire socket, transfer it, reserve protocol, then send");
    }

    let reservation_names = ["sequence_reservation", "reservation"];
    for send_drop in function.event_positions("drop:send_lease") {
        if send_drop < sequence {
            continue;
        }
        let protocol_drop = reservation_names.iter().any(|name| {
            function
                .event_positions(&format!("drop:{name}"))
                .any(|index| sequence < index && index < send_drop)
        });
        if !protocol_drop {
            return error("releases its socket lane before its transmit authority");
        }
    }
    let consuming_typestate = function
        .event_positions("perform")
        .any(|index| index == send);
    let explicit_release = reservation_names.iter().any(|name| {
        function
            .event_positions(&format!("drop:{name}"))
            .any(|index| index > send)
    }) && function
        .event_positions("drop:send_lease")
        .any(|index| index > send);
    if !consuming_typestate && !explicit_release {
        return error(
            "must retain protocol and socket authority through send with StableSendCore or explicitly release them in order",
        );
    }
    None
}

struct FunctionCollector<'a> {
    source: &'a str,
    functions: &'a mut Vec<ProductionFunction>,
}

impl FunctionCollector<'_> {
    fn record(&mut self, signature: &syn::Signature, block: &syn::Block) {
        let mut signature_facts = SyntaxFacts::default();
        syn::visit::Visit::visit_signature(&mut signature_facts, signature);
        let mut body_facts = SyntaxFacts::default();
        syn::visit::Visit::visit_block(&mut body_facts, block);
        self.functions.push(ProductionFunction {
            name: signature.ident.to_string(),
            source: self.source.to_string(),
            signature_identifiers: signature_facts.identifiers,
            body_identifiers: body_facts.identifiers,
            calls: body_facts.calls,
            direct_calls: body_facts.direct_calls,
            events: body_facts.events,
        });
    }
}

impl<'ast> syn::visit::Visit<'ast> for FunctionCollector<'_> {
    visit_non_test_containers!();

    fn visit_item_fn(&mut self, function: &'ast syn::ItemFn) {
        if attrs_are_test_context(&function.attrs) {
            return;
        }
        self.record(&function.sig, &function.block);
        syn::visit::visit_item_fn(self, function);
    }

    fn visit_impl_item_fn(&mut self, function: &'ast syn::ImplItemFn) {
        if attrs_are_test_context(&function.attrs) {
            return;
        }
        self.record(&function.sig, &function.block);
        syn::visit::visit_impl_item_fn(self, function);
    }
}

#[derive(Default)]
struct SyntaxFacts {
    identifiers: BTreeSet<String>,
    calls: Vec<String>,
    direct_calls: Vec<String>,
    events: Vec<String>,
}

impl SyntaxFacts {
    fn record_call(&mut self, name: String) {
        self.identifiers.insert(name.clone());
        self.calls.push(name.clone());
        self.events.push(name);
    }

    fn record_direct_call(&mut self, name: String) {
        self.direct_calls.push(name.clone());
        self.record_call(name);
    }
}

impl<'ast> syn::visit::Visit<'ast> for SyntaxFacts {
    fn visit_path(&mut self, path: &'ast syn::Path) {
        for segment in &path.segments {
            self.identifiers.insert(segment.ident.to_string());
        }
        syn::visit::visit_path(self, path);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = call.func.as_ref()
            && let Some(segment) = path.path.segments.last()
        {
            let name = segment.ident.to_string();
            if name == "drop"
                && let Some(syn::Expr::Path(argument)) = call.args.first()
                && let Some(target) = argument.path.segments.last()
            {
                self.events.push(format!("drop:{}", target.ident));
            }
            if name == "checkpoint"
                && let Some(syn::Expr::Path(stage)) = call.args.iter().nth(1)
                && let Some(stage) = stage.path.segments.last()
            {
                self.events.push(format!("checkpoint:{}", stage.ident));
            }
            self.record_direct_call(name);
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        syn::visit::visit_expr_method_call(self, call);
        // Method chains are nested AST nodes. Record after visiting the
        // receiver so the event stream follows Rust evaluation order rather
        // than outermost-syntax order (`a.first().second()` is first, second).
        self.record_call(call.method.to_string());
    }
}

#[test]
fn send_authority_graph_rejects_order_and_release_inversions() {
    let syntax = syn::parse_file(
        r#"
        fn inverted(permit: StableForwardPermit<'_>) {
            reserve_protocol();
            let send_lease = socket.acquire_send_lease();
            acquire_socket();
            perform();
            drop(send_lease);
            drop(reservation);
            drop(permit);
        }
        "#,
    )
    .expect("parse inverted send fixture");
    let mut functions = Vec::new();
    let mut collector = FunctionCollector {
        source: "fixture.rs",
        functions: &mut functions,
    };
    syn::visit::Visit::visit_file(&mut collector, &syntax);
    let graph = ProductionAuthorityGraph::from_functions(functions);
    let error = send_authority_order_error(graph.unique("inverted"))
        .expect("inverted send must fail the authority graph");
    assert!(
        error.contains("acquire socket, transfer it, reserve protocol"),
        "unexpected authority-order rejection: {error}"
    );
}

#[test]
fn send_authority_graph_tracks_a_resource_owning_cached_lease_wrapper() {
    let syntax = syn::parse_file(
        r#"
        fn wrapped(permit: StableForwardPermit<'_>) {
            let cached_send = cache.acquire_prepared_send(handles);
            let CachedSendLease { socket: send_lease, .. } = cached_send;
            let stable_send = StableSendCore::new(permit)
                .acquire_socket(send_lease)
                .reserve_protocol(reservation);
            stable_send.perform(operation);
        }
        "#,
    )
    .expect("parse wrapped send fixture");
    let mut functions = Vec::new();
    let mut collector = FunctionCollector {
        source: "fixture.rs",
        functions: &mut functions,
    };
    syn::visit::Visit::visit_file(&mut collector, &syntax);
    let graph = ProductionAuthorityGraph::from_functions(functions);
    assert_eq!(send_authority_order_error(graph.unique("wrapped")), None);
}

#[test]
fn stable_authority_graph_follows_unique_helpers_transitively() {
    let syntax = syn::parse_file(
        r#"
        fn stable(permit: StableForwardPermit<'_>) { hidden_helper(); drop(permit); }
        fn hidden_helper() { state.lock(); }
        "#,
    )
    .expect("parse transitive authority fixture");
    let mut functions = Vec::new();
    let mut collector = FunctionCollector {
        source: "fixture.rs",
        functions: &mut functions,
    };
    syn::visit::Visit::visit_file(&mut collector, &syntax);
    let graph = ProductionAuthorityGraph::from_functions(functions);
    let reachable = graph.reachable_from(graph.unique("stable"));
    assert!(reachable.iter().any(|function| {
        function.name == "hidden_helper" && function.body_identifiers.contains("lock")
    }));
}

#[test]
fn checkpoint_evidence_requires_an_actual_checkpoint_call() {
    let syntax = syn::parse_file(
        r#"
        enum PipelineStage { BeforeSend }
        fn decorative_only() { let _name = "PipelineStage::BeforeSend"; }
        fn actual() { checkpoint(true, PipelineStage::BeforeSend); }
        "#,
    )
    .expect("parse checkpoint mutation fixture");
    let mut functions = Vec::new();
    let mut collector = FunctionCollector {
        source: "fixture.rs",
        functions: &mut functions,
    };
    syn::visit::Visit::visit_file(&mut collector, &syntax);
    assert!(
        !functions[0]
            .events
            .contains(&"checkpoint:BeforeSend".to_string())
    );
    assert!(
        functions[1]
            .events
            .contains(&"checkpoint:BeforeSend".to_string())
    );
}

fn assert_definition_owners(root: &Path, sources: &[PathBuf], type_name: &str, expected: &[&str]) {
    let mut owners = sources
        .iter()
        .filter_map(|source| {
            let relative = path_policy::render_repo_relative_path(root, source);
            let syntax = crate::common::rust_semantics::parse_file(source);
            crate::common::rust_semantics::defines_type(&syntax, type_name).then_some(relative)
        })
        .collect::<Vec<_>>();
    owners.sort();
    assert_eq!(
        owners, expected,
        "{type_name} must have exactly one reviewed type-definition owner"
    );
}

#[test]
fn definition_ownership_uses_recursive_exact_ast_identifiers() {
    let syntax =
        syn::parse_file("struct BufferedPayloadSendLease; mod nested { struct BufferedPayload; }")
            .expect("parse exact-definition fixture");
    assert!(crate::common::rust_semantics::defines_type(
        &syntax,
        "BufferedPayload"
    ));
    assert!(!crate::common::rust_semantics::defines_type(
        &syntax, "Buffered"
    ));
    assert!(!crate::common::rust_semantics::defines_type(
        &syntax, "Payload"
    ));
}

fn assert_symbol_owners(root: &Path, sources: &[PathBuf], symbol: &str, expected: &[&str]) {
    let mut owners = sources
        .iter()
        .filter_map(|source| {
            let syntax = crate::common::rust_semantics::parse_file(source);
            crate::common::rust_semantics::references_ident(&syntax, symbol)
                .then(|| path_policy::render_repo_relative_path(root, source))
        })
        .collect::<Vec<_>>();
    owners.sort();
    assert_eq!(
        owners, expected,
        "{symbol} must remain behind its reviewed transaction authority"
    );
}

fn is_test_support_source(path: &Path) -> bool {
    path.components().any(|component| {
        component.as_os_str().to_str().is_some_and(|name| {
            matches!(name, "tests" | "tests.rs" | "test_support.rs")
                || name.ends_with("_tests")
                || name.ends_with("_tests.rs")
        })
    })
}
