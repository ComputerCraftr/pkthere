use super::{
    PolicyFinding, PolicyKind, analyze_rust_source, canonical_function_body,
    function_graph_violations, inventory_from_metadata, repo_root,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMP_REPOSITORY: AtomicU64 = AtomicU64::new(0);

fn findings(source: &str, kind: PolicyKind) -> Vec<PolicyFinding> {
    findings_at("fixture.rs", source, kind)
}

pub(super) fn findings_at(path: &str, source: &str, kind: PolicyKind) -> Vec<PolicyFinding> {
    analyze_rust_source(path, source)
        .findings
        .into_iter()
        .filter(|finding| finding.kind == kind)
        .collect()
}

#[test]
fn production_panic_policy_distinguishes_runtime_tests_and_const_assertions() {
    let source = r#"
        const _: () = assert!(true);

        fn runtime(value: Option<u64>) {
            let _value = value.expect("present");
            assert!(true);
        }

        #[cfg(test)]
        mod tests {
            fn test_only(value: Option<u64>) {
                let _value = value.unwrap();
                assert!(true);
            }
        }
    "#;
    assert_eq!(
        findings_at("src/fixture.rs", source, PolicyKind::ProductionPanicSurface,).len(),
        2
    );
}

#[test]
fn coherent_stats_and_required_evidence_rules_are_syntax_backed() {
    let stats = r#"
        struct Snapshot {
            count: AtomicU64,
        }
    "#;
    assert_eq!(
        findings_at("src/stats.rs", stats, PolicyKind::CoherentStatsAuthority).len(),
        1
    );

    let verifier = r#"
        fn read_required(value: Option<u64>) -> u64 {
            value.unwrap_or_default()
        }
    "#;
    assert_eq!(
        findings_at(
            "tests/support/src/bin/topology_verifier.rs",
            verifier,
            PolicyKind::RequiredEvidenceDefault
        )
        .len(),
        1
    );
}

#[test]
fn test_only_admission_algorithms_cannot_impersonate_production_evidence() {
    let source = r#"
        #[cfg(test)]
        fn renamed_fixture_parser() -> AdmittedWirePacket<'static> {
            AdmittedWirePacket {}
        }
    "#;
    let findings = findings_at(
        "src/worker_support/fake.rs",
        source,
        PolicyKind::SocketLifecycleAuthority,
    );
    assert_eq!(findings.len(), 1);
}

#[test]
fn production_lifecycle_selection_uses_exact_fingerprints_only() {
    let root = repo_root();
    let lifecycle = crate::common::rust_semantics::parse_file(
        &root.join("crates/socket_policy/src/listener_lifecycle.rs"),
    );
    let resolution = crate::common::rust_semantics::parse_file(
        &root.join("crates/socket_policy/src/resolution_api.rs"),
    );
    let socket_policy =
        crate::common::rust_semantics::parse_file(&root.join("crates/socket_policy/src/lib.rs"));
    let socket_setup = crate::common::rust_semantics::parse_file(&root.join("src/net/socket.rs"));

    for (name, source) in [
        ("listener lifecycle", &lifecycle),
        ("socket resolution", &resolution),
        ("socket setup", &socket_setup),
    ] {
        assert!(
            !crate::common::rust_semantics::calls(source, &["datagram_disconnect_capability"]),
            "{name} must not select runtime lifecycle from aggregate platform/family evidence"
        );
        assert!(
            !crate::common::rust_semantics::calls(source, &["datagram_disconnect_evidence"]),
            "{name} must not select runtime lifecycle from aggregate platform/family evidence"
        );
    }
    assert!(
        crate::common::rust_semantics::calls(
            &lifecycle,
            &["same_bind_replacement_lifecycle_supported"],
        ),
        "listener replacement must consume the exact measured replacement fingerprint"
    );
    assert!(
        !crate::common::rust_semantics::calls(
            &lifecycle,
            &["listener_same_bind_replacement_lifecycle_eligible"],
        ),
        "production lifecycle must not collapse replacement evidence to platform/family booleans"
    );
    assert!(
        crate::common::rust_semantics::calls(
            &socket_setup,
            &["resolve_listener_socket_policy_for_creation_path_with_lifecycle"],
        ) && crate::common::rust_semantics::calls(
            &socket_setup,
            &["SocketLifecycleContext", "for_requested_bind"],
        ) && crate::common::rust_semantics::calls(
            &socket_setup,
            &["resolve_socket_policy_for_creation_path_with_lifecycle"],
        ),
        "listener and upstream setup must provide their actual bind/reuse context"
    );
    assert!(
        !crate::common::rust_semantics::local_initializer_references(
            &socket_setup,
            "bind_shape",
            "debug_unconnected",
        ),
        "upstream bind fingerprints must come from the actual requested bind, not a debug flag"
    );
    assert!(
        !crate::common::rust_semantics::references_ident(
            &socket_policy,
            "socket_reuse_capability_for_family",
        ) && !crate::common::rust_semantics::references_ident(&resolution, "with_icmp_intent",),
        "coarse reuse helpers and protocol-mismatched intent APIs must remain removed"
    );
}

#[test]
fn reality_verifiers_reject_adjacent_path_and_coarse_platform_shortcuts() {
    let adjacent_path_exception = r#"
        fn is_windows_regular_raw_capability_case(case: RealityCase) -> bool {
            current_icmp_platform_capabilities().windows_ipv4_protocol_zero_raw
                && case.socket_path == RealitySocketPath::RawIcmp
        }
    "#;
    assert!(
        findings_at(
            "tests/support/src/socket_reality/verify/creation.rs",
            adjacent_path_exception,
            PolicyKind::SocketLifecycleAuthority,
        )
        .len()
            >= 2
    );
}

#[test]
fn socket_setup_rejects_inline_target_dispatch_outside_the_platform_backend() {
    let source = r#"
        #[cfg(unix)]
        fn configure(socket: &Socket) {
            socket.set_reuse_port(true);
        }
    "#;
    assert_eq!(
        findings_at(
            "src/net/socket.rs",
            source,
            PolicyKind::InlineSocketPlatformDecision,
        )
        .len(),
        1
    );
    assert!(
        findings_at(
            "src/net/socket/platform.rs",
            source,
            PolicyKind::InlineSocketPlatformDecision,
        )
        .is_empty(),
        "target dispatch belongs only in the reviewed platform backend"
    );
}

#[test]
fn rollback_cannot_bypass_the_disconnect_postcondition_observer() {
    let source = r#"
        fn rollback_inner(&self, descriptor: &Socket) {
            drop(self.backend.disconnect(descriptor));
        }
    "#;
    assert_eq!(
        findings_at(
            "src/net/managed_socket/association.rs",
            source,
            PolicyKind::SocketLifecycleAuthority,
        )
        .len(),
        1
    );
}

#[test]
fn socket_authority_rejects_renamed_family_discriminators() {
    let source = "enum IpFamily { V4, V6 }\n";
    assert_eq!(
        findings_at(
            "crates/wire/src/packet_headers/fixture.rs",
            source,
            PolicyKind::SocketLifecycleAuthority,
        )
        .len(),
        1
    );
}

#[test]
fn socket_authority_rejects_boolean_send_selection() {
    let source = r#"
        fn transmit(socket: &Socket, connected: bool, bytes: &[u8], destination: &SockAddr) {
            if connected {
                drop(socket.send(bytes));
            } else {
                drop(socket.send_to(bytes, destination));
            }
        }
        fn indirect(handles: &Handles, socket: &Socket) {
            let connected = handles.listener_connected();
            some_other_send_function(socket, connected);
        }
    "#;
    assert!(
        findings_at(
            "src/fixture.rs",
            source,
            PolicyKind::SocketLifecycleAuthority,
        )
        .len()
            >= 2
    );
}

#[test]
fn socket_authority_rejects_combined_parser_and_flow_mutex_guard_bypasses() {
    let source = r#"
        struct ClientFlowReservation<'a> {
            guard: std::sync::MutexGuard<'a, ()>,
        }

        fn process(spec: &Spec, bytes: &[u8]) {
            let parsed = spec.socket.parser.parse(bytes);
            consume(parsed);
        }
    "#;
    let findings = analyze_rust_source("src/worker.rs", source).findings;
    assert!(
        findings
            .iter()
            .any(|finding| { finding.detail.contains("logical tokens") })
    );
    assert!(
        findings
            .iter()
            .any(|finding| { finding.detail.contains("parse_network") })
    );
}

#[test]
fn topology_reservations_and_drain_timeouts_fail_closed() {
    let source = r#"
        struct TopologyReservation<'a> {
            guard: std::sync::MutexGuard<'a, ()>,
        }

        fn reopen_after_io_drain_timeout() {
            let error = IoDrainTimedOut;
            consume(error);
        }
    "#;
    let findings = findings_at(
        "src/net/managed_socket/association.rs",
        source,
        PolicyKind::SocketLifecycleAuthority,
    );
    assert_eq!(findings.len(), 2);
}

#[test]
fn production_socket_timeouts_cannot_replace_readiness_polling() {
    let source = r#"
        fn production(socket: &Socket) {
            socket.set_read_timeout(None);
        }
        #[cfg(test)]
        mod tests {
            fn bounded_witness(socket: &Socket) {
                socket.set_read_timeout(None);
            }
        }
    "#;
    assert_eq!(
        findings_at(
            "src/fixture.rs",
            source,
            PolicyKind::SocketLifecycleAuthority,
        )
        .len(),
        1
    );
    assert!(
        findings_at(
            "tests/support/src/fixture.rs",
            source,
            PolicyKind::SocketLifecycleAuthority,
        )
        .is_empty()
    );
}

#[test]
fn socket_manager_test_helpers_and_fields_cannot_fabricate_lifecycle_evidence() {
    let helper = r#"
        impl SocketManager {
            #[cfg(test)]
            fn fail_listener_replacement_for_test(&self) {
                self.fail_listener_replacement.store(true, Ordering::Relaxed);
            }
        }
    "#;
    assert_eq!(
        findings_at(
            "src/net/sock_mgr/manager.rs",
            helper,
            PolicyKind::SocketLifecycleAuthority,
        )
        .len(),
        1
    );

    let field = r#"
        struct SocketManager {
            #[cfg(test)]
            fail_listener_replacement: AtomicBool,
        }
    "#;
    assert_eq!(
        findings_at(
            "src/net/sock_mgr/manager/types.rs",
            field,
            PolicyKind::SocketLifecycleAuthority,
        )
        .len(),
        1
    );

    let test_module_helper = r#"
        #[cfg(test)]
        mod tests {
            fn observe_production_transaction(manager: &SocketManager) {
                manager.clear_client_flow_group();
            }
        }
    "#;
    assert!(
        findings_at(
            "src/net/sock_mgr/tests.rs",
            test_module_helper,
            PolicyKind::SocketLifecycleAuthority,
        )
        .is_empty()
    );
}

#[test]
fn production_named_tests_cannot_select_debug_connection_scenarios() {
    let source = r#"
        enum MatrixConnectionScenario {
            ProductionPolicy,
            ForcedUnconnectedDebug,
        }

        #[test]
        fn production_lifecycle() {
            run(&FORCED_UNCONNECTED_DEBUG_SCENARIOS);
            run_one(MatrixConnectionScenario::ForcedUnconnectedDebug);
        }

        #[test]
        fn lifecycle_forced_unconnected_debug_scenario() {
            run(&FORCED_UNCONNECTED_DEBUG_SCENARIOS);
        }
    "#;
    assert_eq!(
        findings_at(
            "tests/fixture.rs",
            source,
            PolicyKind::SocketLifecycleAuthority,
        )
        .len(),
        2
    );
}

#[test]
fn manager_version_policy_rejects_cached_arithmetic_and_direct_atomic_allocation() {
    let source = r#"
        struct Manager {
            version_counter: AtomicU64,
        }
        impl Manager {
            fn publish(&self, prev_ver: u64) -> u64 {
                self.version_counter.try_update(Ordering::Release, Ordering::Relaxed, |value| value.checked_add(1)).unwrap();
                self.version.publish_prechecked(capacity);
                prev_ver + 1
            }
        }
    "#;
    assert!(
        findings_at(
            "src/net/sock_mgr/fixture.rs",
            source,
            PolicyKind::ManagerVersionAuthority,
        )
        .len()
            >= 4
    );
}

#[test]
fn manager_publication_requires_typed_transaction_guard() {
    let source = r#"
        impl SocketManager {
            fn publish_prechecked(&self, capacity: VersionCapacityGuard) -> StateVersion {
                self.version.publish_prechecked(capacity)
            }
        }
    "#;
    assert_eq!(
        findings_at(
            "src/net/sock_mgr/manager.rs",
            source,
            PolicyKind::ManagerVersionAuthority,
        )
        .len(),
        1
    );

    let literal_lookalike = r#"
        impl SocketManager {
            fn publish_prechecked(&self, capacity: VersionCapacityGuard) -> StateVersion {
                let _comment = "ManagerTransactionGuard before_transition after_transition";
                self.version.publish_prechecked(capacity)
            }
        }
    "#;
    assert_eq!(
        findings_at(
            "src/net/sock_mgr/manager.rs",
            literal_lookalike,
            PolicyKind::ManagerVersionAuthority,
        )
        .len(),
        1,
        "literal text cannot satisfy the typed transaction-guard requirement"
    );

    let transition_observer = r#"
        fn establish_client_flow_group(
            before_transition: impl FnMut(u32),
            after_transition: impl FnMut(u32),
        ) {
            before_transition(0);
            after_transition(0);
        }
    "#;
    assert_eq!(
        findings_at(
            "src/net/sock_mgr/manager.rs",
            transition_observer,
            PolicyKind::SocketLifecycleAuthority,
        )
        .len(),
        1
    );

    let fabricated_receive_authority = r#"
        #[cfg(test)]
        fn for_test() -> ReceiveAuthority {
            todo!()
        }
    "#;
    assert_eq!(
        findings_at(
            "src/worker_support/receive.rs",
            fabricated_receive_authority,
            PolicyKind::SocketLifecycleAuthority,
        )
        .len(),
        1
    );
}

#[test]
fn failure_containment_policy_rejects_fail_open_authority_patterns() {
    let source = r#"
        fn swallowed(flow: &Flow) {
            let _reservation = flow.try_reserve_client_flow().ok()?;
        }

        fn catch_all(flow: &Flow) {
            match flow.try_topology_read() {
                Ok(read) => consume(read),
                Err(_) => return,
            }
        }

        fn ignored(reservation: &Reservation, state: &mut State) {
            reservation.validate();
            state.mutate();
        }

        fn conditional_erasure(reservation: &Reservation) {
            if reservation.assert_current().is_err() {
                return;
            }
            mutate();
        }

        fn mutation_erasure(flow: &Flow, reservation: &Reservation) {
            if flow.publish_locked(reservation).is_err() {
                return;
            }
            continue_with_usable_authority();
        }

        fn conditional_catch_all(reservation: &Reservation) {
            if let Err(_) = reservation.assert_current() {
                return;
            }
            mutate();
        }

        fn fatal_then_value() -> Result<Token, Error> {
            publish_process_fatal(format_args!("lost"));
            Ok(Token::new())
        }

        fn blocking_join(handle: JoinHandle<()>) {
            handle.join();
        }

        fn running_producer(&self) {
            self.queue_flush_marker(1);
        }
    "#;
    assert!(
        findings_at(
            "src/fixture.rs",
            source,
            PolicyKind::FailureContainmentAuthority,
        )
        .len()
            >= 9
    );
}

#[test]
fn failure_containment_policy_accepts_typed_and_guarded_paths() {
    let source = r#"
        fn typed(flow: &Flow) -> Result<(), Error> {
            let reservation = flow.try_reserve_client_flow()?;
            reservation.validate()?;
            mutate(reservation);
            Ok(())
        }

        fn bounded_join(handle: JoinHandle<()>) {
            if handle.is_finished() {
                handle.join();
            }
        }

        fn seal_until(&self) {
            self.queue_flush_marker(1);
        }
    "#;
    assert!(
        findings_at(
            "src/fixture.rs",
            source,
            PolicyKind::FailureContainmentAuthority,
        )
        .is_empty()
    );
}

#[test]
fn syntactic_recursion_finds_supported_shapes() {
    let source = r#"
        fn free() { free(); }
        fn qualified() { self::qualified(); }
        impl Owner {
            fn method(&self) { self.method(); }
            fn associated(&self) { Self::associated(self); }
        }
    "#;
    assert_eq!(
        findings(source, PolicyKind::SyntacticDirectRecursion).len(),
        4
    );
}

#[test]
fn syntactic_recursion_ignores_drop_and_external_delegation() {
    let source = r#"
        impl Drop for Owner {
            fn drop(&mut self) {
                drop(self.guard.take());
                std::mem::drop(self.other.take());
            }
        }
        impl Owner {
            fn operation(&self) { external::operation(); other.operation(); }
        }
    "#;
    assert!(findings(source, PolicyKind::SyntacticDirectRecursion).is_empty());
}

#[test]
fn syntactic_recursion_distinguishes_trait_adapters_from_recursive_calls() {
    let source = r#"
        trait Adapter {
            fn load(&self) -> u8;
            fn same(&self, other: u8) -> bool;
        }
        impl Adapter for Owner {
            fn load(&self) -> u8 { self.load(Ordering::SeqCst) }
            fn same(&self, other: u8) -> bool { self.same(other) }
        }
        impl OtherAdapter for Owner {
            fn same(&self, other: u8) -> bool { Owner::same(self, other) }
        }
        impl ReserveAdapter for Owner {
            fn reserve(self) { Owner::reserve(self) }
        }
        impl ConstructorAdapter for Owner {
            fn new() -> Self { Self::new(1) }
        }
    "#;
    let findings = findings(source, PolicyKind::SyntacticDirectRecursion);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].item, "same()");
}

#[test]
fn duplicate_logic_normalizes_parameter_and_local_names() {
    let first: syn::ItemFn = syn::parse_str(
        "fn first(input: u64) -> u64 { let incremented = input + 1; incremented * 2 }",
    )
    .expect("parse first duplicate fixture");
    let second: syn::ItemFn =
        syn::parse_str("fn second(value: u64) -> u64 { let next = value + 1; next * 2 }")
            .expect("parse second duplicate fixture");
    assert_eq!(
        canonical_function_body(&first.sig.inputs, &first.block),
        canonical_function_body(&second.sig.inputs, &second.block)
    );
}

#[test]
fn duplicate_logic_has_no_minimum_body_length_escape() {
    let parsed = analyze_rust_source(
        "fixture.rs",
        "fn first(value: u8) -> u8 { value + 1 } \
         fn second(input: u8) -> u8 { input + 1 }",
    );
    let violations = super::duplicate_logic_violations(parsed.functions.iter());
    assert_eq!(violations.len(), 1);
    assert!(violations[0].contains("alpha-equivalent duplicate"));
}

#[test]
fn call_graph_detects_mutual_recursion() {
    let parsed = analyze_rust_source(
        "fixture.rs",
        "fn first() { second(); } fn second() { first(); }",
    );
    let cycles = function_graph_violations(parsed.functions.iter());
    assert!(
        !cycles.is_empty(),
        "mutual recursion must be detected even without a direct self-call"
    );
}

#[test]
fn call_graph_detects_deep_cross_module_recursion() {
    let parsed = analyze_rust_source(
        "fixture.rs",
        "mod first { fn enter() { super::second::continue_cycle(); } } \
         mod second { fn continue_cycle() { super::third::finish(); } } \
         mod third { fn finish() { super::first::enter(); } }",
    );
    let violations = function_graph_violations(parsed.functions.iter());
    assert!(
        violations
            .iter()
            .any(|violation| violation.contains("recursive call cycle")),
        "cross-module cycles of more than two functions must be detected"
    );
}

#[test]
fn call_graph_enforces_resolved_depth_without_recursion() {
    let mut source = String::new();
    for index in 0..=super::function_logic::MAX_RESOLVED_CALL_DEPTH {
        if index == super::function_logic::MAX_RESOLVED_CALL_DEPTH {
            source.push_str(&format!("fn depth_{index}() {{}}"));
        } else {
            source.push_str(&format!("fn depth_{index}() {{ depth_{}(); }}", index + 1));
        }
    }
    let parsed = analyze_rust_source("fixture.rs", &source);
    let violations = function_graph_violations(parsed.functions.iter());
    assert!(
        violations
            .iter()
            .any(|violation| violation.contains("resolved call depth exceeds")),
        "deep acyclic helper chains must not bypass the graph bound"
    );
}

#[test]
fn function_policy_enforces_expression_ast_depth() {
    let nesting = super::function_logic::MAX_FUNCTION_AST_DEPTH + 1;
    let source = format!(
        "fn deep() {{ let _value = {}1{}; }}",
        "(".repeat(nesting),
        ")".repeat(nesting)
    );
    let parsed = analyze_rust_source("fixture.rs", &source);
    let violations = function_graph_violations(parsed.functions.iter());
    assert!(
        violations
            .iter()
            .any(|violation| violation.contains("expression AST depth")),
        "nested AST structure must have an explicit bound"
    );
}

#[test]
fn cfg_overlap_is_semantic_for_recursion_and_duplicates() {
    let parsed = analyze_rust_source(
        "fixture.rs",
        "#[cfg(unix)] fn first() { second(); } \
         #[cfg(target_os = \"linux\")] fn second() { first(); }",
    );
    assert!(
        function_graph_violations(parsed.functions.iter())
            .iter()
            .any(|violation| violation.contains("recursive call cycle")),
        "overlapping cfg predicates must not partition one executable cycle"
    );
}

#[test]
fn call_graph_ignores_explicit_type_qualified_trait_delegation() {
    let parsed = analyze_rust_source(
        "fixture.rs",
        r#"
            trait Adapter { fn load(&self) -> u8; }
            impl Adapter for Owner {
                fn load(&self) -> u8 { <Owner>::load(self, Ordering::SeqCst) }
            }
        "#,
    );
    assert!(function_graph_violations(parsed.functions.iter()).is_empty());
}

#[test]
fn syntax_policies_parse_multiline_attributes_globs_and_ignore_literals() {
    let source = r##"
        const TEXT: &str = r#"#[allow(dead_code)] use super::*;"#;
        #[allow(
            unused_imports,
            clippy::duplicate_mod,
            clippy::large_enum_variant
        )]
        use crate::items::{Thing, *};
    "##;
    assert_eq!(findings(source, PolicyKind::ForbiddenAllow).len(), 1);
    assert_eq!(findings(source, PolicyKind::WildcardImport).len(), 1);
}

#[test]
fn exact_duplicates_are_partitioned_by_cfg_domain() {
    let source = r#"
        #[cfg(unix)]
        fn operation() { let value = calculate(); publish(value); publish(value); }
        #[cfg(windows)]
        fn operation() { let value = calculate(); publish(value); publish(value); }
    "#;
    let parsed = analyze_rust_source("fixture.rs", source);
    assert_eq!(parsed.functions.len(), 2);
    assert_ne!(
        parsed.functions[0].cfg_domain,
        parsed.functions[1].cfg_domain
    );
    assert_eq!(parsed.functions[0].body, parsed.functions[1].body);
}

#[test]
fn cfg_test_context_is_classified_from_nested_predicates() {
    let source = r#"
        #[cfg(any(test, feature = "extra-tests"))]
        mod checks {
            fn helper() { let value = calculate(); publish(value); publish(value); }
        }
    "#;
    let parsed = analyze_rust_source("fixture.rs", source);
    assert_eq!(parsed.functions.len(), 1);
    assert!(parsed.functions[0].is_test);
    assert!(parsed.functions[0].cfg_domain.contains("test"));
}

#[test]
#[should_panic(expected = "failed to parse fixture.rs")]
fn malformed_rust_fails_closed() {
    drop(analyze_rust_source("fixture.rs", "fn broken("));
}

#[test]
fn metadata_inventory_recognizes_custom_build_targets() {
    let root = repo_root();
    let metadata = serde_json::json!({
        "workspace_members": ["pkg 0.1.0 (path+file:///repo)"],
        "packages": [{
            "id": "pkg 0.1.0 (path+file:///repo)",
            "manifest_path": root.join("Cargo.toml"),
            "targets": [{"kind": ["custom-build"]}]
        }]
    });
    let inventory = inventory_from_metadata(&root, &metadata);
    assert!(inventory.has_custom_build_target);
}

#[test]
fn metadata_inventory_covers_nested_packages_and_excludes_generated_sources() {
    let root = temp_repository("nested-inventory");
    write(&root.join("src/lib.rs"), "pub fn root_source() {}\n");
    write(
        &root.join("examples/client.rs"),
        "pub fn example_source() {}\n",
    );
    write(&root.join("benches/load.rs"), "pub fn bench_source() {}\n");
    write(
        &root.join("nested/src/lib.rs"),
        "pub fn nested_source() {}\n",
    );
    write(
        &root.join("target/generated.rs"),
        "compile_error!(\"generated source must not be scanned\");\n",
    );
    write(&root.join("Cargo.toml"), "[workspace]\n");
    write(
        &root.join("nested/Cargo.toml"),
        "[package]\nname='nested'\n",
    );
    let root = root.canonicalize().expect("canonical temporary repository");
    let metadata = serde_json::json!({
        "workspace_members": ["root", "nested"],
        "packages": [
            {"id": "root", "manifest_path": root.join("Cargo.toml"), "targets": []},
            {"id": "nested", "manifest_path": root.join("nested/Cargo.toml"), "targets": []}
        ]
    });
    let inventory = inventory_from_metadata(&root, &metadata);
    let relative = inventory
        .sources
        .iter()
        .map(|path| path.strip_prefix(&root).expect("source under root"))
        .collect::<Vec<_>>();
    assert!(relative.contains(&Path::new("src/lib.rs")));
    assert!(relative.contains(&Path::new("examples/client.rs")));
    assert!(relative.contains(&Path::new("benches/load.rs")));
    assert!(relative.contains(&Path::new("nested/src/lib.rs")));
    assert!(!relative.contains(&Path::new("target/generated.rs")));
    assert_eq!(
        inventory.sources.len(),
        inventory
            .sources
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
    );
    fs::remove_dir_all(&root).expect("remove temporary repository");
}

#[cfg(unix)]
#[test]
fn metadata_inventory_rejects_source_symlinks_that_escape_repository() {
    use std::os::unix::fs::symlink;

    let root = temp_repository("escaping-symlink");
    write(&root.join("Cargo.toml"), "[package]\nname='fixture'\n");
    write(&root.join("src/lib.rs"), "pub fn local() {}\n");
    let outside = root.with_extension("outside.rs");
    write(&outside, "pub fn escaped() {}\n");
    symlink(&outside, root.join("src/escaped.rs")).expect("create escaping source symlink");
    let root = root.canonicalize().expect("canonical temporary repository");
    let metadata = serde_json::json!({
        "workspace_members": ["fixture"],
        "packages": [{
            "id": "fixture",
            "manifest_path": root.join("Cargo.toml"),
            "targets": []
        }]
    });
    let result = std::panic::catch_unwind(|| inventory_from_metadata(&root, &metadata));
    assert!(result.is_err());
    fs::remove_dir_all(&root).expect("remove temporary repository");
    fs::remove_file(outside).expect("remove external fixture");
}

fn temp_repository(name: &str) -> PathBuf {
    let sequence = NEXT_TEMP_REPOSITORY.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "pkthere-policy-{}-{name}-{sequence}",
        std::process::id()
    ));
    fs::create_dir_all(&path).expect("create temporary repository");
    path
}

fn write(path: &Path, contents: &str) {
    fs::create_dir_all(path.parent().expect("fixture parent")).expect("create fixture parent");
    fs::write(path, contents).expect("write fixture");
}

#[test]
fn dockerfile_policy_ignores_comments_and_joins_instructions() {
    let parsed = super::portable_policy::DockerfilePolicy::parse(
        "# RUN cargo clean and target-cpu=native\nRUN cargo build \\\n         --locked\nENV TARGET_CPU=generic\n",
    );
    assert!(!parsed.contains("cargo clean"));
    assert!(!parsed.contains("target-cpu=native"));
    assert!(parsed.contains("cargo build --locked"));
    assert!(parsed.contains("TARGET_CPU=generic"));
}
