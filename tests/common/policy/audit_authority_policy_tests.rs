use super::PolicyKind;
use super::tests::findings_at;

#[test]
fn interior_mutability_inventory_parses_nested_alias_and_macro_surfaces() {
    let source = r#"
        use std::cell::Cell;
        type Hidden<T> = Option<RefCell<T>>;
        struct State {
            direct: Box<Cell<u64>>,
            alias: Hidden<u64>,
        }
        declare_state!(UnsafeCell<u64>);
        unsafe impl Send for State {}
    "#;
    let findings = findings_at(
        "src/unregistered.rs",
        source,
        PolicyKind::InteriorMutabilityAuthority,
    );
    assert_eq!(findings.len(), 4, "findings: {findings:?}");

    let registered = r#"
        use std::cell::Cell;
        thread_local! {
            static CURRENT_THREAD_SLOT: Cell<usize> = const { Cell::new(0) };
        }
    "#;
    assert!(
        findings_at(
            "src/runtime_support.rs",
            registered,
            PolicyKind::InteriorMutabilityAuthority,
        )
        .is_empty()
    );

    let unregistered_symbol = r#"
        use std::cell::Cell;
        thread_local! { static UNREVIEWED: Cell<u64> = const { Cell::new(0) }; }
    "#;
    assert!(
        !findings_at(
            "src/runtime_support.rs",
            unregistered_symbol,
            PolicyKind::InteriorMutabilityAuthority,
        )
        .is_empty(),
        "a reviewed file cannot authorize a newly added Cell symbol"
    );

    let direct_cell_in_registered_file = r#"
        use std::cell::Cell;
        struct HiddenAuthority { value: Cell<u64> }
    "#;
    assert!(
        !findings_at(
            "src/runtime_support.rs",
            direct_cell_in_registered_file,
            PolicyKind::InteriorMutabilityAuthority,
        )
        .is_empty(),
        "thread-local registrations cannot authorize direct struct interior mutability"
    );

    let unregistered_kind = r#"
        use std::cell::RefCell;
        thread_local! { static SLOT: RefCell<u64> = const { RefCell::new(0) }; }
    "#;
    assert!(
        !findings_at(
            "src/runtime_support.rs",
            unregistered_kind,
            PolicyKind::InteriorMutabilityAuthority,
        )
        .is_empty(),
        "registration is per interior-mutability kind, not a whole-file exemption"
    );

    let malformed_registered_symbol = r#"
        use std::cell::Cell;
        thread_local! {
            static CURRENT_THREAD_SLOT: Cell<usize> =
                const { Cell::new(0) } trailing
        }
    "#;
    assert!(
        !findings_at(
            "src/runtime_support.rs",
            malformed_registered_symbol,
            PolicyKind::InteriorMutabilityAuthority,
        )
        .is_empty(),
        "an unparseable thread_local! body must fail closed even for a registered symbol"
    );

    let mixed_macro = r#"declare_state!(Cell<u64>, UnsafeCell<u64>);"#;
    assert!(
        !findings_at(
            "src/runtime_support.rs",
            mixed_macro,
            PolicyKind::InteriorMutabilityAuthority,
        )
        .is_empty(),
        "an allowed Cell token cannot hide an unregistered UnsafeCell token"
    );
}

#[test]
fn mutable_cfg_test_fields_are_a_distinct_test_authority_violation() {
    let source = r#"
        struct SessionAuthority {
            current: u64,
            #[cfg(test)]
            observed: Cell<u64>,
        }
    "#;
    assert_eq!(
        findings_at("src/session.rs", source, PolicyKind::TestStateAuthority).len(),
        1
    );
    assert!(
        findings_at(
            "src/session.rs",
            source,
            PolicyKind::InteriorMutabilityAuthority,
        )
        .is_empty(),
        "test-state closure must not masquerade as the production inventory"
    );
}

#[test]
fn test_only_mutators_cannot_live_in_production_modules() {
    let production_source = r#"
        struct Session;
        impl Session {
            #[cfg(test)]
            fn reset_state_for_test(&mut self) {}
        }
        #[cfg(test)]
        fn force_generation(value: &mut u64) { *value = 4; }
        #[cfg(test)]
        fn disguised_helper(value: &mut u64) { *value = 5; }
        #[cfg(test)]
        fn immutable_observer(value: &u64) -> u64 { *value }
    "#;
    assert_eq!(
        findings_at(
            "src/session.rs",
            production_source,
            PolicyKind::TestStateAuthority,
        )
        .len(),
        3
    );

    let test_support_source = r#"
        struct Session;
        impl Session {
            fn reset_state_for_test(&mut self) {}
        }
    "#;
    assert!(
        findings_at(
            "src/session/test_support.rs",
            test_support_source,
            PolicyKind::TestStateAuthority,
        )
        .is_empty(),
        "test-support helpers may compose production APIs without adding production authority"
    );

    let registered_audit_hook = r#"
        struct Counter;
        impl Counter {
            #[cfg(any(test, feature = "authority-audit"))]
            fn fetch_add(&self, value: u64) { self.store(value); }
        }
    "#;
    assert!(
        findings_at(
            "src/authority/thread_owned.rs",
            registered_audit_hook,
            PolicyKind::TestStateAuthority,
        )
        .is_empty(),
        "an exact reviewed audit hook remains available"
    );
    let renamed_audit_hook = registered_audit_hook.replace("fetch_add", "increment_hidden");
    assert_eq!(
        findings_at(
            "src/authority/thread_owned.rs",
            &renamed_audit_hook,
            PolicyKind::TestStateAuthority,
        )
        .len(),
        1,
        "the registration must not exempt a newly named mutator in the same file"
    );
}

#[test]
fn test_mutation_policy_uses_ast_mutation_not_function_names() {
    let source = r#"
        struct State;
        impl State {
            #[cfg(test)]
            fn complete_observation(&self) -> bool { true }

            #[cfg(test)]
            fn inspect_then_mutate(&self) {
                let mut authority = lock_authority_or_shutdown(&self.state);
                authority.value = 3;
            }

            #[cfg(test)]
            fn unused_mutable_argument(value: &mut u64) -> u64 { 7 }

            #[cfg(test)]
            fn read_mutable_argument(value: &mut u64) -> u64 { *value }

            #[cfg(test)]
            fn mutate_argument(value: &mut u64) { *value += 1; }

            #[cfg(test)]
            fn mutate_only_a_local() -> u64 {
                let mut value = 0;
                value += 1;
                value
            }

            #[cfg(test)]
            fn mutate_interior_authority(&self) {
                self.generation.compare_exchange(1, 2, Acquire, Relaxed);
            }
        }
    "#;
    let findings = findings_at("src/state.rs", source, PolicyKind::TestStateAuthority);
    let items = findings
        .iter()
        .map(|finding| finding.item.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        items,
        std::collections::BTreeSet::from([
            "inspect_then_mutate",
            "read_mutable_argument",
            "mutate_argument",
            "mutate_interior_authority",
            "unused_mutable_argument",
        ])
    );
}
