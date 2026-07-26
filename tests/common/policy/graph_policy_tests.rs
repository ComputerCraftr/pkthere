use super::{PolicyKind, analyze_rust_source, function_logic::function_graph_violations};

#[test]
fn call_graph_detects_deep_mutual_method_recursion() {
    let parsed = analyze_rust_source(
        "fixture.rs",
        r#"
            struct Owner;
            impl Owner {
                fn first(&self) { self.second(); }
                fn second(&self) { Self::third(self); }
                fn third(&self) { self.fourth(); }
                fn fourth(&self) { self.first(); }
            }
        "#,
    );
    assert!(
        function_graph_violations(parsed.functions.iter())
            .iter()
            .any(|violation| violation.contains("recursive call cycle")),
        "direct and associated method calls must participate in the same recursion graph"
    );
}

#[test]
fn call_graph_detects_cross_file_crate_qualified_mutual_recursion() {
    let left = analyze_rust_source(
        "src/left.rs",
        "fn first(value: u8) { crate::right::second(value); }",
    );
    let right = analyze_rust_source(
        "src/right.rs",
        "fn second(value: u8) { crate::left::first(value); }",
    );
    let functions = left.functions.iter().chain(right.functions.iter());
    assert!(
        function_graph_violations(functions)
            .iter()
            .any(|violation| violation.contains("recursive call cycle")),
        "crate-qualified calls across ordinary module files must share one recursion graph"
    );
}

#[test]
fn recursion_graph_ignores_comments_and_string_lookalikes() {
    let parsed = analyze_rust_source(
        "fixture.rs",
        r#"
            fn first() {
                let _comment_lookalike = "second();";
                // second();
            }
            fn second() {
                let _comment_lookalike = "first();";
                // first();
            }
        "#,
    );
    assert!(function_graph_violations(parsed.functions.iter()).is_empty());
}

#[test]
fn call_graph_detects_trait_method_mutual_recursion_by_arity() {
    let parsed = analyze_rust_source(
        "fixture.rs",
        r#"
            trait Cycle {
                fn first(&self, value: u8);
                fn second(&self, value: u8);
            }
            impl Cycle for Owner {
                fn first(&self, value: u8) { Self::second(self, value); }
                fn second(&self, value: u8) { self.first(value); }
            }
            impl Constructor for Owner {
                fn new() -> Self { Self::new(1) }
            }
        "#,
    );
    let violations = function_graph_violations(parsed.functions.iter());
    assert!(
        violations
            .iter()
            .any(|violation| violation.contains("recursive call cycle")),
        "same-trait calls with matching AST arity must form a resolved cycle"
    );
    assert!(
        violations
            .iter()
            .all(|violation| !violation.contains("Constructor")),
        "an arity-distinct inherent constructor adapter must not be a false recursion edge"
    );
}

#[test]
fn seqcst_policy_is_ast_backed_and_ignores_literal_lookalikes() {
    let findings = analyze_rust_source(
        "src/fixture.rs",
        r#"
            fn protocol(state: &AtomicU64) {
                let _lookalike = "Ordering::SeqCst";
                let _ = state.load(Ordering::SeqCst);
            }
        "#,
    )
    .findings;
    assert_eq!(
        findings
            .iter()
            .filter(|finding| finding.kind == PolicyKind::SequentiallyConsistentProtocol)
            .count(),
        1
    );
}

#[test]
fn seqcst_cross_atomic_gate_lane_protocol_cannot_claim_loom_evidence() {
    let findings = analyze_rust_source(
        "src/fixture.rs",
        r#"
            fn reader(gate: &AtomicU64, lane: &AtomicU64) {
                lane.store(1, Ordering::SeqCst);
                let _ = gate.load(Ordering::SeqCst);
            }
        "#,
    )
    .findings;
    assert_eq!(
        findings
            .iter()
            .filter(|finding| finding.kind == PolicyKind::SequentiallyConsistentProtocol)
            .count(),
        2,
        "SEQCST-DEPENDENCY-001 must identify both cross-atomic accesses"
    );
}
