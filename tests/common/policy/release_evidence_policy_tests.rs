use super::release_evidence_policy::{TestContract, validate_contracts};
use std::collections::BTreeMap;

#[test]
fn old_test_name_with_a_weakened_body_cannot_satisfy_evidence() {
    let path = "fixture.rs";
    let syntax = syn::parse_file("#[test] fn stable_path_proof() { assert!(true); }")
        .expect("parse weakened evidence fixture");
    let parsed = BTreeMap::from([(path, syntax)]);
    let contract = TestContract::new(
        path,
        "stable_path_proof",
        &["count_allocations", "production_send"],
    );
    let violations = validate_contracts(&parsed, &[contract]);
    assert_eq!(violations.len(), 2);
    assert!(
        violations
            .iter()
            .all(|violation| violation.contains("missing semantic operation"))
    );
}

#[test]
fn required_operations_in_literal_dead_code_cannot_satisfy_evidence() {
    let path = "fixture.rs";
    let syntax = syn::parse_file(
        "#[test] fn stable_path_proof() { if false { count_allocations(); production_send(); } }",
    )
    .expect("parse dead evidence fixture");
    let parsed = BTreeMap::from([(path, syntax)]);
    let contract = TestContract::new(
        path,
        "stable_path_proof",
        &["count_allocations", "production_send"],
    );
    let violations = validate_contracts(&parsed, &[contract]);
    assert_eq!(violations.len(), 2);
    assert!(
        violations
            .iter()
            .all(|violation| violation.contains("missing semantic operation"))
    );
}

#[test]
fn reachable_helper_operations_satisfy_evidence_without_textual_inlining() {
    let path = "fixture.rs";
    let syntax = syn::parse_file(
        "fn production_core() { reserve_send(); complete_send(); }\
         #[test] fn stable_path_proof() { production_core(); }",
    )
    .expect("parse reachable helper fixture");
    let parsed = BTreeMap::from([(path, syntax)]);
    let contract = TestContract::new(
        path,
        "stable_path_proof",
        &["reserve_send", "complete_send"],
    );
    assert!(validate_contracts(&parsed, &[contract]).is_empty());
}

#[test]
fn uncalled_lookalike_helper_cannot_satisfy_evidence() {
    let path = "fixture.rs";
    let syntax = syn::parse_file(
        "fn production_core() { reserve_send(); complete_send(); }\
         #[test] fn stable_path_proof() { assert!(true); }",
    )
    .expect("parse uncalled helper fixture");
    let parsed = BTreeMap::from([(path, syntax)]);
    let contract = TestContract::new(
        path,
        "stable_path_proof",
        &["reserve_send", "complete_send"],
    );
    assert_eq!(validate_contracts(&parsed, &[contract]).len(), 2);
}

#[test]
fn recursive_helper_graph_is_rejected_instead_of_satisfying_evidence() {
    let path = "fixture.rs";
    let syntax = syn::parse_file(
        "fn first(depth: usize) { if depth > 0 { second(depth - 1); } }\
         fn second(depth: usize) { complete_send(); first(depth); }\
         #[test] fn stable_path_proof() { first(1); }",
    )
    .expect("parse recursive helper fixture");
    let parsed = BTreeMap::from([(path, syntax)]);
    let contract = TestContract::new(path, "stable_path_proof", &["complete_send"]);
    assert!(
        validate_contracts(&parsed, &[contract])
            .iter()
            .any(|violation| violation.contains("recursive release-evidence helper graph"))
    );
}

#[test]
fn excessive_helper_depth_cannot_satisfy_release_evidence() {
    let path = "fixture.rs";
    let mut source = String::new();
    for index in 0..=super::function_logic::MAX_RESOLVED_CALL_DEPTH {
        if index == super::function_logic::MAX_RESOLVED_CALL_DEPTH {
            source.push_str(&format!("fn helper_{index}() {{ complete_send(); }}"));
        } else {
            source.push_str(&format!(
                "fn helper_{index}() {{ helper_{}(); }}",
                index + 1
            ));
        }
    }
    source.push_str("#[test] fn stable_path_proof() { helper_0(); }");
    let syntax = syn::parse_file(&source).expect("parse excessive-depth fixture");
    let parsed = BTreeMap::from([(path, syntax)]);
    let contract = TestContract::new(path, "stable_path_proof", &["complete_send"]);
    assert!(
        validate_contracts(&parsed, &[contract])
            .iter()
            .any(|violation| violation.contains("helper depth exceeds"))
    );
}
