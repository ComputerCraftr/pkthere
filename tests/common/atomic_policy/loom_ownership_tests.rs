use super::loom_ownership::{
    CallPattern, calls_from_module, core_bindings, defines_symbol, has_forbidden_model_name,
    loom_test_names, parse_sources, positive_test_uses_registered_core, reachable_function_facts,
    syntax_facts,
};
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn assert_exact_positive_loom_test_contracts() {
    let root_path = crate::common::policy::repository_root();
    let root = root_path.as_path();
    let parsed = parse_sources(
        root,
        &crate::common::source_layout_policy::rust_source_paths_under(&[root.join("src")]),
    );
    let mut registered = BTreeMap::new();
    for binding in core_bindings() {
        let syntax = parsed
            .get(binding.loom_source)
            .unwrap_or_else(|| panic!("missing exact Loom source {}", binding.loom_source));
        let source_tests = loom_test_names(syntax).into_iter().collect::<BTreeSet<_>>();
        for test in binding.id.positive_tests() {
            assert!(
                source_tests.contains(*test),
                "{}::{test}: exact Loom contract names no positive test",
                binding.loom_source
            );
            assert!(
                positive_test_uses_registered_core(syntax, test, binding.loom_call),
                "{}::{test}: does not transitively call its exact production core through {:?}",
                binding.loom_source,
                binding.loom_call
            );
            let facts = reachable_function_facts(syntax, test);
            for required in binding.loom_required_calls {
                assert!(
                    facts.calls(*required),
                    "{}::{test}: misses required transaction operation {required:?}",
                    binding.loom_source
                );
            }
            assert!(
                registered
                    .insert((binding.loom_source, *test), binding.loom_call)
                    .is_none(),
                "{}::{test}: positive Loom test has more than one ownership contract",
                binding.loom_source
            );
        }
        for test in binding.id.negative_tests() {
            assert!(
                source_tests.contains(*test),
                "{}::{test}: exact negative Loom contract names no test",
                binding.loom_source
            );
            assert!(
                registered
                    .insert((binding.loom_source, *test), binding.loom_call)
                    .is_none(),
                "{}::{test}: Loom test has more than one evidence contract",
                binding.loom_source
            );
        }
    }

    for (source, test) in super::loom_ownership::primitive_loom_tests() {
        let syntax = parsed
            .get(*source)
            .unwrap_or_else(|| panic!("missing primitive Loom source {source}"));
        assert!(loom_test_names(syntax).iter().any(|name| name == test));
        assert!(
            registered
                .insert((*source, *test), CallPattern::free("primitive"))
                .is_none()
        );
    }

    for (source, syntax) in &parsed {
        if !syntax_facts(syntax, false).loom_reference {
            continue;
        }
        for test in loom_test_names(syntax) {
            assert!(
                registered.contains_key(&(source.as_str(), test.as_str())),
                "{source}::{test}: positive Loom test has no exact production-core contract"
            );
        }
    }
}

#[test]
fn loom_detection_ignores_comments_and_literals() {
    let syntax =
        syn::parse_file(r#"fn evidence() { let _comment = "loom::model is not a call"; }"#)
            .expect("parse literal fixture");
    assert!(!syntax_facts(&syntax, false).loom_reference);
}

#[test]
fn associated_call_detection_requires_an_ast_call() {
    let decorative = syn::parse_file(r#"struct Core; fn evidence() { let _name = "Core::new"; }"#)
        .expect("parse decorative fixture");
    assert!(defines_symbol(&decorative, "Core"));
    assert!(!syntax_facts(&decorative, false).calls(CallPattern::associated("Core", "new")));

    let called = syn::parse_file(r#"fn production() { Core::new(); }"#)
        .expect("parse production call fixture");
    assert!(syntax_facts(&called, true).calls(CallPattern::associated("Core", "new")));
}

#[test]
fn model_name_policy_uses_function_identifiers() {
    let literal = syn::parse_file(r#"fn valid() { let _name = "model_only_fake"; }"#)
        .expect("parse model literal");
    assert!(!has_forbidden_model_name(&literal));
    let function = syn::parse_file(r#"fn model_only_fake() {}"#).expect("parse model function");
    assert!(has_forbidden_model_name(&function));
}

#[test]
fn production_callers_require_the_registered_module_identity() {
    let unrelated = syn::parse_file(r#"use crate::other::publish; fn production() { publish(); }"#)
        .expect("parse unrelated call fixture");
    assert!(calls_from_module(&unrelated, &["crate", "atomic_core"], true).is_empty());

    let registered = syn::parse_file(
        r#"use crate::atomic_core::publish as publish_core; fn production() { publish_core(); }"#,
    )
    .expect("parse registered call fixture");
    assert_eq!(
        calls_from_module(&registered, &["crate", "atomic_core"], true),
        std::collections::BTreeSet::from(["publish".to_string()])
    );
}
