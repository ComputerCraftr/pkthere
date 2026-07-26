use super::rust_semantics::{
    calls, defines, expression_identifiers, function_names_with_prefix,
    raw_rust_source_semantic_scans, raw_rust_source_semantic_scans_with_readers, references_ident,
    source_text_reader_functions, token_identifiers, type_identifiers,
};

#[test]
fn fragmented_phase_api_policy_uses_function_ast_not_text() {
    let syntax = syn::parse_file(
        r#"
            // fn refresh_comment_decoy() {}
            const TEXT: &str = "fn refresh_literal_decoy() {}";
            struct Owner;
            impl Owner {
                fn refresh_actual_phase(&mut self) {}
                fn current_version(&self) -> u64 { 0 }
                fn ensure_transaction(&mut self) {}
            }
        "#,
    )
    .expect("parse fragmented phase API fixture");
    assert_eq!(
        function_names_with_prefix(&syntax, "refresh"),
        ["refresh_actual_phase"]
    );
    assert_eq!(
        function_names_with_prefix(&syntax, "current_version"),
        ["current_version"]
    );
}

#[test]
fn comments_and_literals_are_not_semantic_evidence() {
    let syntax = syn::parse_file(
        r#"
            // fn required() {}
            const TEXT: &str = "required(); ForbiddenType";
            fn actual() {}
        "#,
    )
    .expect("parse semantic fixture");
    assert!(!defines(&syntax, "required"));
    assert!(!calls(&syntax, &["required"]));
    assert!(!references_ident(&syntax, "ForbiddenType"));
    assert!(defines(&syntax, "actual"));
}

#[test]
fn semantic_identifier_scans_ignore_literal_text_and_follow_nested_syntax() {
    let expression: syn::Expr =
        syn::parse_str(r#"actual.socket("backend Mutex")"#).expect("parse expression fixture");
    let expression_names = expression_identifiers(&expression);
    assert!(expression_names.contains("actual"));
    assert!(expression_names.contains("socket"));
    assert!(!expression_names.contains("backend"));
    assert!(!expression_names.contains("Mutex"));

    let ty: syn::Type = syn::parse_str("Option<Box<AtomicU64>>").expect("parse type fixture");
    let type_names = type_identifiers(&ty);
    assert!(type_names.contains("AtomicU64"));

    let tokens: proc_macro2::TokenStream = "generated!(Mutex, \"AtomicU64\")"
        .parse()
        .expect("parse token fixture");
    let token_names = token_identifiers(tokens);
    assert!(token_names.contains("Mutex"));
    assert!(!token_names.contains("AtomicU64"));
}

#[test]
fn rust_source_semantics_must_not_use_substring_scans() {
    let invalid = syn::parse_file(
        r#"
            fn audit(path: &Path) {
                let source = std::fs::read_to_string(path).unwrap();
                assert!(source.contains("required_call()"));
            }
        "#,
    )
    .expect("parse raw semantic scan fixture");
    assert_eq!(
        raw_rust_source_semantic_scans(&invalid),
        ["contains() on raw read_to_string source"]
    );

    let valid = syn::parse_file(
        r#"
            fn audit(path: &Path) {
                let source = std::fs::read_to_string(path).unwrap();
                let syntax = syn::parse_file(&source).unwrap();
                assert!(calls(&syntax, "required_call"));
                let decoy = "source.contains(\"required_call()\")";
                drop(decoy);
            }
        "#,
    )
    .expect("parse AST-backed semantic scan fixture");
    assert!(raw_rust_source_semantic_scans(&valid).is_empty());
}

#[test]
fn rust_source_semantic_scan_audit_follows_chains_and_borrowed_aliases() {
    let syntax = syn::parse_file(
        r#"
            fn chained(path: &Path) {
                assert!(std::fs::read_to_string(path).unwrap().contains("required_call()"));
            }

            fn aliased(path: &Path) {
                let source = std::fs::read_to_string(path).unwrap();
                let borrowed = &source;
                let forwarded: &str = borrowed.as_str();
                assert!(forwarded.find("required_call()").is_some());
            }
        "#,
    )
    .expect("parse chained raw-source fixture");
    assert_eq!(
        raw_rust_source_semantic_scans(&syntax),
        [
            "contains() on raw read_to_string source",
            "find() on raw read_to_string source",
        ]
    );
}

#[test]
fn rust_source_semantic_scan_follows_reader_helpers_but_stops_at_parsers() {
    let syntax = syn::parse_file(
        r#"
            fn read(path: &Path) -> String {
                std::fs::read_to_string(path).unwrap()
            }

            fn audit(path: &Path) {
                assert!(read(path).starts_with("fn required_call"));
                let syntax = syn::parse_file(&read(path)).unwrap();
                assert!(syntax.items.iter().any(|item| matches!(item, syn::Item::Fn(_))));
            }
        "#,
    )
    .expect("parse helper-reader fixture");
    assert_eq!(
        raw_rust_source_semantic_scans(&syntax),
        ["starts_with() on raw read_to_string source"]
    );
}

#[test]
fn rust_source_semantic_scan_follows_cross_module_reader_helpers() {
    let reader = syn::parse_file(
        r#"fn read(path: &Path) -> String { std::fs::read_to_string(path).unwrap() }"#,
    )
    .expect("parse source-reader module");
    let consumer = syn::parse_file(
        r#"fn audit(path: &Path) { assert!(super::read(path).contains("required")); }"#,
    )
    .expect("parse source-reader consumer");
    let readers = source_text_reader_functions(&reader, &std::collections::BTreeSet::new());
    assert_eq!(
        raw_rust_source_semantic_scans_with_readers(&consumer, &readers),
        ["contains() on raw read_to_string source"]
    );
}
