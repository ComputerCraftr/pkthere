use super::{PolicyFinding, PolicyKind, analyze_rust_source, inventory_from_metadata, repo_root};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMP_REPOSITORY: AtomicU64 = AtomicU64::new(0);

fn findings(source: &str, kind: PolicyKind) -> Vec<PolicyFinding> {
    analyze_rust_source("fixture.rs", source)
        .findings
        .into_iter()
        .filter(|finding| finding.kind == kind)
        .collect()
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
fn syntax_policies_parse_multiline_attributes_globs_and_ignore_literals() {
    let source = r##"
        const TEXT: &str = r#"#[allow(dead_code)] use super::*;"#;
        #[allow(
            unused_imports,
            clippy::duplicate_mod
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
    let _ = analyze_rust_source("fixture.rs", "fn broken(");
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
