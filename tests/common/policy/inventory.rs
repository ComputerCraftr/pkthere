use super::{WorkspaceAnalysis, WorkspaceInventory, analyze_rust_source};
use crate::common::source_layout_policy::{self, SourceKind};
use pkthere_test_support::managed_child::{ChildIdentity, ChildLimits, ManagedChild};
use pkthere_test_support::test_paths as path_policy;
use pkthere_test_support::timing::MAX_WAIT_SECS;
use proc_macro2::Span;
use serde_json::Value as JsonValue;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::time::Instant;

pub(super) fn workspace_inventory() -> &'static WorkspaceInventory {
    &workspace_analysis().inventory
}

pub(super) fn workspace_analysis() -> &'static WorkspaceAnalysis {
    static ANALYSIS: OnceLock<WorkspaceAnalysis> = OnceLock::new();
    ANALYSIS.get_or_init(|| {
        let inventory = load_workspace_inventory();
        let parsed = inventory
            .sources
            .iter()
            .map(|path| {
                let relative_path = relative(&inventory.repo_root, path);
                (
                    path.clone(),
                    analyze_rust_source(&relative_path, &read(path)),
                )
            })
            .collect();
        WorkspaceAnalysis { inventory, parsed }
    })
}

fn load_workspace_inventory() -> WorkspaceInventory {
    let repo_root = repo_root();
    let mut command = Command::new(env!("CARGO"));
    command.current_dir(&repo_root).args([
        "metadata",
        "--locked",
        "--format-version",
        "1",
        "--no-deps",
    ]);
    let child = ManagedChild::spawn(
        &mut command,
        ChildIdentity::new("workspace cargo metadata"),
        ChildLimits::default(),
    )
    .expect("spawn cargo metadata");
    let completed = child
        .wait_until(Instant::now() + MAX_WAIT_SECS)
        .expect("bounded cargo metadata");
    assert!(
        completed.exit.success,
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&completed.output.stderr)
    );
    let metadata: JsonValue =
        serde_json::from_slice(&completed.output.stdout).expect("parse cargo metadata JSON");
    inventory_from_metadata_with_sources(
        &repo_root,
        &metadata,
        source_layout_policy::governed_source_paths(Some(SourceKind::Rust)),
    )
}

pub(super) fn inventory_from_metadata(
    repo_root: &Path,
    metadata: &JsonValue,
) -> WorkspaceInventory {
    inventory_from_metadata_with_sources(repo_root, metadata, Vec::new())
}

fn inventory_from_metadata_with_sources(
    repo_root: &Path,
    metadata: &JsonValue,
    authoritative_sources: Vec<PathBuf>,
) -> WorkspaceInventory {
    let workspace_ids = metadata["workspace_members"]
        .as_array()
        .expect("workspace member IDs")
        .iter()
        .filter_map(JsonValue::as_str)
        .collect::<BTreeSet<_>>();
    let packages = metadata["packages"].as_array().expect("metadata packages");
    let mut manifests = Vec::new();
    let mut roots = Vec::new();
    let mut has_custom_build_target = false;
    for package in packages {
        let id = package["id"].as_str().expect("package id");
        if !workspace_ids.contains(id) {
            continue;
        }
        let manifest = PathBuf::from(package["manifest_path"].as_str().expect("manifest path"));
        let root = manifest
            .parent()
            .expect("package root")
            .canonicalize()
            .expect("canonical package root");
        assert!(
            root.starts_with(repo_root),
            "workspace package escapes repository: {}",
            root.display()
        );
        manifests.push(manifest);
        roots.push(root);
        has_custom_build_target |= package["targets"]
            .as_array()
            .expect("package targets")
            .iter()
            .any(|target| {
                target["kind"].as_array().is_some_and(|kinds| {
                    kinds
                        .iter()
                        .any(|kind| kind.as_str() == Some("custom-build"))
                })
            });
    }
    roots.sort();
    roots.dedup();
    manifests.sort();

    let canonical_sources = if authoritative_sources.is_empty() {
        let root_set = roots.iter().cloned().collect::<BTreeSet<_>>();
        let mut fixture_sources = BTreeSet::new();
        for package_root in &roots {
            collect_package_sources(repo_root, package_root, &root_set, &mut fixture_sources);
        }
        fixture_sources
    } else {
        authoritative_sources.into_iter().collect()
    };
    WorkspaceInventory {
        repo_root: repo_root.to_path_buf(),
        manifests,
        sources: canonical_sources.into_iter().collect(),
        has_custom_build_target,
    }
}

fn collect_package_sources(
    repo_root: &Path,
    package_root: &Path,
    package_roots: &BTreeSet<PathBuf>,
    sources: &mut BTreeSet<PathBuf>,
) {
    let mut pending = vec![package_root.to_path_buf()];
    let mut visited = BTreeSet::new();
    while let Some(directory) = pending.pop() {
        let canonical_directory = directory
            .canonicalize()
            .expect("canonical source directory");
        assert!(
            canonical_directory.starts_with(repo_root),
            "source directory symlink escapes repository: {}",
            directory.display()
        );
        if !visited.insert(canonical_directory.clone()) {
            continue;
        }
        let mut entries = fs::read_dir(&directory)
            .unwrap_or_else(|error| panic!("read {}: {error}", directory.display()))
            .map(|entry| entry.expect("source entry"))
            .collect::<Vec<_>>();
        entries.sort_by_key(std::fs::DirEntry::path);
        for entry in entries {
            let path = entry.path();
            let file_type = entry.file_type().expect("source file type");
            let canonical = path.canonicalize().expect("canonical source path");
            assert!(
                canonical.starts_with(repo_root),
                "source symlink escapes repository: {}",
                path.display()
            );
            if file_type.is_dir() || file_type.is_symlink() && canonical.is_dir() {
                let name = path
                    .file_name()
                    .and_then(|value| value.to_str())
                    .unwrap_or_default();
                if matches!(
                    name,
                    "target" | ".git" | ".artifacts" | "docker-artifacts" | "cross-artifacts"
                ) {
                    continue;
                }
                if canonical != *package_root && package_roots.contains(&canonical) {
                    continue;
                }
                pending.push(path);
            } else if canonical.extension().and_then(|value| value.to_str()) == Some("rs") {
                sources.insert(canonical);
            }
        }
    }
}

pub(super) fn parse_file(path: &str, source: &str) -> syn::File {
    syn::parse_file(source).unwrap_or_else(|error| panic!("failed to parse {path}: {error}"))
}

pub(super) fn source_line(span: Span) -> usize {
    span.start().line
}

pub(super) fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .canonicalize()
        .expect("canonical repository root")
}

pub(super) fn relative(root: &Path, path: &Path) -> String {
    path_policy::render_repo_relative_path(root, path)
}

pub(super) fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}
