use pkthere_test_support::managed_child::{ChildIdentity, ChildLimits, ManagedChild};
use pkthere_test_support::test_paths as path_policy;
use pkthere_test_support::timing::MAX_WAIT_SECS;

use proc_macro2::Span;
use quote::ToTokens;
use serde_json::Value as JsonValue;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::time::Instant;
use syn::parse::Parser;
use syn::spanned::Spanned;
use syn::visit::Visit;

#[path = "portable_policy.rs"]
mod portable_policy;

const MAX_SOURCE_LINES_EXCLUSIVE: usize = 1000;
const MAX_FACADE_LINES: usize = 200;
const DUPLICATE_FUNCTION_BODY_MIN_LEN: usize = 80;
const DUPLICATE_TEST_BODY_MIN_LEN: usize = 80;
const FACADE_ROOTS: &[&str] = &[
    "src/net/sock_mgr",
    "crates/wire/src/packet_headers",
    "src/worker_support/packet_admission",
    "tests/support/src/socket_reality",
];
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum PolicyKind {
    SyntacticDirectRecursion,
    WildcardImport,
    ForbiddenAllow,
    LoopbackAlias,
    UnconditionalDebug,
}

impl PolicyKind {
    fn description(self) -> &'static str {
        match self {
            Self::SyntacticDirectRecursion => "syntactic direct recursion",
            Self::WildcardImport => "wildcard import",
            Self::ForbiddenAllow => "forbidden allow attribute",
            Self::LoopbackAlias => "forbidden loopback alias",
            Self::UnconditionalDebug => "unconditional debug emission",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PolicyFinding {
    pub kind: PolicyKind,
    pub path: String,
    pub line: usize,
    pub item: String,
    pub cfg_domain: String,
    pub detail: String,
}

impl PolicyFinding {
    fn render(&self) -> String {
        let domain = if self.cfg_domain.is_empty() {
            String::new()
        } else {
            format!(" [{}]", self.cfg_domain)
        };
        format!(
            "{}:{}: {} in {}{}: {}",
            self.path,
            self.line,
            self.kind.description(),
            self.item,
            domain,
            self.detail
        )
    }
}

#[derive(Clone, Debug)]
struct FunctionRecord {
    path: String,
    line: usize,
    name: String,
    cfg_domain: String,
    is_test: bool,
    body: String,
}

#[derive(Debug)]
struct ParsedSource {
    findings: Vec<PolicyFinding>,
    functions: Vec<FunctionRecord>,
    top_level_items: Vec<TopLevelItem>,
}

#[derive(Debug)]
struct TopLevelItem {
    line: usize,
    kind: &'static str,
    facade_allowed: bool,
}

#[derive(Debug)]
struct WorkspaceInventory {
    repo_root: PathBuf,
    manifests: Vec<PathBuf>,
    sources: Vec<PathBuf>,
    has_custom_build_target: bool,
}

#[derive(Debug)]
struct WorkspaceAnalysis {
    inventory: WorkspaceInventory,
    parsed: BTreeMap<PathBuf, ParsedSource>,
}

pub fn assert_rust_source_files_stay_under_1000_lines() {
    let inventory = workspace_inventory();
    let offenders = inventory
        .sources
        .iter()
        .filter_map(|path| {
            let contents = read(path);
            let lines = contents.lines().count();
            (lines >= MAX_SOURCE_LINES_EXCLUSIVE)
                .then(|| format!("{} has {lines} lines", relative(&inventory.repo_root, path)))
        })
        .collect::<Vec<_>>();
    assert!(
        offenders.is_empty(),
        "Rust source files must stay under {MAX_SOURCE_LINES_EXCLUSIVE} lines:\n{}",
        offenders.join("\n")
    );
}

pub fn assert_tests_do_not_use_loopback_aliases() {
    assert_no_findings(&[PolicyKind::LoopbackAlias]);
}

pub fn assert_scoped_mod_files_are_small_facades() {
    let repo_root = repo_root();
    let mut files = Vec::new();
    for root in FACADE_ROOTS {
        collect_named_files(&repo_root.join(root), "mod.rs", &mut files);
    }
    let mut violations = Vec::new();
    for path in files {
        let rel = relative(&repo_root, &path);
        let contents = read(&path);
        let count = contents.lines().count();
        if count > MAX_FACADE_LINES {
            violations.push(format!("{rel} has {count} lines"));
        }
        let canonical = path.canonicalize().expect("canonical facade path");
        let parsed = workspace_analysis()
            .parsed
            .get(&canonical)
            .expect("facade belongs to workspace inventory");
        for item in &parsed.top_level_items {
            if !item.facade_allowed {
                violations.push(format!(
                    "{rel}:{} contains non-facade {}",
                    item.line, item.kind
                ));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "Scoped mod.rs files must be facade-only and at most {MAX_FACADE_LINES} lines:\n{}",
        violations.join("\n")
    );
}

pub fn assert_syntactic_direct_recursion_is_forbidden() {
    assert_no_findings(&[PolicyKind::SyntacticDirectRecursion]);
}

pub fn assert_dead_code_allows_are_forbidden() {
    assert_no_findings(&[PolicyKind::ForbiddenAllow]);
}

pub fn assert_no_wildcard_imports_in_project_rust_sources() {
    assert_no_findings(&[PolicyKind::WildcardImport]);
}

pub fn assert_protocol_helpers_do_not_emit_unrequested_debug_logs() {
    assert_no_findings_in_paths(
        &[PolicyKind::UnconditionalDebug],
        &["src/net/payload.rs", "src/net/socket.rs"],
    );
}

pub fn assert_legacy_text_scanners_are_forbidden() {
    let forbidden_names = [
        ["sanitize_rust_", "source"].concat(),
        ["find_function_", "defs"].concat(),
        ["collect_preceding_", "attrs"].concat(),
        ["strip_cfg_test_", "items"].concat(),
        ["detect_direct_recursion_", "in_rust_text"].concat(),
    ];
    let inventory = workspace_inventory();
    let violations = inventory
        .sources
        .iter()
        .filter_map(|path| {
            let source = read(path);
            forbidden_names
                .iter()
                .find(|name| source.contains(name.as_str()))
                .map(|name| {
                    format!(
                        "{} contains retired text scanner {name}",
                        relative(&inventory.repo_root, path)
                    )
                })
        })
        .collect::<Vec<_>>();
    assert!(
        violations.is_empty(),
        "legacy source scanners must not return:\n{}",
        violations.join("\n")
    );
}

pub fn assert_no_exact_duplicate_bodies_in_workspace() {
    let mut groups = BTreeMap::<(bool, String, String), Vec<&FunctionRecord>>::new();
    for parsed in workspace_analysis().parsed.values() {
        for function in &parsed.functions {
            let minimum = if function.is_test {
                DUPLICATE_TEST_BODY_MIN_LEN
            } else {
                DUPLICATE_FUNCTION_BODY_MIN_LEN
            };
            if function.body.len() >= minimum {
                groups
                    .entry((
                        function.is_test,
                        function.cfg_domain.clone(),
                        function.body.clone(),
                    ))
                    .or_default()
                    .push(function);
            }
        }
    }
    let violations = groups
        .into_values()
        .filter(|records| records.len() > 1)
        .map(|records| {
            let category = if records[0].is_test {
                "test"
            } else {
                "function"
            };
            let locations = records
                .iter()
                .map(|record| format!("{}:{}: {}()", record.path, record.line, record.name))
                .collect::<Vec<_>>()
                .join("\n  ");
            format!("exact duplicate {category} body in one cfg domain:\n  {locations}")
        })
        .collect::<Vec<_>>();
    assert!(
        violations.is_empty(),
        "Exact normalized function bodies are duplicated:\n{}",
        violations.join("\n")
    );
}

pub fn assert_portable_build_configuration() {
    portable_policy::assert_configuration(workspace_inventory());
}

fn analyze_rust_source(path: &str, source: &str) -> ParsedSource {
    let file = parse_file(path, source);
    let top_level_items = file
        .items
        .iter()
        .map(|item| TopLevelItem {
            line: line(item.span()),
            kind: item_kind(item),
            facade_allowed: matches!(
                item,
                syn::Item::Use(syn::ItemUse {
                    vis: syn::Visibility::Public(_) | syn::Visibility::Restricted(_),
                    ..
                }) | syn::Item::Mod(syn::ItemMod { content: None, .. })
            ),
        })
        .collect();
    let mut collector = AstCollector::new(path);
    collector.visit_file(&file);
    ParsedSource {
        findings: collector.findings,
        functions: collector.functions,
        top_level_items,
    }
}

fn assert_no_findings(kinds: &[PolicyKind]) {
    assert_no_findings_in_paths(kinds, &[]);
}

fn assert_no_findings_in_paths(kinds: &[PolicyKind], governed_paths: &[&str]) {
    let analysis = workspace_analysis();
    let expected = kinds.iter().copied().collect::<BTreeSet<_>>();
    let mut findings = Vec::new();
    for (path, parsed) in &analysis.parsed {
        let rel = relative(&analysis.inventory.repo_root, path);
        if !governed_paths.is_empty() && !governed_paths.contains(&rel.as_str()) {
            continue;
        }
        findings.extend(
            parsed
                .findings
                .iter()
                .filter(|finding| expected.contains(&finding.kind)),
        );
    }
    assert!(
        findings.is_empty(),
        "Rust syntax policy violations:\n{}",
        findings
            .iter()
            .map(|finding| finding.render())
            .collect::<Vec<_>>()
            .join("\n")
    );
}

struct AstCollector<'a> {
    path: &'a str,
    findings: Vec<PolicyFinding>,
    functions: Vec<FunctionRecord>,
    cfg_stack: Vec<String>,
    test_depth: usize,
    drop_impl_depth: usize,
}

impl<'a> AstCollector<'a> {
    fn new(path: &'a str) -> Self {
        Self {
            path,
            findings: Vec::new(),
            functions: Vec::new(),
            cfg_stack: Vec::new(),
            test_depth: 0,
            drop_impl_depth: 0,
        }
    }

    fn enter_attrs(&mut self, attrs: &[syn::Attribute]) -> (usize, usize) {
        let cfg_len = self.cfg_stack.len();
        let test_depth = self.test_depth;
        self.cfg_stack.extend(cfg_fragments(attrs));
        if attrs.iter().any(attr_is_test_context) {
            self.test_depth += 1;
        }
        (cfg_len, test_depth)
    }

    fn leave_attrs(&mut self, state: (usize, usize)) {
        self.cfg_stack.truncate(state.0);
        self.test_depth = state.1;
    }

    fn cfg_domain(&self) -> String {
        let mut fragments = self.cfg_stack.clone();
        fragments.sort();
        fragments.join(" && ")
    }

    fn record_function(&mut self, ident: &syn::Ident, block: &syn::Block, is_method: bool) {
        let name = ident.to_string();
        let mut recursion = RecursionVisitor::new(&name, is_method);
        recursion.visit_block(block);
        if recursion.found {
            self.findings.push(PolicyFinding {
                kind: PolicyKind::SyntacticDirectRecursion,
                path: self.path.to_string(),
                line: line(ident.span()),
                item: format!("{name}()"),
                cfg_domain: self.cfg_domain(),
                detail: "the body contains a syntactically self-directed call".to_string(),
            });
        }
        if self.drop_impl_depth == 0 || name != "drop" {
            self.functions.push(FunctionRecord {
                path: self.path.to_string(),
                line: line(ident.span()),
                name,
                cfg_domain: self.cfg_domain(),
                is_test: self.test_depth != 0,
                body: block.to_token_stream().to_string(),
            });
        }
    }
}

impl<'ast> Visit<'ast> for AstCollector<'_> {
    fn visit_lit_str(&mut self, value: &'ast syn::LitStr) {
        let text = value.value();
        for alias in [["127.0.0.", "2"].concat(), ["127.0.0.", "3"].concat()] {
            if text.contains(&alias) {
                self.findings.push(PolicyFinding {
                    kind: PolicyKind::LoopbackAlias,
                    path: self.path.to_string(),
                    line: line(value.span()),
                    item: "string literal".to_string(),
                    cfg_domain: self.cfg_domain(),
                    detail: format!("use localhost or ::1 instead of {alias}"),
                });
            }
        }
        syn::visit::visit_lit_str(self, value);
    }

    fn visit_attribute(&mut self, attr: &'ast syn::Attribute) {
        if attr.path().is_ident("allow") {
            let mut forbidden = Vec::new();
            let _ = attr.parse_nested_meta(|meta| {
                let name = path_string(&meta.path);
                if matches!(
                    name.as_str(),
                    "dead_code"
                        | "unused"
                        | "unused_imports"
                        | "unused_variables"
                        | "clippy::duplicate_mod"
                ) {
                    forbidden.push(name);
                }
                Ok(())
            });
            if !forbidden.is_empty() {
                self.findings.push(PolicyFinding {
                    kind: PolicyKind::ForbiddenAllow,
                    path: self.path.to_string(),
                    line: line(attr.span()),
                    item: "attribute".to_string(),
                    cfg_domain: self.cfg_domain(),
                    detail: format!("allow({}) is forbidden", forbidden.join(", ")),
                });
            }
        }
        syn::visit::visit_attribute(self, attr);
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        if use_tree_has_glob(&item.tree) {
            self.findings.push(PolicyFinding {
                kind: PolicyKind::WildcardImport,
                path: self.path.to_string(),
                line: line(item.span()),
                item: "use declaration".to_string(),
                cfg_domain: self.cfg_domain(),
                detail: "import exact names instead".to_string(),
            });
        }
        syn::visit::visit_item_use(self, item);
    }

    fn visit_macro(&mut self, item: &'ast syn::Macro) {
        if item
            .path
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "log_debug")
        {
            let parser = syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated;
            if let Ok(arguments) = parser.parse2(item.tokens.clone())
                && matches!(
                    arguments.first(),
                    Some(syn::Expr::Lit(syn::ExprLit {
                        lit: syn::Lit::Bool(value),
                        ..
                    })) if value.value
                )
            {
                self.findings.push(PolicyFinding {
                    kind: PolicyKind::UnconditionalDebug,
                    path: self.path.to_string(),
                    line: line(item.span()),
                    item: "log_debug!".to_string(),
                    cfg_domain: self.cfg_domain(),
                    detail: "debug output must be controlled by a diagnostics category".to_string(),
                });
            }
        }
        syn::visit::visit_macro(self, item);
    }

    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        let state = self.enter_attrs(&item.attrs);
        syn::visit::visit_item_mod(self, item);
        self.leave_attrs(state);
    }

    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        let state = self.enter_attrs(&item.attrs);
        let drop_impl = item.trait_.as_ref().is_some_and(|(path, _)| {
            path.segments
                .last()
                .is_some_and(|segment| segment.ident == "Drop")
        });
        if drop_impl {
            self.drop_impl_depth += 1;
        }
        syn::visit::visit_item_impl(self, item);
        if drop_impl {
            self.drop_impl_depth -= 1;
        }
        self.leave_attrs(state);
    }

    fn visit_item_trait(&mut self, item: &'ast syn::ItemTrait) {
        let state = self.enter_attrs(&item.attrs);
        syn::visit::visit_item_trait(self, item);
        self.leave_attrs(state);
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        let state = self.enter_attrs(&item.attrs);
        self.record_function(&item.sig.ident, &item.block, false);
        syn::visit::visit_item_fn(self, item);
        self.leave_attrs(state);
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        let state = self.enter_attrs(&item.attrs);
        self.record_function(&item.sig.ident, &item.block, true);
        syn::visit::visit_impl_item_fn(self, item);
        self.leave_attrs(state);
    }

    fn visit_trait_item_fn(&mut self, item: &'ast syn::TraitItemFn) {
        let state = self.enter_attrs(&item.attrs);
        if let Some(block) = &item.default {
            self.record_function(&item.sig.ident, block, true);
        }
        syn::visit::visit_trait_item_fn(self, item);
        self.leave_attrs(state);
    }
}

struct RecursionVisitor<'a> {
    name: &'a str,
    is_method: bool,
    found: bool,
}

impl<'a> RecursionVisitor<'a> {
    fn new(name: &'a str, is_method: bool) -> Self {
        Self {
            name,
            is_method,
            found: false,
        }
    }
}

impl<'ast> Visit<'ast> for RecursionVisitor<'_> {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            let segments = path
                .path
                .segments
                .iter()
                .map(|segment| segment.ident.to_string())
                .collect::<Vec<_>>();
            let bare_free = !self.is_method && segments.as_slice() == [self.name];
            let self_free = !self.is_method
                && segments.len() == 2
                && segments[0] == "self"
                && segments[1] == self.name;
            let self_associated = self.is_method
                && segments.len() == 2
                && segments[0] == "Self"
                && segments[1] == self.name;
            self.found |= bare_free || self_free || self_associated;
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        let self_receiver = matches!(
            &*call.receiver,
            syn::Expr::Path(path) if path.path.is_ident("self")
        );
        self.found |= self.is_method && self_receiver && call.method == self.name;
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_item_fn(&mut self, _item: &'ast syn::ItemFn) {}
    fn visit_impl_item_fn(&mut self, _item: &'ast syn::ImplItemFn) {}
    fn visit_trait_item_fn(&mut self, _item: &'ast syn::TraitItemFn) {}
}

fn workspace_inventory() -> &'static WorkspaceInventory {
    &workspace_analysis().inventory
}

fn workspace_analysis() -> &'static WorkspaceAnalysis {
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
    inventory_from_metadata(&repo_root, &metadata)
}

fn inventory_from_metadata(repo_root: &Path, metadata: &JsonValue) -> WorkspaceInventory {
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

    let root_set = roots.iter().cloned().collect::<BTreeSet<_>>();
    let mut canonical_sources = BTreeSet::new();
    for package_root in &roots {
        collect_package_sources(repo_root, package_root, &root_set, &mut canonical_sources);
    }
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

fn build_surface_paths(inventory: &WorkspaceInventory) -> Vec<PathBuf> {
    let mut paths = inventory.manifests.clone();
    for cargo_config in [".cargo/config", ".cargo/config.toml"] {
        let path = inventory.repo_root.join(cargo_config);
        if path.exists() {
            paths.push(path);
        }
    }
    paths.push(inventory.repo_root.join("Cross.toml"));
    paths.push(inventory.repo_root.join(".github/workflows/rust.yml"));
    paths.push(inventory.repo_root.join("docker/rust_build/Dockerfile"));
    paths.extend(
        inventory
            .sources
            .iter()
            .filter(|path| path.file_name().is_some_and(|name| name == "build.rs"))
            .cloned(),
    );
    for root in [".github/scripts", "docker/alpine"] {
        collect_extensions(
            &inventory.repo_root.join(root),
            &["sh", "py", "toml", "yml", "yaml"],
            &mut paths,
        );
    }
    paths.sort();
    paths.dedup();
    paths
}

fn collect_extensions(root: &Path, extensions: &[&str], output: &mut Vec<PathBuf>) {
    if !root.exists() {
        return;
    }
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory).expect("build surface directory") {
            let path = entry.expect("build surface entry").path();
            if path.is_dir() {
                pending.push(path);
            } else if path
                .extension()
                .and_then(|value| value.to_str())
                .is_some_and(|extension| extensions.contains(&extension))
            {
                output.push(path);
            }
        }
    }
}

fn cfg_fragments(attrs: &[syn::Attribute]) -> Vec<String> {
    attrs
        .iter()
        .filter(|attr| attr.path().is_ident("cfg") || attr.path().is_ident("cfg_attr"))
        .map(|attr| attr.meta.to_token_stream().to_string())
        .collect()
}

fn attr_is_test_context(attr: &syn::Attribute) -> bool {
    if attr
        .path()
        .segments
        .last()
        .is_some_and(|segment| segment.ident == "test")
    {
        return true;
    }
    (attr.path().is_ident("cfg") || attr.path().is_ident("cfg_attr"))
        && token_stream_has_ident(attr.meta.to_token_stream(), "test")
}

fn token_stream_has_ident(stream: proc_macro2::TokenStream, expected: &str) -> bool {
    let mut pending = stream.into_iter().collect::<Vec<_>>();
    while let Some(token) = pending.pop() {
        match token {
            proc_macro2::TokenTree::Ident(ident) if ident == expected => return true,
            proc_macro2::TokenTree::Group(group) => pending.extend(group.stream()),
            _ => {}
        }
    }
    false
}

fn use_tree_has_glob(tree: &syn::UseTree) -> bool {
    let mut pending = vec![tree];
    while let Some(tree) = pending.pop() {
        match tree {
            syn::UseTree::Glob(_) => return true,
            syn::UseTree::Group(group) => pending.extend(group.items.iter()),
            syn::UseTree::Path(path) => pending.push(&path.tree),
            syn::UseTree::Name(_) | syn::UseTree::Rename(_) => {}
        }
    }
    false
}

fn path_string(path: &syn::Path) -> String {
    path.segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>()
        .join("::")
}

fn parse_file(path: &str, source: &str) -> syn::File {
    syn::parse_file(source).unwrap_or_else(|error| panic!("failed to parse {path}: {error}"))
}

fn line(span: Span) -> usize {
    span.start().line
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .canonicalize()
        .expect("canonical repository root")
}

fn relative(root: &Path, path: &Path) -> String {
    path_policy::render_repo_relative_path(root, path)
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

fn collect_named_files(root: &Path, name: &str, output: &mut Vec<PathBuf>) {
    if !root.exists() {
        return;
    }
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory).expect("facade directory") {
            let path = entry.expect("facade entry").path();
            if path.is_dir() {
                pending.push(path);
            } else if path.file_name().and_then(|value| value.to_str()) == Some(name) {
                output.push(path);
            }
        }
    }
    output.sort();
}

fn item_kind(item: &syn::Item) -> &'static str {
    match item {
        syn::Item::Const(_) => "const",
        syn::Item::Enum(_) => "enum",
        syn::Item::Fn(_) => "function",
        syn::Item::Impl(_) => "impl",
        syn::Item::Macro(_) => "macro",
        syn::Item::Mod(_) => "inline module",
        syn::Item::Static(_) => "static",
        syn::Item::Struct(_) => "struct",
        syn::Item::Trait(_) => "trait",
        syn::Item::Type(_) => "type alias",
        syn::Item::Union(_) => "union",
        _ => "unsupported item",
    }
}

#[cfg(test)]
#[path = "policy_tests.rs"]
mod tests;
