use proc_macro2::Span;
use quote::ToTokens;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use syn::parse::Parser;
use syn::spanned::Spanned;
use syn::visit::Visit;
mod audit_authority_policy;
#[cfg(test)]
mod audit_authority_policy_tests;
mod debug_assertion_policy;
mod failure_containment_policy;
mod finding_assertions;
mod function_logic;
#[cfg(test)]
mod graph_policy_tests;
mod inventory;
mod policy_syntax;
mod policy_types;
mod portable_policy;
mod release_evidence_policy;
#[cfg(test)]
mod release_evidence_policy_tests;
#[cfg(test)]
mod reservation_policy_tests;
mod socket_authority_policy;
#[cfg(test)]
mod socket_reality_policy_tests;
mod test_execution_policy;
#[cfg(test)]
mod test_execution_policy_tests;
mod workflow_policy;
#[cfg(test)]
mod workflow_policy_tests;
use crate::common::rust_semantics::{atomic_operation_method, expression_uses_seq_cst};
use function_logic::{
    BindingCollector, DuplicateBodyKind, FunctionCallCollector, canonical_function_body,
    contains_direct_recursion, duplicate_body_kind, expression_ast_depth,
    function_graph_violations, module_scope_for_path,
};
use inventory::{
    inventory_from_metadata, parse_file, read, relative, repo_root, source_line as line,
    workspace_analysis, workspace_inventory,
};
use policy_syntax::{
    TargetMask, attr_is_test_context, cfg_attr_has_ident, cfg_fragments, cfg_target_mask,
    path_string, use_tree_has_glob,
};
use policy_types::{PolicyFinding, PolicyKind};
pub use test_execution_policy::assert_tests_do_not_return_without_running;
const POSIX_PRIVATE_TEMP_ROOT: &str = concat!("/private/", "tmp");
const POSIX_TEMP_ROOT: &str = concat!("/", "tmp");

#[derive(Clone, Debug)]
struct FunctionRecord {
    path: String,
    line: usize,
    name: String,
    cfg_domain: String,
    target_mask: TargetMask,
    is_test: bool,
    duplicate_body_kind: DuplicateBodyKind,
    explicit_argument_count: usize,
    has_receiver: bool,
    module: String,
    scope: String,
    calls: BTreeSet<function_logic::CallReference>,
    ast_depth: usize,
    body: String,
}

#[derive(Debug)]
struct ParsedSource {
    findings: Vec<PolicyFinding>,
    functions: Vec<FunctionRecord>,
    displaced_module_constants: Vec<(usize, String)>,
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

pub fn assert_rust_items_have_bounded_complexity() {
    crate::common::source_layout_policy::assert_repository_valid();
}

pub fn assert_ci_workflow_has_executable_semantics() {
    workflow_policy::assert_ci_workflow_has_executable_semantics();
}

pub fn assert_release_evidence_tests_execute_required_semantics() {
    release_evidence_policy::assert_release_evidence_tests_execute_required_semantics();
}

pub(super) fn repository_root() -> PathBuf {
    repo_root()
}

pub fn assert_tests_do_not_use_loopback_aliases() {
    assert_no_findings(&[PolicyKind::LoopbackAlias]);
}

pub fn assert_rust_sources_use_platform_temporary_directories() {
    assert_no_findings(&[PolicyKind::HardcodedTemporaryRoot]);
}

pub fn assert_module_constants_are_grouped_at_the_top() {
    let analysis = workspace_analysis();
    let violations = analysis
        .parsed
        .iter()
        .flat_map(|(path, parsed)| {
            let relative = relative(&analysis.inventory.repo_root, path);
            parsed
                .displaced_module_constants
                .iter()
                .map(move |(line, scope)| {
                    format!(
                        "{relative}:{line}: module-level const/static in {scope} follows a runtime item"
                    )
                })
        })
        .collect::<Vec<_>>();
    assert!(
        violations.is_empty(),
        "Module-level constants and statics must be grouped after imports/module declarations and before runtime items:\n{}",
        violations.join("\n")
    );
}

pub fn assert_production_protocols_use_explicit_publication_ordering() {
    assert_no_findings(&[PolicyKind::SequentiallyConsistentProtocol]);
}

pub fn assert_syntactic_direct_recursion_is_forbidden() {
    assert_no_findings(&[PolicyKind::SyntacticDirectRecursion]);
    let violations = function_graph_violations(
        workspace_analysis()
            .parsed
            .values()
            .flat_map(|parsed| parsed.functions.iter()),
    );
    assert!(
        violations.is_empty(),
        "Recursive or excessively deep function graphs are forbidden:\n{}",
        violations.join("\n")
    );
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

pub fn assert_endpoint_and_socket_authority_is_centralized() {
    assert_no_findings(&[
        PolicyKind::RetiredEndpointAuthority,
        PolicyKind::SocketLifecycleAuthority,
        PolicyKind::InlineSocketPlatformDecision,
    ]);
}

pub fn assert_manager_version_authority_is_transactional() {
    assert_no_findings(&[PolicyKind::ManagerVersionAuthority]);
}

pub fn assert_stats_and_required_evidence_fail_closed() {
    assert_no_findings(&[
        PolicyKind::CoherentStatsAuthority,
        PolicyKind::RequiredEvidenceDefault,
    ]);
}

pub fn assert_production_code_has_no_debug_only_assertions() {
    assert_no_findings(&[PolicyKind::ProductionDebugAssertion]);
}

pub fn assert_production_code_has_no_explicit_panic_surfaces() {
    assert_no_findings(&[PolicyKind::ProductionPanicSurface]);
}

pub fn assert_failure_containment_is_fail_closed() {
    assert_no_findings(&[PolicyKind::FailureContainmentAuthority]);
}

pub fn assert_interior_mutability_authorities_are_registered() {
    assert_no_findings(&[PolicyKind::InteriorMutabilityAuthority]);
}

pub fn assert_production_types_have_no_mutable_test_only_authority() {
    assert_no_findings(&[PolicyKind::TestStateAuthority]);
}

pub fn assert_no_duplicate_function_logic_in_workspace() {
    let violations = duplicate_logic_violations(
        workspace_analysis()
            .parsed
            .values()
            .flat_map(|parsed| parsed.functions.iter()),
    );
    assert!(
        violations.is_empty(),
        "AST-normalized function logic is duplicated:\n{}",
        violations.join("\n")
    );
}

pub fn assert_rust_source_semantic_policies_are_ast_backed() {
    let root = repo_root();
    let policy_root = root.join("tests/common");
    let parsed = workspace_inventory()
        .sources
        .iter()
        .filter(|source| source.starts_with(&policy_root))
        .map(|source| (source, crate::common::rust_semantics::parse_file(source)))
        .collect::<Vec<_>>();
    let mut source_readers = std::collections::BTreeSet::new();
    loop {
        let mut changed = false;
        for (_, syntax) in &parsed {
            for reader in
                crate::common::rust_semantics::source_text_reader_functions(syntax, &source_readers)
            {
                changed |= source_readers.insert(reader);
            }
        }
        if !changed {
            break;
        }
    }
    let violations = parsed
        .iter()
        .filter_map(|(source, syntax)| {
            let scans = crate::common::rust_semantics::raw_rust_source_semantic_scans_with_readers(
                syntax,
                &source_readers,
            );
            (!scans.is_empty())
                .then(|| format!("{}: {}", relative(&root, source), scans.join(", ")))
        })
        .collect::<Vec<_>>();
    assert!(
        violations.is_empty(),
        "Rust source semantics must be derived from parsed ASTs, not raw text:\n{}",
        violations.join("\n")
    );
}

fn duplicate_logic_violations<'a>(
    functions: impl IntoIterator<Item = &'a FunctionRecord>,
) -> Vec<String> {
    let mut groups = BTreeMap::<(bool, String), Vec<&FunctionRecord>>::new();
    for function in functions {
        if function.duplicate_body_kind == DuplicateBodyKind::TrivialAdapter {
            continue;
        }
        groups
            .entry((function.is_test, function.body.clone()))
            .or_default()
            .push(function);
    }
    groups
        .into_values()
        .filter(|records| {
            records.iter().enumerate().any(|(index, left)| {
                records[index + 1..]
                    .iter()
                    .any(|right| left.target_mask.overlaps(right.target_mask))
            })
        })
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
            format!("alpha-equivalent duplicate {category} logic in one cfg domain:\n  {locations}")
        })
        .collect()
}

pub fn assert_portable_build_configuration() {
    portable_policy::assert_configuration(workspace_inventory());
}

fn analyze_rust_source(path: &str, source: &str) -> ParsedSource {
    let file = parse_file(path, source);
    let socket_aliases = socket_authority_policy::socket_type_aliases(&file);
    let mut displaced_module_constants = Vec::new();
    finding_assertions::collect_displaced_constants(
        &file.items,
        "crate",
        &mut displaced_module_constants,
    );
    let mut collector = AstCollector::new(path, socket_aliases);
    let file_state = collector.enter_attrs(&file.attrs);
    collector.visit_file(&file);
    collector.leave_attrs(file_state);
    ParsedSource {
        findings: collector.findings,
        functions: collector.functions,
        displaced_module_constants,
    }
}

fn assert_no_findings(kinds: &[PolicyKind]) {
    assert_no_findings_in_paths(kinds, &[]);
}

fn assert_no_findings_in_paths(kinds: &[PolicyKind], governed_paths: &[&str]) {
    finding_assertions::assert_none(workspace_analysis(), kinds, governed_paths);
}

struct AstCollector<'a> {
    path: &'a str,
    findings: Vec<PolicyFinding>,
    functions: Vec<FunctionRecord>,
    cfg_stack: Vec<String>,
    target_mask: TargetMask,
    test_depth: usize,
    const_depth: usize,
    drop_impl_depth: usize,
    trait_impl_depth: usize,
    function_depth: usize,
    socket_aliases: BTreeSet<String>,
    scope: Vec<String>,
    module_depth: usize,
    generic_type_scopes: Vec<BTreeSet<String>>,
}

impl<'a> AstCollector<'a> {
    fn new(path: &'a str, socket_aliases: BTreeSet<String>) -> Self {
        Self {
            path,
            findings: Vec::new(),
            functions: Vec::new(),
            cfg_stack: Vec::new(),
            target_mask: TargetMask::all(),
            test_depth: 0,
            const_depth: 0,
            drop_impl_depth: 0,
            trait_impl_depth: 0,
            function_depth: 0,
            socket_aliases,
            scope: vec![module_scope_for_path(path)],
            module_depth: 1,
            generic_type_scopes: Vec::new(),
        }
    }

    fn enter_generics(&mut self, generics: &syn::Generics) {
        self.generic_type_scopes.push(
            generics
                .params
                .iter()
                .filter_map(|parameter| match parameter {
                    syn::GenericParam::Type(parameter) => Some(parameter.ident.to_string()),
                    syn::GenericParam::Lifetime(_) | syn::GenericParam::Const(_) => None,
                })
                .collect(),
        );
    }

    fn leave_generics(&mut self) {
        drop(self.generic_type_scopes.pop());
    }

    fn generic_type_shadows(&self, path: &syn::Path) -> bool {
        path.leading_colon.is_none()
            && path.segments.len() == 1
            && self.generic_type_scopes.iter().rev().any(|scope| {
                path.segments
                    .first()
                    .is_some_and(|segment| scope.contains(&segment.ident.to_string()))
            })
    }

    fn enter_attrs(&mut self, attrs: &[syn::Attribute]) -> (usize, usize, TargetMask) {
        let cfg_len = self.cfg_stack.len();
        let test_depth = self.test_depth;
        let target_mask = self.target_mask;
        self.cfg_stack.extend(cfg_fragments(attrs));
        self.target_mask = self.target_mask.intersect(cfg_target_mask(attrs));
        if attrs.iter().any(attr_is_test_context) {
            self.test_depth += 1;
        }
        (cfg_len, test_depth, target_mask)
    }

    fn leave_attrs(&mut self, state: (usize, usize, TargetMask)) {
        self.cfg_stack.truncate(state.0);
        self.test_depth = state.1;
        self.target_mask = state.2;
    }

    fn cfg_domain(&self) -> String {
        let mut fragments = self.cfg_stack.clone();
        fragments.sort();
        fragments.join(" && ")
    }

    fn is_production_context(&self) -> bool {
        if self.test_depth != 0 || self.const_depth != 0 {
            return false;
        }
        let governed_root = self.path.starts_with("src/")
            || self.path.starts_with("crates/socket_policy/src/")
            || self.path.starts_with("crates/wire/src/");
        governed_root
            && !self.path.contains("/tests/")
            && !self.path.ends_with("/tests.rs")
            && !self.path.ends_with("/test_support.rs")
            && !self.path.ends_with("_tests.rs")
    }

    fn record_panic_surface(&mut self, span: Span, item: &str, detail: String) {
        self.findings.push(PolicyFinding {
            kind: PolicyKind::ProductionPanicSurface,
            path: self.path.to_string(),
            line: line(span),
            item: item.to_string(),
            cfg_domain: self.cfg_domain(),
            detail,
        });
    }

    fn record_function(
        &mut self,
        ident: &syn::Ident,
        inputs: &syn::punctuated::Punctuated<syn::FnArg, syn::Token![,]>,
        block: &syn::Block,
        is_method: bool,
    ) {
        let name = ident.to_string();
        let explicit_argument_count = inputs
            .iter()
            .filter(|input| matches!(input, syn::FnArg::Typed(_)))
            .count();
        let has_receiver = inputs
            .iter()
            .any(|input| matches!(input, syn::FnArg::Receiver(_)));
        if contains_direct_recursion(
            &name,
            is_method,
            self.trait_impl_depth != 0,
            has_receiver,
            explicit_argument_count,
            block,
        ) {
            self.findings.push(PolicyFinding {
                kind: PolicyKind::SyntacticDirectRecursion,
                path: self.path.to_string(),
                line: line(ident.span()),
                item: format!("{name}()"),
                cfg_domain: self.cfg_domain(),
                detail: "the body contains a syntactically self-directed call".to_string(),
            });
        }
        self.findings
            .extend(socket_authority_policy::analyze_function(
                self.path,
                &name,
                self.test_depth != 0
                    || self.path.contains("/tests/")
                    || self.path.ends_with("/tests.rs")
                    || self.path.ends_with("_tests.rs"),
                self.cfg_domain(),
                inputs,
                &self.socket_aliases,
                block,
            ));
        self.findings
            .extend(failure_containment_policy::analyze_function(
                self.path,
                &name,
                !self.is_production_context(),
                self.cfg_domain(),
                block,
            ));
        if self.drop_impl_depth == 0 || name != "drop" {
            let mut bindings = BindingCollector::default();
            for input in inputs {
                if let syn::FnArg::Typed(argument) = input {
                    bindings.visit_pat(&argument.pat);
                }
            }
            bindings.visit_block(block);
            let mut calls = FunctionCallCollector {
                calls: BTreeSet::new(),
                local_bindings: bindings.names.into_iter().collect(),
            };
            calls.visit_block(block);
            self.functions.push(FunctionRecord {
                path: self.path.to_string(),
                line: line(ident.span()),
                name,
                cfg_domain: self.cfg_domain(),
                target_mask: self.target_mask,
                is_test: self.test_depth != 0,
                duplicate_body_kind: duplicate_body_kind(block, self.trait_impl_depth != 0),
                explicit_argument_count,
                has_receiver,
                module: self.scope[..self.module_depth].join("::"),
                scope: self.scope.join("::"),
                calls: calls.calls,
                ast_depth: expression_ast_depth(block),
                body: canonical_function_body(inputs, block),
            });
        }
    }
}

impl<'ast> Visit<'ast> for AstCollector<'_> {
    fn visit_lit_str(&mut self, value: &'ast syn::LitStr) {
        let text = value.value();
        if text == POSIX_TEMP_ROOT
            || text
                .strip_prefix(POSIX_TEMP_ROOT)
                .is_some_and(|suffix| suffix.starts_with('/'))
            || text == POSIX_PRIVATE_TEMP_ROOT
            || text
                .strip_prefix(POSIX_PRIVATE_TEMP_ROOT)
                .is_some_and(|suffix| suffix.starts_with('/'))
        {
            self.findings.push(PolicyFinding {
                kind: PolicyKind::HardcodedTemporaryRoot,
                path: self.path.to_string(),
                line: line(value.span()),
                item: "string literal".to_string(),
                cfg_domain: self.cfg_domain(),
                detail: "use std::env::temp_dir() and PathBuf composition".to_string(),
            });
        }
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

    fn visit_expr_path(&mut self, expression: &'ast syn::ExprPath) {
        syn::visit::visit_expr_path(self, expression);
    }

    fn visit_attribute(&mut self, attr: &'ast syn::Attribute) {
        if let Some(finding) =
            debug_assertion_policy::analyze_attribute(self.path, self.cfg_domain(), attr)
        {
            self.findings.push(finding);
        }
        if attr.path().is_ident("allow") {
            let mut forbidden = Vec::new();
            drop(attr.parse_nested_meta(|meta| {
                let name = path_string(&meta.path);
                if matches!(
                    name.as_str(),
                    "dead_code"
                        | "unused"
                        | "unused_imports"
                        | "unused_variables"
                        | "clippy::duplicate_mod"
                        | "clippy::large_enum_variant"
                ) {
                    forbidden.push(name);
                }
                Ok(())
            }));
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
        if self.path == "src/net/socket.rs"
            && attr.path().is_ident("cfg")
            && ["unix", "windows", "target_os"]
                .iter()
                .any(|expected| cfg_attr_has_ident(attr, expected))
        {
            self.findings.push(PolicyFinding {
                kind: PolicyKind::InlineSocketPlatformDecision,
                path: self.path.to_string(),
                line: line(attr.span()),
                item: "socket setup attribute".to_string(),
                cfg_domain: self.cfg_domain(),
                detail:
                    "consume typed socket policy and dispatch through src/net/socket/platform.rs"
                        .to_string(),
            });
        }
        syn::visit::visit_attribute(self, attr);
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        if let Some(finding) =
            socket_authority_policy::analyze_use(self.path, self.cfg_domain(), item)
        {
            self.findings.push(finding);
        }
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

    fn visit_item_struct(&mut self, item: &'ast syn::ItemStruct) {
        self.findings.extend(audit_authority_policy::analyze_struct(
            self.path,
            self.cfg_domain(),
            item,
        ));
        if item.ident != "SocketStateSnapshot" {
            for field in &item.fields {
                if field.ident.as_ref().is_some_and(|ident| {
                    ident == "listener_connected" || ident == "upstream_connected"
                }) {
                    self.findings.push(PolicyFinding {
                        kind: PolicyKind::SocketLifecycleAuthority,
                        path: self.path.to_string(),
                        line: line(field.span()),
                        item: item.ident.to_string(),
                        cfg_domain: self.cfg_domain(),
                        detail: "live connection state must come from ManagedSocket association"
                            .to_string(),
                    });
                }
            }
        }
        self.findings
            .extend(socket_authority_policy::analyze_struct(
                self.path,
                self.test_depth != 0
                    || self.path.contains("/tests/")
                    || self.path.ends_with("/tests.rs")
                    || self.path.ends_with("_tests.rs"),
                self.cfg_domain(),
                item,
            ));
        self.enter_generics(&item.generics);
        syn::visit::visit_item_struct(self, item);
        self.leave_generics();
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if self.is_production_context()
            && atomic_operation_method(&call.method.to_string())
            && call.args.iter().any(expression_uses_seq_cst)
        {
            self.findings.push(PolicyFinding {
                kind: PolicyKind::SequentiallyConsistentProtocol,
                path: self.path.to_string(),
                line: line(call.span()),
                item: "atomic ordering".to_string(),
                cfg_domain: self.cfg_domain(),
                detail: "use explicit Acquire observation, Release publication, and AcqRel CAS ownership"
                    .to_string(),
            });
        }
        if self.is_production_context()
            && matches!(call.method.to_string().as_str(), "unwrap" | "expect")
        {
            self.record_panic_surface(
                call.method.span(),
                &format!("{}()", call.method),
                "production Result/Option handling must be typed or fail-closed".to_string(),
            );
        }
        if let Some(finding) =
            audit_authority_policy::analyze_method_call(self.path, self.cfg_domain(), call)
        {
            self.findings.push(finding);
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_item_enum(&mut self, item: &'ast syn::ItemEnum) {
        if let Some(finding) =
            socket_authority_policy::analyze_enum(self.path, self.cfg_domain(), item)
        {
            self.findings.push(finding);
        }
        self.enter_generics(&item.generics);
        syn::visit::visit_item_enum(self, item);
        self.leave_generics();
    }

    fn visit_ident(&mut self, ident: &'ast syn::Ident) {
        if ident == "CanonicalAddr" || ident == "FlowEndpoint" {
            self.findings.push(PolicyFinding {
                kind: PolicyKind::RetiredEndpointAuthority,
                path: self.path.to_string(),
                line: line(ident.span()),
                item: ident.to_string(),
                cfg_domain: self.cfg_domain(),
                detail: "LogicalEndpoint is the sole logical address authority".to_string(),
            });
        }
        syn::visit::visit_ident(self, ident);
    }

    fn visit_path(&mut self, path: &'ast syn::Path) {
        if self.is_production_context()
            && self.function_depth == 0
            && !self.generic_type_shadows(path)
            && let Some(finding) = audit_authority_policy::analyze_interior_mutability_path(
                self.path,
                self.cfg_domain(),
                path,
            )
        {
            self.findings.push(finding);
        }
        syn::visit::visit_path(self, path);
    }

    fn visit_macro(&mut self, item: &'ast syn::Macro) {
        if self.is_production_context()
            && let Some(finding) = audit_authority_policy::analyze_interior_mutability_macro(
                self.path,
                self.cfg_domain(),
                item,
            )
        {
            self.findings.push(finding);
        }
        if self.is_production_context()
            && item.path.segments.last().is_some_and(|segment| {
                matches!(
                    segment.ident.to_string().as_str(),
                    "assert"
                        | "assert_eq"
                        | "assert_ne"
                        | "panic"
                        | "unreachable"
                        | "todo"
                        | "unimplemented"
                )
            })
        {
            self.record_panic_surface(
                item.span(),
                "macro",
                format!(
                    "{}! is forbidden in production runtime context",
                    item.path.to_token_stream()
                ),
            );
        }
        if let Some(finding) =
            debug_assertion_policy::analyze_macro(self.path, self.cfg_domain(), item)
        {
            self.findings.push(finding);
        }
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
        self.scope.push(item.ident.to_string());
        self.module_depth += 1;
        syn::visit::visit_item_mod(self, item);
        self.module_depth -= 1;
        self.scope.pop();
        self.leave_attrs(state);
    }

    fn visit_item_const(&mut self, item: &'ast syn::ItemConst) {
        self.const_depth += 1;
        syn::visit::visit_item_const(self, item);
        self.const_depth -= 1;
    }

    fn visit_impl_item_const(&mut self, item: &'ast syn::ImplItemConst) {
        self.const_depth += 1;
        syn::visit::visit_impl_item_const(self, item);
        self.const_depth -= 1;
    }

    fn visit_trait_item_const(&mut self, item: &'ast syn::TraitItemConst) {
        self.const_depth += 1;
        syn::visit::visit_trait_item_const(self, item);
        self.const_depth -= 1;
    }

    fn visit_item_static(&mut self, item: &'ast syn::ItemStatic) {
        self.const_depth += 1;
        syn::visit::visit_item_static(self, item);
        self.const_depth -= 1;
    }

    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        let state = self.enter_attrs(&item.attrs);
        if let Some(finding) =
            audit_authority_policy::analyze_unsafe_thread_impl(self.path, self.cfg_domain(), item)
        {
            self.findings.push(finding);
        }
        let implementation_scope = item.trait_.as_ref().map_or_else(
            || item.self_ty.to_token_stream().to_string(),
            |(trait_path, _)| {
                format!(
                    "{} as {}",
                    item.self_ty.to_token_stream(),
                    trait_path.to_token_stream()
                )
            },
        );
        self.scope.push(implementation_scope);
        self.enter_generics(&item.generics);
        let drop_impl = item.trait_.as_ref().is_some_and(|(path, _)| {
            path.segments
                .last()
                .is_some_and(|segment| segment.ident == "Drop")
        });
        if drop_impl {
            self.drop_impl_depth += 1;
        }
        if item.trait_.is_some() {
            self.trait_impl_depth += 1;
        }
        syn::visit::visit_item_impl(self, item);
        if item.trait_.is_some() {
            self.trait_impl_depth -= 1;
        }
        if drop_impl {
            self.drop_impl_depth -= 1;
        }
        self.leave_generics();
        self.scope.pop();
        self.leave_attrs(state);
    }

    fn visit_field(&mut self, field: &'ast syn::Field) {
        let state = self.enter_attrs(&field.attrs);
        syn::visit::visit_field(self, field);
        self.leave_attrs(state);
    }

    fn visit_item_trait(&mut self, item: &'ast syn::ItemTrait) {
        let state = self.enter_attrs(&item.attrs);
        self.scope.push(item.ident.to_string());
        self.enter_generics(&item.generics);
        syn::visit::visit_item_trait(self, item);
        self.leave_generics();
        self.scope.pop();
        self.leave_attrs(state);
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if let Some(finding) = audit_authority_policy::analyze_test_only_mutator(
            self.path,
            self.cfg_domain(),
            &item.attrs,
            &item.sig,
            &item.block,
        ) {
            self.findings.push(finding);
        }
        let state = self.enter_attrs(&item.attrs);
        if let Some(finding) = audit_authority_policy::analyze_function_signature(
            self.path,
            self.cfg_domain(),
            &item.sig,
        ) {
            self.findings.push(finding);
        }
        self.record_function(&item.sig.ident, &item.sig.inputs, &item.block, false);
        self.enter_generics(&item.sig.generics);
        self.function_depth += 1;
        syn::visit::visit_item_fn(self, item);
        self.function_depth -= 1;
        self.leave_generics();
        self.leave_attrs(state);
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        if let Some(finding) = audit_authority_policy::analyze_test_only_mutator(
            self.path,
            self.cfg_domain(),
            &item.attrs,
            &item.sig,
            &item.block,
        ) {
            self.findings.push(finding);
        }
        let state = self.enter_attrs(&item.attrs);
        if let Some(finding) = audit_authority_policy::analyze_function_signature(
            self.path,
            self.cfg_domain(),
            &item.sig,
        ) {
            self.findings.push(finding);
        }
        self.record_function(&item.sig.ident, &item.sig.inputs, &item.block, true);
        self.enter_generics(&item.sig.generics);
        self.function_depth += 1;
        syn::visit::visit_impl_item_fn(self, item);
        self.function_depth -= 1;
        self.leave_generics();
        self.leave_attrs(state);
    }

    fn visit_trait_item_fn(&mut self, item: &'ast syn::TraitItemFn) {
        let state = self.enter_attrs(&item.attrs);
        if let Some(finding) = audit_authority_policy::analyze_function_signature(
            self.path,
            self.cfg_domain(),
            &item.sig,
        ) {
            self.findings.push(finding);
        }
        if let Some(block) = &item.default {
            self.record_function(&item.sig.ident, &item.sig.inputs, block, true);
        }
        self.enter_generics(&item.sig.generics);
        self.function_depth += 1;
        syn::visit::visit_trait_item_fn(self, item);
        self.function_depth -= 1;
        self.leave_generics();
        self.leave_attrs(state);
    }
}

#[cfg(test)]
mod tests;
