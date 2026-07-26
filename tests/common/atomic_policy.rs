use pkthere_test_support::test_paths as path_policy;
use std::collections::BTreeMap;
use std::path::Path;

use crate::common::rust_semantics::attrs_are_test_context;

macro_rules! visit_non_test_containers {
    () => {
        fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
            if !attrs_are_test_context(&item.attrs) {
                syn::visit::visit_item_mod(self, item);
            }
        }

        fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
            if !attrs_are_test_context(&item.attrs) {
                syn::visit::visit_item_impl(self, item);
            }
        }
    };
}

mod authority_graph;
mod authority_ownership;
mod loom_contract_types;
mod loom_ownership;
#[cfg(test)]
mod loom_ownership_tests;
mod loom_syntax;
mod operation_boundaries;
mod ownership_typestate;

use crate::common::source_layout_policy::production_rust_source_paths_under;
pub use authority_graph::{
    assert_shared_worker_flow_authorities_are_unique,
    assert_stable_forwarding_requires_directional_permits,
    assert_transaction_recovery_authorities_are_unique,
};

fn production_rust_sources(root: &Path) -> Vec<std::path::PathBuf> {
    production_rust_source_paths_under(&[root.join("src")])
}
use operation_boundaries::assert_no_unaudited_operation_boundaries;

pub fn assert_synchronization_authority_catalog_is_complete() {
    let root_path = crate::common::policy::repository_root();
    let root = root_path.as_path();
    for source in production_rust_sources(root) {
        let syntax = crate::common::rust_semantics::parse_file(&source);
        let mut fragmented =
            crate::common::rust_semantics::function_names_with_prefix(&syntax, "refresh");
        fragmented.extend(crate::common::rust_semantics::function_names_with_prefix(
            &syntax,
            "current_version",
        ));
        assert!(
            fragmented.is_empty(),
            "{}: detached refresh/version phase APIs are forbidden; use one resource-owning transaction: {fragmented:?}",
            path_policy::render_repo_relative_path(root, &source),
        );
    }
    let authority = [
        "src/authority.rs",
        "src/authority/catalog.rs",
        "src/authority/catalog/atomics.rs",
        "src/authority/catalog/blocking.rs",
        "src/authority/catalog/lifecycles.rs",
        "src/authority/catalog/operations.rs",
        "src/authority/catalog/refcounts.rs",
        "src/authority/catalog_validation.rs",
        "src/authority/error.rs",
        "src/authority/scopes.rs",
        "src/authority/synchronization.rs",
        "src/authority/tags.rs",
        "src/authority/thread_owned.rs",
        "src/authority/validation.rs",
        "src/authority/worker_audit.rs",
    ]
    .into_iter()
    .map(|path| crate::common::rust_semantics::parse_file(&root.join(path)))
    .collect::<Vec<_>>();
    for required in [
        "AUTHORITY_RECORDS",
        "BLOCKING_EDGES",
        "COHOLD_RULES",
        "WAIT_RECORDS",
        "WAIT_PROTOCOL_RECORDS",
        "PUBLICATION_RECORDS",
        "OPERATION_RECORDS",
        "SHARED_RMW_RECORDS",
        "ATOMIC_PROTOCOL_RECORDS",
        "LIFECYCLE_OWNERSHIP_RECORDS",
        "BLOCKING_CONTRACTS",
        "REFERENCE_COUNT_OWNERSHIP_RECORDS",
        "validate_catalog",
        "AuthorityInstance",
        "AuthorityMutex",
        "AuthorityCondvar",
        "AuthorityAtomic",
        "AuthorityOnceLock",
        "AuthorityQueue",
        "AuthorityChannelSender",
        "AuthorityChannelReceiver",
        "AuthorityScope",
        "AuditedOperationScope",
        "ThreadOwned",
        "WorkerAuditRegistry",
        "LifecycleOwnershipRecord",
        "AtomicProtocolRecord",
        "BlockingContract",
        "WaitProtocolRecord",
        "ReferenceCountOwnershipRecord",
        "RECORDS",
        "release_for_wait",
        "reacquire_after_wait",
    ] {
        assert!(
            authority
                .iter()
                .any(|syntax| crate::common::rust_semantics::defines(syntax, required)),
            "synchronization catalog is missing {required}"
        );
    }
    assert!(
        authority.iter().all(|syntax| {
            !crate::common::rust_semantics::references_ident(syntax, "RuntimeAuthorityLock")
        }),
        "legacy RuntimeAuthorityLock synchronization authority returned"
    );
    let main = crate::common::rust_semantics::parse_file(&root.join("src/main.rs"));
    assert!(
        crate::common::rust_semantics::calls(&main, &["authority", "validate_catalog"]),
        "production startup must fail closed when the authority graph is incomplete"
    );
    assert_no_hidden_synchronization_generators(root);
    assert_unsafe_runtime_surface_is_scoped(root);
    assert_no_unaudited_operation_boundaries(root);
    loom_ownership::assert_loom_cores_have_production_callers(root);
    assert_no_authority_callback_escape_hatches(root);
    assert_replacement_retirement_is_consuming(root);
    assert_seq_cst_is_confined_to_the_exact_negative_control(root);
}

fn assert_seq_cst_is_confined_to_the_exact_negative_control(root: &Path) {
    let allowed_path = root.join("src/authority/tests.rs");
    let mut violations = Vec::new();
    for path in crate::common::source_layout_policy::rust_source_paths_under(&[root.to_path_buf()])
    {
        let syntax = crate::common::rust_semantics::parse_file(&path);
        for call in crate::common::rust_semantics::seq_cst_atomic_calls(&syntax) {
            if path != allowed_path
                || call.function != "non_main_worker_rejects_uncataloged_atomic_ordering"
            {
                violations.push(format!(
                    "{}::{} uses {} with Ordering::SeqCst",
                    path.display(),
                    call.function,
                    call.method
                ));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "SEQCST-DEPENDENCY-001: positive production/Loom protocols may not rely on cross-atomic sequential consistency:\n{}",
        violations.join("\n")
    );
}

fn assert_unsafe_runtime_surface_is_scoped(root: &Path) {
    use syn::visit::Visit;

    #[derive(Default)]
    struct UnsafeSurface {
        blocks: usize,
        functions: usize,
        implementations: usize,
        unsafe_cells: usize,
        non_null: usize,
    }

    fn attrs_are_exclusively_test_context(attrs: &[syn::Attribute]) -> bool {
        attrs.iter().any(|attr| {
            if !attr.path().is_ident("cfg") {
                return attr.path().is_ident("test");
            }
            let tokens = quote::quote!(#attr).to_string();
            tokens
                .split(|character: char| !character.is_ascii_alphanumeric())
                .any(|fragment| fragment == "test")
                && !tokens.contains("feature")
        })
    }

    impl<'ast> Visit<'ast> for UnsafeSurface {
        fn visit_item_mod(&mut self, module: &'ast syn::ItemMod) {
            if !attrs_are_exclusively_test_context(&module.attrs) {
                syn::visit::visit_item_mod(self, module);
            }
        }

        fn visit_expr_unsafe(&mut self, expression: &'ast syn::ExprUnsafe) {
            self.blocks += 1;
            syn::visit::visit_expr_unsafe(self, expression);
        }

        fn visit_item_impl(&mut self, implementation: &'ast syn::ItemImpl) {
            if attrs_are_exclusively_test_context(&implementation.attrs) {
                return;
            }
            self.implementations += usize::from(implementation.unsafety.is_some());
            syn::visit::visit_item_impl(self, implementation);
        }

        fn visit_item_fn(&mut self, function: &'ast syn::ItemFn) {
            if attrs_are_exclusively_test_context(&function.attrs) {
                return;
            }
            self.functions += usize::from(matches!(function.sig.safety, syn::Safety::Unsafe(_)));
            syn::visit::visit_item_fn(self, function);
        }

        fn visit_impl_item_fn(&mut self, function: &'ast syn::ImplItemFn) {
            if attrs_are_exclusively_test_context(&function.attrs) {
                return;
            }
            self.functions += usize::from(matches!(function.sig.safety, syn::Safety::Unsafe(_)));
            syn::visit::visit_impl_item_fn(self, function);
        }

        fn visit_path(&mut self, path: &'ast syn::Path) {
            self.unsafe_cells += usize::from(
                path.segments
                    .iter()
                    .any(|segment| segment.ident == "UnsafeCell"),
            );
            self.non_null += usize::from(
                path.segments
                    .iter()
                    .any(|segment| segment.ident == "NonNull"),
            );
            syn::visit::visit_path(self, path);
        }
    }

    let expected = BTreeMap::from([
        ("src/allocation_test_support.rs".to_string(), (4, 4, 1, 0)),
        ("src/runtime_support.rs".to_string(), (2, 0, 0, 0)),
        ("src/net/socket/platform.rs".to_string(), (2, 0, 0, 0)),
        (
            "src/net/managed_socket/platform.rs".to_string(),
            (4, 0, 0, 0),
        ),
        (
            "src/net/managed_socket/receive.rs".to_string(),
            (1, 0, 0, 0),
        ),
    ]);
    let mut observed = BTreeMap::new();
    for source in production_rust_sources(root) {
        let relative = path_policy::render_repo_relative_path(root, &source);
        let syntax = crate::common::rust_semantics::parse_file(&source);
        let mut surface = UnsafeSurface::default();
        surface.visit_file(&syntax);
        assert_eq!(
            surface.non_null, 0,
            "{relative}: raw NonNull ownership is forbidden in production"
        );
        if surface.blocks != 0
            || surface.functions != 0
            || surface.implementations != 0
            || surface.unsafe_cells != 0
        {
            observed.insert(
                relative,
                (
                    surface.blocks,
                    surface.functions,
                    surface.implementations,
                    surface.unsafe_cells,
                ),
            );
        }
    }
    assert_eq!(
        observed, expected,
        "production unsafe code or UnsafeCell use changed without updating the reviewed safety inventory"
    );
}

fn assert_replacement_retirement_is_consuming(root: &Path) {
    for source in [
        "src/net/sock_mgr/manager.rs",
        "src/net/sock_mgr/manager_reresolve.rs",
    ] {
        let contents = crate::common::rust_semantics::parse_file(&root.join(source));
        assert!(
            crate::common::rust_semantics::references_ident(
                &contents,
                "RetiredTopologyReservation",
            ) && crate::common::rust_semantics::calls(&contents, &["into_retired_for_replacement"],),
            "{source}: manager replacement must separate irreversible retired ownership"
        );
    }
}

fn assert_no_authority_callback_escape_hatches(root: &Path) {
    const FORBIDDEN_FUNCTIONS: &[&str] = &["wait_with_io_lease", "reserve_until_with_wake"];
    const FORBIDDEN_CALLBACKS: &[&str] = &[
        "capture_current",
        "authority_is_current",
        "make_payload",
        "take_authenticated_work",
    ];
    for source in production_rust_sources(root) {
        let relative = path_policy::render_repo_relative_path(root, &source);
        let contents = crate::common::rust_semantics::parse_file(&source);
        for forbidden in FORBIDDEN_FUNCTIONS {
            assert!(
                !crate::common::rust_semantics::defines(&contents, forbidden),
                "{relative}: authority-bearing runtime work escaped through callback API {forbidden}"
            );
        }
        assert!(
            !crate::common::rust_semantics::callback_parameter_named(
                &contents,
                FORBIDDEN_CALLBACKS,
            ),
            "{relative}: authority-bearing runtime work escaped through a callback parameter"
        );
    }
}

fn assert_no_hidden_synchronization_generators(root: &Path) {
    use syn::visit::Visit;

    const RAW_SYNC_TYPES: &[&str] = &[
        "Mutex",
        "RwLock",
        "Condvar",
        "OnceLock",
        "AtomicBool",
        "AtomicI8",
        "AtomicI16",
        "AtomicI32",
        "AtomicI64",
        "AtomicIsize",
        "AtomicPtr",
        "AtomicU8",
        "AtomicU16",
        "AtomicU32",
        "AtomicU64",
        "AtomicUsize",
        "ArrayQueue",
        "SegQueue",
        "Sender",
        "Receiver",
    ];

    #[derive(Default)]
    struct GeneratorAudit {
        aliases: Vec<String>,
        macros: Vec<String>,
        raw_sites: Vec<String>,
        raw_imports: std::collections::BTreeSet<String>,
    }

    fn synchronization_path(
        path: &syn::Path,
        imports: &std::collections::BTreeSet<String>,
    ) -> bool {
        let Some(last) = path.segments.last() else {
            return false;
        };
        let name = last.ident.to_string();
        if !RAW_SYNC_TYPES.contains(&name.as_str()) {
            return false;
        }
        if path.segments.len() == 1 {
            return imports.contains(&name);
        }
        matches!(
            path.segments
                .first()
                .map(|segment| segment.ident.to_string())
                .as_deref(),
            Some("std" | "core" | "loom" | "crossbeam_channel" | "crossbeam_queue")
        )
    }

    fn collect_raw_imports(syntax: &syn::File) -> std::collections::BTreeSet<String> {
        struct ImportCollector {
            imports: std::collections::BTreeSet<String>,
        }

        fn collect_use_tree(tree: &syn::UseTree, imports: &mut std::collections::BTreeSet<String>) {
            let mut pending = vec![(tree, Vec::<String>::new())];
            while let Some((tree, mut prefix)) = pending.pop() {
                match tree {
                    syn::UseTree::Path(path) => {
                        prefix.push(path.ident.to_string());
                        pending.push((&path.tree, prefix));
                    }
                    syn::UseTree::Name(name) => {
                        prefix.push(name.ident.to_string());
                        if prefix.len() > 1
                            && matches!(
                                prefix.first().map(String::as_str),
                                Some(
                                    "std"
                                        | "core"
                                        | "loom"
                                        | "crossbeam_channel"
                                        | "crossbeam_queue"
                                )
                            )
                            && RAW_SYNC_TYPES.contains(&name.ident.to_string().as_str())
                        {
                            imports.insert(name.ident.to_string());
                        }
                    }
                    syn::UseTree::Rename(rename) => {
                        prefix.push(rename.ident.to_string());
                        if prefix.len() > 1
                            && matches!(
                                prefix.first().map(String::as_str),
                                Some(
                                    "std"
                                        | "core"
                                        | "loom"
                                        | "crossbeam_channel"
                                        | "crossbeam_queue"
                                )
                            )
                            && RAW_SYNC_TYPES.contains(&rename.ident.to_string().as_str())
                        {
                            imports.insert(rename.rename.to_string());
                        }
                    }
                    syn::UseTree::Group(group) => {
                        for item in &group.items {
                            pending.push((item, prefix.clone()));
                        }
                    }
                    syn::UseTree::Glob(_) => {}
                }
            }
        }

        impl<'ast> Visit<'ast> for ImportCollector {
            fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
                collect_use_tree(&item.tree, &mut self.imports);
            }
        }

        let mut collector = ImportCollector {
            imports: std::collections::BTreeSet::new(),
        };
        collector.visit_file(syntax);
        collector.imports
    }

    impl<'ast> Visit<'ast> for GeneratorAudit {
        visit_non_test_containers!();

        fn visit_item_type(&mut self, item: &syn::ItemType) {
            let direct_raw_alias = match item.ty.as_ref() {
                syn::Type::Path(path) => synchronization_path(&path.path, &self.raw_imports),
                _ => false,
            };
            if direct_raw_alias {
                self.aliases.push(item.ident.to_string());
            }
            syn::visit::visit_item_type(self, item);
        }

        fn visit_item_macro(&mut self, item: &syn::ItemMacro) {
            if let Some(name) = item.ident.as_ref() {
                let identifiers =
                    crate::common::rust_semantics::token_identifiers(item.mac.tokens.clone());
                let qualified = [
                    "std",
                    "core",
                    "loom",
                    "crossbeam_channel",
                    "crossbeam_queue",
                ]
                .iter()
                .any(|namespace| identifiers.contains(*namespace));
                let imported = self.raw_imports.iter().any(|raw| identifiers.contains(raw));
                if RAW_SYNC_TYPES.iter().any(|raw| identifiers.contains(*raw))
                    && (qualified || imported)
                {
                    self.macros.push(name.to_string());
                }
            }
            syn::visit::visit_item_macro(self, item);
        }

        fn visit_item_fn(&mut self, item: &syn::ItemFn) {
            if attrs_are_test_context(&item.attrs) {
                return;
            }
            syn::visit::visit_item_fn(self, item);
        }

        fn visit_impl_item_fn(&mut self, item: &syn::ImplItemFn) {
            if attrs_are_test_context(&item.attrs) {
                return;
            }
            syn::visit::visit_impl_item_fn(self, item);
        }

        fn visit_field(&mut self, field: &syn::Field) {
            if attrs_are_test_context(&field.attrs) {
                return;
            }
            syn::visit::visit_field(self, field);
        }

        fn visit_type_path(&mut self, item: &syn::TypePath) {
            let Some(last) = item.path.segments.last() else {
                return;
            };
            let name = last.ident.to_string();
            if matches!(
                name.as_str(),
                "AuthorityMutex"
                    | "AuthorityCondvar"
                    | "AuthorityAtomic"
                    | "AuthorityOnceLock"
                    | "CounterAtomic"
                    | "AuthorityQueue"
                    | "AuthorityChannelSender"
                    | "AuthorityChannelReceiver"
                    | "ThreadOwned"
            ) {
                return;
            }
            if synchronization_path(&item.path, &self.raw_imports) {
                self.raw_sites.push(quote::quote!(#item).to_string());
            }
            syn::visit::visit_type_path(self, item);
        }

        fn visit_expr_call(&mut self, item: &syn::ExprCall) {
            if let syn::Expr::Path(path) = item.func.as_ref()
                && synchronization_path(&path.path, &self.raw_imports)
            {
                self.raw_sites.push(quote::quote!(#item.func).to_string());
            }
            syn::visit::visit_expr_call(self, item);
        }
    }

    for source in production_rust_sources(root) {
        let relative = path_policy::render_repo_relative_path(root, &source);
        if relative == "src/authority.rs"
            || relative == "src/atomic_core.rs"
            || relative.starts_with("src/authority/")
            || relative.starts_with("src/atomic_core/")
        {
            continue;
        }
        let syntax = crate::common::rust_semantics::parse_file(&source);
        let mut audit = GeneratorAudit {
            raw_imports: collect_raw_imports(&syntax),
            ..GeneratorAudit::default()
        };
        audit.visit_file(&syntax);
        assert!(
            audit.aliases.is_empty(),
            "{relative}: raw synchronization is hidden behind type aliases {:?}",
            audit.aliases
        );
        assert!(
            audit.macros.is_empty(),
            "{relative}: macros can generate unregistered synchronization {:?}",
            audit.macros
        );
        assert!(
            audit.raw_sites.is_empty(),
            "{relative}: direct production synchronization bypasses the sealed authority wrappers: {:?}",
            audit.raw_sites
        );
    }
}
