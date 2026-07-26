use pkthere_test_support::test_paths as path_policy;
use std::fs;
use syn::visit::Visit;

#[derive(Default)]
struct LifecycleVisitor {
    forbidden_methods: Vec<String>,
    child_type_references: usize,
    read_impls: usize,
    join_handle_returns: usize,
    inline_durations: usize,
    blocking_file_locks: usize,
}

impl<'ast> Visit<'ast> for LifecycleVisitor {
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if matches!(
            call.method.to_string().as_str(),
            "spawn" | "wait" | "try_wait" | "kill"
        ) {
            self.forbidden_methods.push(call.method.to_string());
        }
        if call.method == "lock"
            && matches!(
                call.receiver.as_ref(),
                syn::Expr::Path(path)
                    if path.path.segments.last().is_some_and(|segment| segment.ident == "file")
            )
        {
            self.blocking_file_locks += 1;
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = call.func.as_ref()
            && let Some(function) = path.path.segments.last()
        {
            if matches!(
                function.ident.to_string().as_str(),
                "from_secs" | "from_millis"
            ) && path
                .path
                .segments
                .iter()
                .any(|segment| segment.ident == "Duration")
            {
                self.inline_durations += 1;
            }
            if function.ident == "flock" {
                self.blocking_file_locks += 1;
            }
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_path(&mut self, path: &'ast syn::Path) {
        if path
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "Child")
        {
            self.child_type_references += 1;
        }
        syn::visit::visit_path(self, path);
    }

    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        if item
            .trait_
            .as_ref()
            .and_then(|(path, _)| path.segments.last())
            .is_some_and(|segment| segment.ident == "Read")
        {
            self.read_impls += 1;
        }
        syn::visit::visit_item_impl(self, item);
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if return_type_mentions_join_handle(&item.sig.output) {
            self.join_handle_returns += 1;
        }
        syn::visit::visit_item_fn(self, item);
    }
}

fn return_type_mentions_join_handle(output: &syn::ReturnType) -> bool {
    struct JoinHandleVisitor(bool);
    impl<'ast> Visit<'ast> for JoinHandleVisitor {
        fn visit_path(&mut self, path: &'ast syn::Path) {
            if path
                .segments
                .last()
                .is_some_and(|segment| segment.ident == "JoinHandle")
            {
                self.0 = true;
            }
            syn::visit::visit_path(self, path);
        }
    }

    let syn::ReturnType::Type(_, returned) = output else {
        return false;
    };
    let mut visitor = JoinHandleVisitor(false);
    visitor.visit_type(returned);
    visitor.0
}

pub fn assert_test_harness_lifecycle_boundaries() {
    let repo_root_path = crate::common::policy::repository_root();
    let repo_root = repo_root_path.as_path();
    let tests_root = repo_root.join("tests");
    let mut sources = crate::common::source_layout_policy::governed_source_paths(Some(
        crate::common::source_layout_policy::SourceKind::Rust,
    ))
    .into_iter()
    .filter(|source| source.starts_with(&tests_root))
    .collect::<Vec<_>>();
    sources.sort();
    let mut violations = Vec::new();

    for path in sources {
        let relative = path_policy::render_repo_relative_path(repo_root, &path);
        if relative == "tests/support/src/managed_child.rs"
            || relative.starts_with("tests/support/src/managed_child/")
            || relative == "tests/support/src/bin/harness_child.rs"
            || relative == "tests/common/harness_policy.rs"
        {
            continue;
        }
        let contents = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        let parsed = syn::parse_file(&contents)
            .unwrap_or_else(|error| panic!("failed to parse {relative}: {error}"));
        let mut visitor = LifecycleVisitor::default();
        visitor.visit_file(&parsed);
        if !visitor.forbidden_methods.is_empty() {
            violations.push(format!(
                "{relative}: direct child lifecycle methods {:?}",
                visitor.forbidden_methods
            ));
        }
        if visitor.child_type_references != 0 {
            violations.push(format!(
                "{relative}: {} direct std::process::Child reference(s)",
                visitor.child_type_references
            ));
        }
        if visitor.read_impls != 0 {
            violations.push(format!("{relative}: inactivity Read implementation"));
        }
        if visitor.join_handle_returns != 0 {
            violations.push(format!("{relative}: bare JoinHandle return"));
        }
        if relative != "tests/support/src/timing.rs" && visitor.inline_durations != 0 {
            violations.push(format!("{relative}: inline governed duration"));
        }
    }

    let raw_lock = fs::read_to_string(tests_root.join("support/src/raw_icmp.rs"))
        .expect("read RAW ICMP lock implementation");
    let raw_lock = syn::parse_file(&raw_lock).expect("parse RAW ICMP lock implementation");
    let mut raw_lock_visitor = LifecycleVisitor::default();
    raw_lock_visitor.visit_file(&raw_lock);
    if raw_lock_visitor.blocking_file_locks != 0 {
        violations.push("tests/support/src/raw_icmp.rs: blocking file lock".to_string());
    }
    assert!(
        violations.is_empty(),
        "Test harness lifecycle boundaries were bypassed:\n{}",
        violations.join("\n")
    );
}
