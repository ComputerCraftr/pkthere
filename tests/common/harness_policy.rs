use pkthere_test_support::test_paths as path_policy;
use std::fs;
use std::path::{Path, PathBuf};
use syn::visit::Visit;

#[derive(Default)]
struct LifecycleVisitor {
    forbidden_methods: Vec<String>,
    child_type_references: usize,
    read_impls: usize,
    join_handle_returns: usize,
}

impl<'ast> Visit<'ast> for LifecycleVisitor {
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if matches!(
            call.method.to_string().as_str(),
            "spawn" | "wait" | "try_wait" | "kill"
        ) {
            self.forbidden_methods.push(call.method.to_string());
        }
        syn::visit::visit_expr_method_call(self, call);
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
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let tests_root = repo_root.join("tests");
    let mut sources = rust_sources(&tests_root);
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
        if relative != "tests/support/src/timing.rs"
            && (contents.contains("Duration::from_secs(")
                || contents.contains("Duration::from_millis("))
        {
            violations.push(format!("{relative}: inline governed duration"));
        }
    }

    let raw_lock = fs::read_to_string(tests_root.join("support/src/raw_icmp.rs"))
        .expect("read RAW ICMP lock implementation");
    if raw_lock.contains("file.lock()") || raw_lock.contains("flock(") {
        violations.push("tests/support/src/raw_icmp.rs: blocking file lock".to_string());
    }
    assert!(
        violations.is_empty(),
        "Test harness lifecycle boundaries were bypassed:\n{}",
        violations.join("\n")
    );
}

fn rust_sources(root: &Path) -> Vec<PathBuf> {
    let mut sources = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)
            .unwrap_or_else(|error| panic!("read {}: {error}", directory.display()))
        {
            let path = entry.expect("test source entry").path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().and_then(|extension| extension.to_str()) == Some("rs") {
                sources.push(path);
            }
        }
    }
    sources
}
