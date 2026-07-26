use syn::visit::Visit;

pub fn assert_tests_do_not_return_without_running() {
    let root = super::repo_root();
    let violations = super::workspace_inventory()
        .sources
        .iter()
        .flat_map(|source| {
            let syntax = crate::common::rust_semantics::parse_file(source);
            test_functions_with_bare_return(&syntax)
                .into_iter()
                .map(|name| format!("{}::{name}", super::relative(&root, source)))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    assert!(
        violations.is_empty(),
        "tests must use explicit ignore attributes for unsupported platforms, not a bare return:\n{}",
        violations.join("\n")
    );
}

pub(super) fn test_functions_with_bare_return(syntax: &syn::File) -> Vec<String> {
    struct BareReturn(bool);

    impl Visit<'_> for BareReturn {
        fn visit_expr_return(&mut self, expression: &syn::ExprReturn) {
            self.0 |= expression.expr.is_none();
        }

        fn visit_expr_closure(&mut self, _expression: &syn::ExprClosure) {}

        fn visit_item_fn(&mut self, _function: &syn::ItemFn) {}
    }

    syntax
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Fn(function)
                if function.attrs.iter().any(|attr| {
                    attr.path()
                        .segments
                        .last()
                        .is_some_and(|segment| segment.ident == "test")
                }) =>
            {
                let mut visitor = BareReturn(false);
                visitor.visit_block(&function.block);
                visitor.0.then(|| function.sig.ident.to_string())
            }
            _ => None,
        })
        .collect()
}
