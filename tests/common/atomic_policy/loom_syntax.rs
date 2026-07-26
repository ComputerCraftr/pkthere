use super::loom_ownership::CallPattern;
use std::collections::{BTreeMap, BTreeSet};
use syn::parse::Parser;
use syn::visit::Visit;

#[derive(Debug, Eq, PartialEq)]
pub(super) struct DeclaredResourceField {
    pub(super) owner: String,
    pub(super) identity: String,
    pub(super) source_field: String,
}

pub(super) fn loom_test_names(syntax: &syn::File) -> Vec<String> {
    syntax
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Fn(function) if has_attribute(&function.attrs, "test") => {
                Some(function.sig.ident.to_string())
            }
            _ => None,
        })
        .collect()
}

fn has_attribute(attributes: &[syn::Attribute], expected: &str) -> bool {
    attributes
        .iter()
        .any(|attribute| attribute.path().is_ident(expected))
}

pub(super) fn positive_test_uses_registered_core(
    syntax: &syn::File,
    test: &str,
    core_call: CallPattern,
) -> bool {
    reachable_function_facts(syntax, test).calls(core_call)
}

pub(super) fn reachable_function_facts(syntax: &syn::File, entry: &str) -> SyntaxFacts {
    let functions = syntax
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Fn(function) => {
                let mut facts = SyntaxFacts::default();
                facts.visit_block(&function.block);
                Some((function.sig.ident.to_string(), facts))
            }
            _ => None,
        })
        .collect::<BTreeMap<_, _>>();
    let mut combined = SyntaxFacts::default();
    let mut visited = BTreeSet::new();
    let mut pending = vec![entry.to_string()];
    while let Some(function) = pending.pop() {
        if !visited.insert(function.clone()) {
            continue;
        }
        let Some(facts) = functions.get(&function) else {
            continue;
        };
        pending.extend(
            facts
                .free_calls
                .iter()
                .filter(|called| functions.contains_key(*called))
                .cloned(),
        );
        combined.merge(facts);
    }
    combined
}

#[derive(Clone, Default)]
pub(super) struct SyntaxFacts {
    pub(super) free_calls: BTreeSet<String>,
    associated_calls: BTreeSet<(String, String)>,
    pub(super) call_paths: BTreeSet<Vec<String>>,
    pub(super) loom_reference: bool,
    skip_test_context: bool,
}

impl SyntaxFacts {
    pub(super) fn calls(&self, expected: CallPattern) -> bool {
        match expected.owner {
            Some(owner) => self
                .associated_calls
                .contains(&(owner.to_string(), expected.function.to_string())),
            None => self.free_calls.contains(expected.function),
        }
    }

    fn merge(&mut self, other: &Self) {
        self.free_calls.extend(other.free_calls.iter().cloned());
        self.associated_calls
            .extend(other.associated_calls.iter().cloned());
        self.call_paths.extend(other.call_paths.iter().cloned());
        self.loom_reference |= other.loom_reference;
    }
}

impl<'ast> Visit<'ast> for SyntaxFacts {
    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        if attrs_allowed(self.skip_test_context, &item.attrs) {
            syn::visit::visit_item_mod(self, item);
        }
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if attrs_allowed(self.skip_test_context, &item.attrs) {
            syn::visit::visit_item_fn(self, item);
        }
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        if attrs_allowed(self.skip_test_context, &item.attrs) {
            syn::visit::visit_impl_item_fn(self, item);
        }
    }

    fn visit_path(&mut self, path: &'ast syn::Path) {
        self.loom_reference |= path
            .segments
            .first()
            .is_some_and(|segment| segment.ident == "loom");
        syn::visit::visit_path(self, path);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = call.func.as_ref() {
            let segments = path
                .path
                .segments
                .iter()
                .map(|segment| segment.ident.to_string())
                .collect::<Vec<_>>();
            if let Some(function) = segments.last() {
                self.free_calls.insert(function.clone());
            }
            self.call_paths.insert(segments.clone());
            if segments.len() >= 2 {
                self.associated_calls.insert((
                    segments[segments.len() - 2].clone(),
                    segments[segments.len() - 1].clone(),
                ));
            }
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_macro(&mut self, item: &'ast syn::Macro) {
        let parser = syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated;
        if let Ok(expressions) = parser.parse2(item.tokens.clone()) {
            for expression in &expressions {
                self.visit_expr(expression);
            }
        }
        syn::visit::visit_macro(self, item);
    }
}

pub(super) fn attrs_allowed(skip_test_context: bool, attrs: &[syn::Attribute]) -> bool {
    !skip_test_context || !super::attrs_are_test_context(attrs)
}

pub(super) fn syntax_facts(syntax: &syn::File, skip_test_context: bool) -> SyntaxFacts {
    let mut facts = SyntaxFacts {
        skip_test_context,
        ..SyntaxFacts::default()
    };
    facts.visit_file(syntax);
    facts
}

pub(super) fn free_function_call_graph(syntax: &syn::File) -> BTreeMap<String, BTreeSet<String>> {
    syntax
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Fn(function) => {
                let mut facts = SyntaxFacts::default();
                facts.visit_block(&function.block);
                Some((function.sig.ident.to_string(), facts.free_calls))
            }
            _ => None,
        })
        .collect()
}

pub(super) fn defines_symbol(syntax: &syn::File, expected: &str) -> bool {
    crate::common::rust_semantics::defines(syntax, expected)
}

pub(super) fn has_forbidden_model_name(syntax: &syn::File) -> bool {
    syntax.items.iter().any(|item| {
        matches!(item, syn::Item::Fn(function) if {
            let name = function.sig.ident.to_string();
            name.starts_with("model_only_") || name.starts_with("explanatory_model_")
        })
    })
}

pub(super) fn calls_from_module(
    syntax: &syn::File,
    module: &[&str],
    skip_test_context: bool,
) -> BTreeSet<String> {
    let facts = syntax_facts(syntax, skip_test_context);
    let imports = imports_from_module(syntax, module, skip_test_context);
    let mut calls = facts
        .call_paths
        .iter()
        .filter_map(|path| {
            (path.len() == module.len() + 1
                && path
                    .iter()
                    .take(module.len())
                    .map(String::as_str)
                    .eq(module.iter().copied()))
            .then(|| path.last().cloned())
            .flatten()
        })
        .collect::<BTreeSet<_>>();
    for (original, local) in imports {
        if facts.free_calls.contains(&local) {
            calls.insert(original);
        }
    }
    calls
}

fn imports_from_module(
    syntax: &syn::File,
    module: &[&str],
    skip_test_context: bool,
) -> Vec<(String, String)> {
    struct Imports<'a> {
        module: &'a [&'a str],
        skip_test_context: bool,
        imports: Vec<(String, String)>,
    }

    impl Imports<'_> {
        fn collect_tree(&mut self, tree: &syn::UseTree) {
            let mut pending = vec![(tree, Vec::new())];
            while let Some((tree, mut prefix)) = pending.pop() {
                match tree {
                    syn::UseTree::Path(path) => {
                        prefix.push(path.ident.to_string());
                        pending.push((&path.tree, prefix));
                    }
                    syn::UseTree::Name(name) => {
                        prefix.push(name.ident.to_string());
                        self.record(prefix, name.ident.to_string());
                    }
                    syn::UseTree::Rename(rename) => {
                        prefix.push(rename.ident.to_string());
                        self.record(prefix, rename.rename.to_string());
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

        fn record(&mut self, path: Vec<String>, local: String) {
            if path.len() == self.module.len() + 1
                && path
                    .iter()
                    .take(self.module.len())
                    .map(String::as_str)
                    .eq(self.module.iter().copied())
                && let Some(original) = path.last()
            {
                self.imports.push((original.clone(), local));
            }
        }
    }

    impl<'ast> Visit<'ast> for Imports<'_> {
        fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
            if attrs_allowed(self.skip_test_context, &item.attrs) {
                syn::visit::visit_item_mod(self, item);
            }
        }

        fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
            if attrs_allowed(self.skip_test_context, &item.attrs) {
                syn::visit::visit_item_fn(self, item);
            }
        }

        fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
            if attrs_allowed(self.skip_test_context, &item.attrs) {
                syn::visit::visit_impl_item_fn(self, item);
            }
        }

        fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
            if !self.skip_test_context || !super::attrs_are_test_context(&item.attrs) {
                self.collect_tree(&item.tree);
            }
        }
    }

    let mut imports = Imports {
        module,
        skip_test_context,
        imports: Vec::new(),
    };
    imports.visit_file(syntax);
    imports.imports
}

pub(super) fn declared_resource_fields(syntax: &syn::File) -> Vec<DeclaredResourceField> {
    #[derive(Default)]
    struct Resources {
        fields: Vec<DeclaredResourceField>,
    }

    fn path_tail(expression: &syn::Expr) -> Option<String> {
        let syn::Expr::Path(path) = expression else {
            return None;
        };
        path.path
            .segments
            .last()
            .map(|segment| segment.ident.to_string())
    }

    fn string_literal(expression: &syn::Expr) -> Option<String> {
        let syn::Expr::Lit(literal) = expression else {
            return None;
        };
        let syn::Lit::Str(value) = &literal.lit else {
            return None;
        };
        Some(value.value())
    }

    impl Visit<'_> for Resources {
        fn visit_expr_struct(&mut self, expression: &syn::ExprStruct) {
            if expression
                .path
                .segments
                .last()
                .is_some_and(|segment| segment.ident == "OwnedField")
            {
                let field = |name: &str| {
                    expression.fields.iter().find_map(|field| {
                        matches!(&field.member, syn::Member::Named(member) if member == name)
                            .then_some(&field.expr)
                    })
                };
                if let (Some(owner), Some(identity), Some(source_field)) = (
                    field("owner").and_then(path_tail),
                    field("field").and_then(path_tail),
                    field("source_field").and_then(string_literal),
                ) {
                    self.fields.push(DeclaredResourceField {
                        owner,
                        identity,
                        source_field,
                    });
                }
            }
            syn::visit::visit_expr_struct(self, expression);
        }
    }

    let mut resources = Resources::default();
    resources.visit_file(syntax);
    resources.fields
}
