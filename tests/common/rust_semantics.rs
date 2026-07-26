use quote::ToTokens;
use std::fs;
use std::path::Path;
use syn::visit::Visit;

#[derive(Default)]
struct IdentifierCollector(std::collections::BTreeSet<String>);

impl Visit<'_> for IdentifierCollector {
    fn visit_ident(&mut self, ident: &proc_macro2::Ident) {
        self.0.insert(ident.to_string());
    }
}

pub(super) fn parse_file(path: &Path) -> syn::File {
    let source =
        fs::read_to_string(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    syn::parse_file(&source).unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
}

pub(super) fn attrs_are_test_context(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("test")
            || (attr.path().is_ident("cfg")
                && quote::quote!(#attr)
                    .to_string()
                    .split(|character: char| !character.is_ascii_alphanumeric())
                    .any(|fragment| fragment == "test"))
    })
}

pub(super) fn defines(syntax: &syn::File, expected: &str) -> bool {
    let mut visitor = DefinitionVisitor {
        expected,
        found: false,
    };
    visitor.visit_file(syntax);
    visitor.found
}

pub(super) fn defines_type(syntax: &syn::File, expected: &str) -> bool {
    struct TypeDefinition<'a> {
        expected: &'a str,
        found: bool,
    }

    impl Visit<'_> for TypeDefinition<'_> {
        fn visit_item(&mut self, item: &syn::Item) {
            self.found |= match item {
                syn::Item::Enum(item) => item.ident == self.expected,
                syn::Item::Struct(item) => item.ident == self.expected,
                syn::Item::Union(item) => item.ident == self.expected,
                _ => false,
            };
            if !self.found {
                syn::visit::visit_item(self, item);
            }
        }
    }

    let mut visitor = TypeDefinition {
        expected,
        found: false,
    };
    visitor.visit_file(syntax);
    visitor.found
}

pub(super) fn references_ident(syntax: &syn::File, expected: &str) -> bool {
    let mut visitor = ReferenceVisitor {
        expected,
        found: false,
    };
    visitor.visit_file(syntax);
    visitor.found
}

pub(super) fn identifiers(syntax: &syn::File) -> std::collections::BTreeSet<String> {
    let mut visitor = IdentifierCollector::default();
    visitor.visit_file(syntax);
    visitor.0
}

pub(super) fn function_names_with_prefix(syntax: &syn::File, prefix: &str) -> Vec<String> {
    struct Collector<'prefix> {
        prefix: &'prefix str,
        names: Vec<String>,
    }

    impl<'ast> Visit<'ast> for Collector<'_> {
        fn visit_item_fn(&mut self, function: &'ast syn::ItemFn) {
            if !attrs_are_test_context(&function.attrs)
                && function.sig.ident.to_string().starts_with(self.prefix)
            {
                self.names.push(function.sig.ident.to_string());
            }
            syn::visit::visit_item_fn(self, function);
        }

        fn visit_impl_item_fn(&mut self, function: &'ast syn::ImplItemFn) {
            if !attrs_are_test_context(&function.attrs)
                && function.sig.ident.to_string().starts_with(self.prefix)
            {
                self.names.push(function.sig.ident.to_string());
            }
            syn::visit::visit_impl_item_fn(self, function);
        }

        fn visit_trait_item_fn(&mut self, function: &'ast syn::TraitItemFn) {
            if !attrs_are_test_context(&function.attrs)
                && function.sig.ident.to_string().starts_with(self.prefix)
            {
                self.names.push(function.sig.ident.to_string());
            }
            syn::visit::visit_trait_item_fn(self, function);
        }
    }

    let mut collector = Collector {
        prefix,
        names: Vec::new(),
    };
    collector.visit_file(syntax);
    collector.names
}

pub(super) fn expression_identifiers(expression: &syn::Expr) -> std::collections::BTreeSet<String> {
    let mut visitor = IdentifierCollector::default();
    visitor.visit_expr(expression);
    visitor.0
}

pub(super) fn atomic_operation_method(name: &str) -> bool {
    matches!(
        name,
        "load" | "store" | "swap" | "compare_exchange" | "compare_exchange_weak" | "try_update"
    ) || name.starts_with("fetch_")
}

pub(super) fn expression_uses_seq_cst(expression: &syn::Expr) -> bool {
    struct OrderingFinder {
        found: bool,
    }

    impl<'ast> Visit<'ast> for OrderingFinder {
        fn visit_expr_path(&mut self, expression: &'ast syn::ExprPath) {
            let mut segments = expression.path.segments.iter().rev();
            self.found |= segments
                .next()
                .is_some_and(|segment| segment.ident == "SeqCst")
                && segments
                    .next()
                    .is_some_and(|segment| segment.ident == "Ordering");
            if !self.found {
                syn::visit::visit_expr_path(self, expression);
            }
        }
    }

    let mut finder = OrderingFinder { found: false };
    finder.visit_expr(expression);
    finder.found
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct SeqCstAtomicCall {
    pub(super) function: String,
    pub(super) method: String,
}

pub(super) fn seq_cst_atomic_calls(syntax: &syn::File) -> Vec<SeqCstAtomicCall> {
    struct Collector {
        functions: Vec<String>,
        calls: Vec<SeqCstAtomicCall>,
    }

    impl Collector {
        fn enter_function(&mut self, name: &syn::Ident, body: &syn::Block) {
            self.functions.push(name.to_string());
            self.visit_block(body);
            self.functions.pop();
        }
    }

    impl<'ast> Visit<'ast> for Collector {
        fn visit_item_fn(&mut self, function: &'ast syn::ItemFn) {
            self.enter_function(&function.sig.ident, &function.block);
        }

        fn visit_impl_item_fn(&mut self, function: &'ast syn::ImplItemFn) {
            self.enter_function(&function.sig.ident, &function.block);
        }

        fn visit_trait_item_fn(&mut self, function: &'ast syn::TraitItemFn) {
            if let Some(body) = &function.default {
                self.enter_function(&function.sig.ident, body);
            }
        }

        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            let method = call.method.to_string();
            if atomic_operation_method(&method) && call.args.iter().any(expression_uses_seq_cst) {
                self.calls.push(SeqCstAtomicCall {
                    function: self
                        .functions
                        .last()
                        .cloned()
                        .unwrap_or_else(|| "<module>".to_string()),
                    method,
                });
            }
            syn::visit::visit_expr_method_call(self, call);
        }
    }

    let mut collector = Collector {
        functions: Vec::new(),
        calls: Vec::new(),
    };
    collector.visit_file(syntax);
    collector.calls
}

pub(super) fn type_identifiers(ty: &syn::Type) -> std::collections::BTreeSet<String> {
    let mut visitor = IdentifierCollector::default();
    visitor.visit_type(ty);
    visitor.0
}

pub(super) fn token_identifiers(
    tokens: proc_macro2::TokenStream,
) -> std::collections::BTreeSet<String> {
    let mut identifiers = std::collections::BTreeSet::new();
    let mut pending = vec![tokens];
    while let Some(tokens) = pending.pop() {
        for token in tokens {
            match token {
                proc_macro2::TokenTree::Ident(ident) => {
                    identifiers.insert(ident.to_string());
                }
                proc_macro2::TokenTree::Group(group) => pending.push(group.stream()),
                proc_macro2::TokenTree::Punct(_) | proc_macro2::TokenTree::Literal(_) => {}
            }
        }
    }
    identifiers
}

pub(super) fn calls(syntax: &syn::File, expected: &[&str]) -> bool {
    let mut visitor = CallVisitor {
        expected,
        found: false,
    };
    visitor.visit_file(syntax);
    visitor.found
}

pub(super) fn struct_has_field_type(
    syntax: &syn::File,
    structure: &str,
    field: &str,
    expected_type_path: &[&str],
) -> bool {
    let mut visitor = StructFieldVisitor {
        structure,
        field,
        expected_type_path,
        found: false,
    };
    visitor.visit_file(syntax);
    visitor.found
}

pub(super) fn has_nested_type(syntax: &syn::File, outer: &str, inner: &str) -> bool {
    let mut visitor = NestedTypeVisitor {
        outer,
        inner,
        found: false,
    };
    visitor.visit_file(syntax);
    visitor.found
}

pub(super) fn has_unsafe_impl(syntax: &syn::File, trait_name: &str) -> bool {
    let mut visitor = UnsafeImplVisitor {
        trait_name,
        found: false,
    };
    visitor.visit_file(syntax);
    visitor.found
}

pub(super) fn callback_parameter_named(syntax: &syn::File, parameter_names: &[&str]) -> bool {
    let mut visitor = CallbackParameterVisitor {
        parameter_names,
        found: false,
    };
    visitor.visit_file(syntax);
    visitor.found
}

pub(super) fn local_initializer_references(
    syntax: &syn::File,
    binding_name: &str,
    referenced: &str,
) -> bool {
    let mut visitor = LocalInitializerVisitor {
        binding_name,
        referenced,
        found: false,
    };
    visitor.visit_file(syntax);
    visitor.found
}

pub(super) fn enum_has_variant(syntax: &syn::File, enum_name: &str, variant: &str) -> bool {
    syntax.items.iter().any(|item| {
        matches!(item, syn::Item::Enum(item) if item.ident == enum_name && item.variants.iter().any(|candidate| candidate.ident == variant))
    })
}

pub(super) fn type_name(ty: &syn::Type) -> Option<String> {
    let syn::Type::Path(path) = ty else {
        return None;
    };
    path.path
        .segments
        .last()
        .map(|segment| segment.ident.to_string())
}

pub(super) fn named_struct_fields(
    syntax: &syn::File,
    owner: &str,
) -> std::collections::BTreeSet<String> {
    syntax
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Struct(item) if item.ident == owner => Some(
                item.fields
                    .iter()
                    .filter_map(|field| field.ident.as_ref().map(ToString::to_string))
                    .collect(),
            ),
            _ => None,
        })
        .unwrap_or_default()
}

pub(super) fn parameter_is_consumed(
    syntax: &syn::File,
    function_name: &str,
    parameter_name: &str,
    method: bool,
) -> bool {
    struct Finder<'a> {
        function_name: &'a str,
        parameter_name: &'a str,
        method: bool,
        found: bool,
    }

    impl Finder<'_> {
        fn inspect(&mut self, signature: &syn::Signature) {
            if signature.ident != self.function_name {
                return;
            }
            self.found = signature.inputs.iter().any(|argument| {
                let syn::FnArg::Typed(argument) = argument else {
                    return false;
                };
                let syn::Pat::Ident(identifier) = argument.pat.as_ref() else {
                    return false;
                };
                identifier.ident == self.parameter_name
                    && !matches!(argument.ty.as_ref(), syn::Type::Reference(_))
            });
        }
    }

    impl<'ast> Visit<'ast> for Finder<'_> {
        fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
            if !self.method {
                self.inspect(&item.sig);
            }
            syn::visit::visit_item_fn(self, item);
        }

        fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
            if self.method {
                self.inspect(&item.sig);
            }
            syn::visit::visit_impl_item_fn(self, item);
        }
    }

    let mut finder = Finder {
        function_name,
        parameter_name,
        method,
        found: false,
    };
    finder.visit_file(syntax);
    finder.found
}

/// Reports semantic string operations performed directly on Rust source text.
///
/// Reading source is only an input step. Policies that reason about Rust must
/// parse that text and inspect syntax; otherwise comments and literals can
/// satisfy or hide the purported invariant.
pub(super) fn raw_rust_source_semantic_scans(syntax: &syn::File) -> Vec<String> {
    let readers = source_text_reader_functions(syntax, &std::collections::BTreeSet::new());
    raw_rust_source_semantic_scans_with_readers(syntax, &readers)
}

pub(super) fn source_text_reader_functions(
    syntax: &syn::File,
    known_readers: &std::collections::BTreeSet<String>,
) -> std::collections::BTreeSet<String> {
    struct ReaderCalls<'a> {
        known_readers: &'a std::collections::BTreeSet<String>,
        found: bool,
    }

    impl Visit<'_> for ReaderCalls<'_> {
        fn visit_expr_call(&mut self, call: &syn::ExprCall) {
            if let syn::Expr::Path(path) = call.func.as_ref()
                && path.path.segments.last().is_some_and(|segment| {
                    segment.ident == "read_to_string"
                        || self.known_readers.contains(&segment.ident.to_string())
                })
            {
                self.found = true;
            }
            if !self.found {
                syn::visit::visit_expr_call(self, call);
            }
        }

        fn visit_expr_method_call(&mut self, call: &syn::ExprMethodCall) {
            self.found |= call.method == "read_to_string";
            if !self.found {
                syn::visit::visit_expr_method_call(self, call);
            }
        }

        fn visit_item_fn(&mut self, _item: &syn::ItemFn) {}
        fn visit_impl_item_fn(&mut self, _item: &syn::ImplItemFn) {}
        fn visit_trait_item_fn(&mut self, _item: &syn::TraitItemFn) {}
    }

    fn returns_text(output: &syn::ReturnType) -> bool {
        let syn::ReturnType::Type(_, ty) = output else {
            return false;
        };
        type_identifiers(ty)
            .iter()
            .any(|name| matches!(name.as_str(), "String" | "str"))
    }

    fn body_reads_source(
        block: &syn::Block,
        known_readers: &std::collections::BTreeSet<String>,
    ) -> bool {
        let mut calls = ReaderCalls {
            known_readers,
            found: false,
        };
        calls.visit_block(block);
        calls.found
    }

    let mut readers = std::collections::BTreeSet::new();
    for item in &syntax.items {
        match item {
            syn::Item::Fn(function)
                if returns_text(&function.sig.output)
                    && body_reads_source(&function.block, known_readers) =>
            {
                readers.insert(function.sig.ident.to_string());
            }
            syn::Item::Impl(implementation) => {
                for method in &implementation.items {
                    if let syn::ImplItem::Fn(method) = method
                        && returns_text(&method.sig.output)
                        && body_reads_source(&method.block, known_readers)
                    {
                        readers.insert(method.sig.ident.to_string());
                    }
                }
            }
            syn::Item::Trait(trait_item) => {
                for method in &trait_item.items {
                    if let syn::TraitItem::Fn(method) = method
                        && returns_text(&method.sig.output)
                        && method
                            .default
                            .as_ref()
                            .is_some_and(|block| body_reads_source(block, known_readers))
                    {
                        readers.insert(method.sig.ident.to_string());
                    }
                }
            }
            _ => {}
        }
    }
    readers
}

pub(super) fn raw_rust_source_semantic_scans_with_readers(
    syntax: &syn::File,
    source_readers: &std::collections::BTreeSet<String>,
) -> Vec<String> {
    const SEMANTIC_TEXT_METHODS: &[&str] = &[
        "contains",
        "ends_with",
        "find",
        "match_indices",
        "matches",
        "rfind",
        "split",
        "starts_with",
    ];

    #[derive(Default)]
    struct LocalSources<'ast> {
        initializers: Vec<(&'ast syn::Pat, &'ast syn::Expr)>,
    }

    impl<'ast> Visit<'ast> for LocalSources<'ast> {
        fn visit_local(&mut self, local: &'ast syn::Local) {
            if let Some(initial) = &local.init {
                self.initializers.push((&local.pat, initial.expr.as_ref()));
            }
            syn::visit::visit_local(self, local);
        }

        fn visit_item_fn(&mut self, _item: &'ast syn::ItemFn) {}
        fn visit_impl_item_fn(&mut self, _item: &'ast syn::ImplItemFn) {}
        fn visit_trait_item_fn(&mut self, _item: &'ast syn::TraitItemFn) {}
    }

    struct Audit<'a> {
        source_bindings: &'a std::collections::BTreeSet<String>,
        source_readers: &'a std::collections::BTreeSet<String>,
        violations: Vec<String>,
    }

    impl Visit<'_> for Audit<'_> {
        fn visit_expr_method_call(&mut self, call: &syn::ExprMethodCall) {
            if SEMANTIC_TEXT_METHODS.contains(&call.method.to_string().as_str())
                && expression_is_source_text(
                    call.receiver.as_ref(),
                    self.source_bindings,
                    self.source_readers,
                )
            {
                self.violations
                    .push(format!("{}() on raw read_to_string source", call.method));
            }
            syn::visit::visit_expr_method_call(self, call);
        }

        fn visit_macro(&mut self, item: &syn::Macro) {
            use syn::parse::Parser;

            let parser = syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated;
            if let Ok(expressions) = parser.parse2(item.tokens.clone()) {
                for expression in expressions {
                    self.visit_expr(&expression);
                }
            }
            syn::visit::visit_macro(self, item);
        }

        fn visit_item_fn(&mut self, _item: &syn::ItemFn) {}
        fn visit_impl_item_fn(&mut self, _item: &syn::ImplItemFn) {}
        fn visit_trait_item_fn(&mut self, _item: &syn::TraitItemFn) {}
    }

    fn expression_is_source_text(
        expression: &syn::Expr,
        source_bindings: &std::collections::BTreeSet<String>,
        source_readers: &std::collections::BTreeSet<String>,
    ) -> bool {
        const TEXT_PRESERVING_METHODS: &[&str] = &[
            "as_ref",
            "as_str",
            "borrow",
            "clone",
            "expect",
            "to_owned",
            "to_string",
            "unwrap",
            "unwrap_or_else",
        ];
        let mut current = expression;
        loop {
            current = match current {
                syn::Expr::Path(path) => {
                    return path.path.segments.last().is_some_and(|segment| {
                        source_bindings.contains(&segment.ident.to_string())
                    });
                }
                syn::Expr::Call(call) => {
                    return matches!(call.func.as_ref(), syn::Expr::Path(path)
                        if path.path.segments.last().is_some_and(|segment|
                            segment.ident == "read_to_string"
                                || source_readers.contains(&segment.ident.to_string())));
                }
                syn::Expr::MethodCall(call) if call.method == "read_to_string" => return true,
                syn::Expr::MethodCall(call)
                    if TEXT_PRESERVING_METHODS.contains(&call.method.to_string().as_str()) =>
                {
                    call.receiver.as_ref()
                }
                syn::Expr::Reference(reference) => reference.expr.as_ref(),
                syn::Expr::Paren(paren) => &paren.expr,
                syn::Expr::Group(group) => &group.expr,
                syn::Expr::Try(try_expression) => &try_expression.expr,
                _ => return false,
            };
        }
    }

    fn pattern_binding(pattern: &syn::Pat) -> Option<String> {
        let mut current = pattern;
        loop {
            match current {
                syn::Pat::Ident(binding) => return Some(binding.ident.to_string()),
                syn::Pat::Type(typed) => current = &typed.pat,
                _ => return None,
            }
        }
    }

    fn scan_block(
        block: &syn::Block,
        source_readers: &std::collections::BTreeSet<String>,
    ) -> Vec<String> {
        let mut locals = LocalSources::default();
        locals.visit_block(block);
        let mut source_bindings = std::collections::BTreeSet::new();
        loop {
            let mut changed = false;
            for (pattern, initializer) in &locals.initializers {
                let Some(binding) = pattern_binding(pattern) else {
                    continue;
                };
                if !source_bindings.contains(&binding)
                    && expression_is_source_text(initializer, &source_bindings, source_readers)
                {
                    changed |= source_bindings.insert(binding);
                }
            }
            if !changed {
                break;
            }
        }

        let mut audit = Audit {
            source_bindings: &source_bindings,
            source_readers,
            violations: Vec::new(),
        };
        audit.visit_block(block);
        audit.violations
    }

    #[derive(Default)]
    struct FunctionAudit {
        source_readers: std::collections::BTreeSet<String>,
        violations: Vec<String>,
    }

    impl FunctionAudit {
        fn scan_function_block(&mut self, block: &syn::Block) {
            self.violations
                .extend(scan_block(block, &self.source_readers));
            syn::visit::visit_block(self, block);
        }
    }

    impl Visit<'_> for FunctionAudit {
        fn visit_item_fn(&mut self, item: &syn::ItemFn) {
            self.scan_function_block(&item.block);
        }

        fn visit_impl_item_fn(&mut self, item: &syn::ImplItemFn) {
            self.scan_function_block(&item.block);
        }

        fn visit_trait_item_fn(&mut self, item: &syn::TraitItemFn) {
            if let Some(block) = &item.default {
                self.scan_function_block(block);
            }
        }
    }

    let mut audit = FunctionAudit {
        source_readers: source_readers.clone(),
        violations: Vec::new(),
    };
    audit.visit_file(syntax);
    audit.violations.sort();
    audit.violations.dedup();
    audit.violations
}

fn path_ends_with(path: &syn::Path, expected: &[&str]) -> bool {
    let actual = path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>();
    actual.len() >= expected.len()
        && actual[actual.len() - expected.len()..]
            .iter()
            .map(String::as_str)
            .eq(expected.iter().copied())
}

struct DefinitionVisitor<'a> {
    expected: &'a str,
    found: bool,
}

impl Visit<'_> for DefinitionVisitor<'_> {
    fn visit_item(&mut self, item: &syn::Item) {
        self.found |= match item {
            syn::Item::Const(item) => item.ident == self.expected,
            syn::Item::Enum(item) => item.ident == self.expected,
            syn::Item::Fn(item) => item.sig.ident == self.expected,
            syn::Item::Static(item) => item.ident == self.expected,
            syn::Item::Struct(item) => item.ident == self.expected,
            syn::Item::Trait(item) => item.ident == self.expected,
            syn::Item::TraitAlias(item) => item.ident == self.expected,
            syn::Item::Type(item) => item.ident == self.expected,
            syn::Item::Union(item) => item.ident == self.expected,
            _ => false,
        };
        if !self.found {
            syn::visit::visit_item(self, item);
        }
    }

    fn visit_impl_item_fn(&mut self, item: &syn::ImplItemFn) {
        self.found |= item.sig.ident == self.expected;
        if !self.found {
            syn::visit::visit_impl_item_fn(self, item);
        }
    }

    fn visit_trait_item_fn(&mut self, item: &syn::TraitItemFn) {
        self.found |= item.sig.ident == self.expected;
        if !self.found {
            syn::visit::visit_trait_item_fn(self, item);
        }
    }
}

struct ReferenceVisitor<'a> {
    expected: &'a str,
    found: bool,
}

impl Visit<'_> for ReferenceVisitor<'_> {
    fn visit_path(&mut self, path: &syn::Path) {
        self.found |= path
            .segments
            .iter()
            .any(|segment| segment.ident == self.expected);
        if !self.found {
            syn::visit::visit_path(self, path);
        }
    }

    fn visit_ident(&mut self, ident: &proc_macro2::Ident) {
        self.found |= ident == self.expected;
    }
}

struct CallVisitor<'a> {
    expected: &'a [&'a str],
    found: bool,
}

impl Visit<'_> for CallVisitor<'_> {
    fn visit_expr_call(&mut self, call: &syn::ExprCall) {
        self.found |= matches!(call.func.as_ref(), syn::Expr::Path(path) if path_ends_with(&path.path, self.expected));
        if !self.found {
            syn::visit::visit_expr_call(self, call);
        }
    }

    fn visit_expr_method_call(&mut self, call: &syn::ExprMethodCall) {
        self.found |= self
            .expected
            .last()
            .is_some_and(|expected| call.method == expected);
        if !self.found {
            syn::visit::visit_expr_method_call(self, call);
        }
    }
}

struct StructFieldVisitor<'a> {
    structure: &'a str,
    field: &'a str,
    expected_type_path: &'a [&'a str],
    found: bool,
}

impl Visit<'_> for StructFieldVisitor<'_> {
    fn visit_item_struct(&mut self, item: &syn::ItemStruct) {
        if item.ident == self.structure {
            self.found = item.fields.iter().any(|field| {
                field
                    .ident
                    .as_ref()
                    .is_some_and(|ident| ident == self.field)
                    && type_references_path(&field.ty, self.expected_type_path)
            });
        }
        if !self.found {
            syn::visit::visit_item_struct(self, item);
        }
    }
}

fn type_references_path(ty: &syn::Type, expected: &[&str]) -> bool {
    struct Visitor<'a> {
        expected: &'a [&'a str],
        found: bool,
    }
    impl Visit<'_> for Visitor<'_> {
        fn visit_path(&mut self, path: &syn::Path) {
            self.found |= path_ends_with(path, self.expected);
            if !self.found {
                syn::visit::visit_path(self, path);
            }
        }
    }
    let mut visitor = Visitor {
        expected,
        found: false,
    };
    visitor.visit_type(ty);
    visitor.found
}

pub(super) fn type_references_ident(ty: &syn::Type, expected: &str) -> bool {
    type_references_path(ty, &[expected])
}

pub(super) fn pattern_references_ident(pattern: &syn::Pat, expected: &str) -> bool {
    let mut visitor = ReferenceVisitor {
        expected,
        found: false,
    };
    visitor.visit_pat(pattern);
    visitor.found
}

struct NestedTypeVisitor<'a> {
    outer: &'a str,
    inner: &'a str,
    found: bool,
}

impl Visit<'_> for NestedTypeVisitor<'_> {
    fn visit_type_path(&mut self, ty: &syn::TypePath) {
        if ty
            .path
            .segments
            .last()
            .is_some_and(|segment| segment.ident == self.outer)
        {
            self.found |= ty
                .path
                .segments
                .last()
                .and_then(|segment| match &segment.arguments {
                    syn::PathArguments::AngleBracketed(arguments) => Some(arguments),
                    _ => None,
                })
                .is_some_and(|arguments| {
                    arguments.args.iter().any(|argument| {
                        matches!(argument, syn::GenericArgument::Type(inner) if type_references_path(inner, &[self.inner]))
                    })
                });
        }
        if !self.found {
            syn::visit::visit_type_path(self, ty);
        }
    }
}

struct UnsafeImplVisitor<'a> {
    trait_name: &'a str,
    found: bool,
}

impl Visit<'_> for UnsafeImplVisitor<'_> {
    fn visit_item_impl(&mut self, item: &syn::ItemImpl) {
        self.found |= item.unsafety.is_some()
            && item
                .trait_
                .as_ref()
                .is_some_and(|(path, _)| path_ends_with(path, &[self.trait_name]));
        if !self.found {
            syn::visit::visit_item_impl(self, item);
        }
    }
}

struct CallbackParameterVisitor<'a> {
    parameter_names: &'a [&'a str],
    found: bool,
}

impl CallbackParameterVisitor<'_> {
    fn inspect(&mut self, signature: &syn::Signature) {
        for input in &signature.inputs {
            let syn::FnArg::Typed(argument) = input else {
                continue;
            };
            let syn::Pat::Ident(binding) = argument.pat.as_ref() else {
                continue;
            };
            if self
                .parameter_names
                .iter()
                .any(|name| binding.ident == name)
                && type_contains_fn_trait(&argument.ty)
            {
                self.found = true;
                return;
            }
        }
    }
}

impl Visit<'_> for CallbackParameterVisitor<'_> {
    fn visit_item_fn(&mut self, item: &syn::ItemFn) {
        self.inspect(&item.sig);
        if !self.found {
            syn::visit::visit_item_fn(self, item);
        }
    }

    fn visit_impl_item_fn(&mut self, item: &syn::ImplItemFn) {
        self.inspect(&item.sig);
        if !self.found {
            syn::visit::visit_impl_item_fn(self, item);
        }
    }
}

fn type_contains_fn_trait(ty: &syn::Type) -> bool {
    let tokens = ty.to_token_stream();
    tokens.into_iter().any(|token| {
        matches!(token, proc_macro2::TokenTree::Ident(ident) if matches!(ident.to_string().as_str(), "Fn" | "FnMut" | "FnOnce"))
    })
}

struct LocalInitializerVisitor<'a> {
    binding_name: &'a str,
    referenced: &'a str,
    found: bool,
}

impl Visit<'_> for LocalInitializerVisitor<'_> {
    fn visit_local(&mut self, local: &syn::Local) {
        let matching_binding = matches!(
            &local.pat,
            syn::Pat::Ident(binding) if binding.ident == self.binding_name
        );
        if matching_binding && let Some(initializer) = &local.init {
            let mut references = ReferenceVisitor {
                expected: self.referenced,
                found: false,
            };
            references.visit_expr(&initializer.expr);
            self.found = references.found;
        }
        if !self.found {
            syn::visit::visit_local(self, local);
        }
    }
}
