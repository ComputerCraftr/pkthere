use super::FunctionRecord;
use quote::ToTokens;
use std::collections::{BTreeMap, BTreeSet};
use syn::visit::Visit;
use syn::visit_mut::VisitMut;

pub(super) const MAX_FUNCTION_AST_DEPTH: usize = 64;
pub(super) const MAX_RESOLVED_CALL_DEPTH: usize = 64;

pub(super) fn module_scope_for_path(path: &str) -> String {
    let mut components = path
        .trim_end_matches(".rs")
        .split('/')
        .map(str::to_string)
        .collect::<Vec<_>>();
    if matches!(
        components.last().map(String::as_str),
        Some("lib" | "main" | "mod")
    ) {
        components.pop();
    }
    components.join("::")
}

fn qualified_name(function: &FunctionRecord) -> String {
    format!("{}::{}", function.scope, function.name)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DuplicateBodyKind {
    TrivialAdapter,
    Substantive,
}

pub(super) fn duplicate_body_kind(block: &syn::Block, _trait_adapter: bool) -> DuplicateBodyKind {
    if block.stmts.is_empty() {
        return DuplicateBodyKind::TrivialAdapter;
    }
    let [statement] = block.stmts.as_slice() else {
        return DuplicateBodyKind::Substantive;
    };
    let expression = match statement {
        syn::Stmt::Expr(expression, _) => expression,
        syn::Stmt::Local(_) | syn::Stmt::Item(_) | syn::Stmt::Macro(_) => {
            return DuplicateBodyKind::Substantive;
        }
    };
    if is_trivial_adapter_expression(expression) {
        DuplicateBodyKind::TrivialAdapter
    } else {
        DuplicateBodyKind::Substantive
    }
}

fn is_trivial_adapter_expression(expression: &syn::Expr) -> bool {
    enum Node<'a> {
        Expression(&'a syn::Expr),
        Statement(&'a syn::Stmt),
    }
    let mut pending = vec![Node::Expression(expression)];
    while let Some(node) = pending.pop() {
        let expression = match node {
            Node::Statement(syn::Stmt::Expr(expression, _)) => expression,
            Node::Statement(syn::Stmt::Local(_) | syn::Stmt::Item(_) | syn::Stmt::Macro(_)) => {
                return false;
            }
            Node::Expression(expression) => expression,
        };
        match expression {
            syn::Expr::Array(array) => pending.extend(array.elems.iter().map(Node::Expression)),
            syn::Expr::Block(block) => {
                pending.extend(block.block.stmts.iter().map(Node::Statement));
            }
            syn::Expr::Call(call) => {
                pending.push(Node::Expression(&call.func));
                pending.extend(call.args.iter().map(Node::Expression));
            }
            syn::Expr::Cast(cast) => pending.push(Node::Expression(&cast.expr)),
            syn::Expr::Field(field) => pending.push(Node::Expression(&field.base)),
            syn::Expr::Group(group) => pending.push(Node::Expression(&group.expr)),
            syn::Expr::If(expression) => {
                pending.push(Node::Expression(&expression.cond));
                pending.extend(expression.then_branch.stmts.iter().map(Node::Statement));
                if let Some((_, alternate)) = &expression.else_branch {
                    pending.push(Node::Expression(alternate));
                }
            }
            syn::Expr::Index(index) => {
                pending.push(Node::Expression(&index.expr));
                pending.push(Node::Expression(&index.index));
            }
            syn::Expr::Lit(_) | syn::Expr::Path(_) => {}
            syn::Expr::MethodCall(call) => {
                pending.push(Node::Expression(&call.receiver));
                pending.extend(call.args.iter().map(Node::Expression));
            }
            syn::Expr::Paren(paren) => pending.push(Node::Expression(&paren.expr)),
            syn::Expr::Macro(expression) if expression.mac.path.is_ident("matches") => {}
            syn::Expr::Reference(reference) => pending.push(Node::Expression(&reference.expr)),
            syn::Expr::Return(returned) => {
                if let Some(returned) = returned.expr.as_deref() {
                    pending.push(Node::Expression(returned));
                }
            }
            syn::Expr::Tuple(tuple) => pending.extend(tuple.elems.iter().map(Node::Expression)),
            syn::Expr::Unary(unary) => pending.push(Node::Expression(&unary.expr)),
            _ => return false,
        }
    }
    true
}

pub(super) fn canonical_function_body(
    inputs: &syn::punctuated::Punctuated<syn::FnArg, syn::Token![,]>,
    block: &syn::Block,
) -> String {
    let mut bindings = BindingCollector::default();
    for input in inputs {
        if let syn::FnArg::Typed(argument) = input {
            bindings.visit_pat(&argument.pat);
        }
    }
    bindings.visit_block(block);
    let mut canonical = block.clone();
    AlphaCanonicalizer {
        bindings: bindings
            .names
            .into_iter()
            .enumerate()
            .map(|(index, name)| (name, format!("__local_{index}")))
            .collect(),
    }
    .visit_block_mut(&mut canonical);
    canonical.to_token_stream().to_string()
}

#[derive(Default)]
pub(super) struct BindingCollector {
    pub(super) names: Vec<String>,
}

impl Visit<'_> for BindingCollector {
    fn visit_pat_ident(&mut self, pattern: &syn::PatIdent) {
        let name = pattern.ident.to_string();
        if name != "self" && !self.names.contains(&name) {
            self.names.push(name);
        }
        syn::visit::visit_pat_ident(self, pattern);
    }
}

struct AlphaCanonicalizer {
    bindings: BTreeMap<String, String>,
}

impl VisitMut for AlphaCanonicalizer {
    fn visit_pat_ident_mut(&mut self, pattern: &mut syn::PatIdent) {
        if let Some(canonical) = self.bindings.get(&pattern.ident.to_string()) {
            pattern.ident = syn::Ident::new(canonical, pattern.ident.span());
        }
        syn::visit_mut::visit_pat_ident_mut(self, pattern);
    }

    fn visit_expr_path_mut(&mut self, expression: &mut syn::ExprPath) {
        if expression.qself.is_none()
            && let Some(first) = expression.path.segments.first_mut()
            && let Some(canonical) = self.bindings.get(&first.ident.to_string())
        {
            first.ident = syn::Ident::new(canonical, first.ident.span());
        }
        syn::visit_mut::visit_expr_path_mut(self, expression);
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct CallReference {
    path: Vec<String>,
    argument_count: usize,
    receiver: CallReceiver,
}

impl CallReference {
    fn free(path: Vec<String>, argument_count: usize) -> Self {
        Self {
            path,
            argument_count,
            receiver: CallReceiver::FreeOrAssociated,
        }
    }

    fn method(path: Vec<String>, argument_count: usize) -> Self {
        Self {
            path,
            argument_count,
            receiver: CallReceiver::Method,
        }
    }

    fn name(&self) -> Option<&str> {
        self.path.last().map(String::as_str)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum CallReceiver {
    FreeOrAssociated,
    Method,
}

pub(super) struct FunctionCallCollector {
    pub(super) calls: BTreeSet<CallReference>,
    pub(super) local_bindings: BTreeSet<String>,
}

impl Visit<'_> for FunctionCallCollector {
    fn visit_expr_call(&mut self, call: &syn::ExprCall) {
        if let syn::Expr::Path(path) = call.func.as_ref() {
            let segments = path
                .path
                .segments
                .iter()
                .map(|segment| segment.ident.to_string())
                .collect::<Vec<_>>();
            if path.qself.is_none()
                && let Some(callee) = segments.last()
                && !self.local_bindings.contains(callee)
            {
                self.calls
                    .insert(CallReference::free(segments, call.args.len()));
            }
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &syn::ExprMethodCall) {
        if matches!(
            call.receiver.as_ref(),
            syn::Expr::Path(path) if path.path.is_ident("self")
        ) {
            self.calls.insert(CallReference::method(
                vec!["Self".to_string(), call.method.to_string()],
                call.args.len(),
            ));
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_item_fn(&mut self, _item: &syn::ItemFn) {}
    fn visit_impl_item_fn(&mut self, _item: &syn::ImplItemFn) {}
    fn visit_trait_item_fn(&mut self, _item: &syn::TraitItemFn) {}
}

pub(super) fn contains_direct_recursion(
    name: &str,
    is_method: bool,
    is_trait_adapter: bool,
    has_receiver: bool,
    explicit_argument_count: usize,
    block: &syn::Block,
) -> bool {
    let mut visitor = RecursionVisitor {
        name,
        is_method,
        is_trait_adapter,
        has_receiver,
        explicit_argument_count,
        found: false,
    };
    visitor.visit_block(block);
    visitor.found
}

struct RecursionVisitor<'a> {
    name: &'a str,
    is_method: bool,
    is_trait_adapter: bool,
    has_receiver: bool,
    explicit_argument_count: usize,
    found: bool,
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
            let expected_associated_arguments = self
                .explicit_argument_count
                .saturating_add(usize::from(self.has_receiver));
            let self_associated = self.is_method
                && segments.len() == 2
                && segments[0] == "Self"
                && segments[1] == self.name
                && (!self.is_trait_adapter || call.args.len() == expected_associated_arguments);
            self.found |= bare_free || self_free || self_associated;
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        let self_receiver = matches!(
            &*call.receiver,
            syn::Expr::Path(path) if path.path.is_ident("self")
        );
        let matching_trait_arity =
            !self.is_trait_adapter || call.args.len() == self.explicit_argument_count;
        self.found |=
            self.is_method && self_receiver && call.method == self.name && matching_trait_arity;
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_item_fn(&mut self, _item: &'ast syn::ItemFn) {}
    fn visit_impl_item_fn(&mut self, _item: &'ast syn::ImplItemFn) {}
    fn visit_trait_item_fn(&mut self, _item: &'ast syn::TraitItemFn) {}
}

pub(super) fn function_graph_violations<'a>(
    functions: impl IntoIterator<Item = &'a FunctionRecord>,
) -> Vec<String> {
    let functions = functions.into_iter().collect::<Vec<_>>();
    let mut violations = functions
        .iter()
        .filter(|function| function.ast_depth > MAX_FUNCTION_AST_DEPTH)
        .map(|function| {
            format!(
                "{} has expression AST depth {}; maximum is {}",
                qualified_name(function),
                function.ast_depth,
                MAX_FUNCTION_AST_DEPTH
            )
        })
        .collect::<Vec<_>>();
    let graph = resolved_call_graph(&functions);
    let mut cycles = BTreeSet::new();
    for start in graph.keys() {
        let mut pending = vec![vec![start.clone()]];
        while let Some(path) = pending.pop() {
            let Some(current) = path.last() else {
                continue;
            };
            for target in graph.get(current).into_iter().flatten() {
                if target == start {
                    let mut cycle = path.clone();
                    cycle.push(start.clone());
                    cycles.insert(cycle.join(" -> "));
                } else if path.len() <= graph.len() && !path.contains(target) {
                    let mut extended = path.clone();
                    extended.push(target.clone());
                    pending.push(extended);
                }
            }
        }
    }
    violations.extend(
        cycles
            .into_iter()
            .map(|cycle| format!("recursive call cycle: {cycle}")),
    );
    for start in graph.keys() {
        if let Some(overlong) = find_overlong_path(start, &graph) {
            violations.push(format!(
                "resolved call depth exceeds {MAX_RESOLVED_CALL_DEPTH}: {}",
                overlong.join(" -> ")
            ));
        }
    }
    violations.sort();
    violations.dedup();
    violations
}

fn resolved_call_graph(functions: &[&FunctionRecord]) -> BTreeMap<String, BTreeSet<String>> {
    let mut graph = functions
        .iter()
        .map(|function| (qualified_name(function), BTreeSet::new()))
        .collect::<BTreeMap<_, _>>();
    for function in functions {
        let source = qualified_name(function);
        for call in &function.calls {
            let candidates = functions
                .iter()
                .copied()
                .filter(|candidate| function.target_mask.overlaps(candidate.target_mask))
                .filter(|candidate| call_matches(function, call, candidate))
                .collect::<Vec<_>>();
            for candidate in candidates {
                graph
                    .entry(source.clone())
                    .or_default()
                    .insert(qualified_name(candidate));
            }
        }
    }
    graph
}

fn call_matches(source: &FunctionRecord, call: &CallReference, candidate: &FunctionRecord) -> bool {
    let Some(name) = call.name() else {
        return false;
    };
    if candidate.name != name {
        return false;
    }
    let expected_arguments = match call.receiver {
        CallReceiver::Method => candidate.explicit_argument_count,
        CallReceiver::FreeOrAssociated => candidate
            .explicit_argument_count
            .saturating_add(usize::from(candidate.has_receiver)),
    };
    if call.argument_count != expected_arguments {
        return false;
    }
    match call.path.as_slice() {
        [_] => candidate.scope == source.module && candidate.module == source.module,
        [owner, _] if owner == "Self" => candidate.scope == source.scope,
        [owner, _] if owner == "self" => {
            candidate.scope == source.module && candidate.module == source.module
        }
        [owner, _] if owner == "super" => candidate.module == parent_module(&source.module),
        [owner, rest @ ..] if owner == "crate" => {
            let module_path = rest.get(..rest.len().saturating_sub(1)).unwrap_or_default();
            let root = crate_root_module(&source.module);
            let expected = if module_path.is_empty() {
                root
            } else {
                format!("{root}::{}", module_path.join("::"))
            };
            candidate.module == expected
        }
        segments => {
            let owner_path = &segments[..segments.len().saturating_sub(1)];
            module_ends_with(&candidate.module, owner_path)
                || candidate.scope.split("::").last().is_some_and(|owner| {
                    owner_path.last().is_some_and(|expected| owner == expected)
                })
        }
    }
}

fn parent_module(module: &str) -> String {
    module
        .rsplit_once("::")
        .map_or_else(String::new, |(parent, _)| parent.to_string())
}

fn crate_root_module(module: &str) -> String {
    let components = module.split("::").collect::<Vec<_>>();
    let root_index = components
        .iter()
        .rposition(|component| matches!(*component, "src" | "tests" | "benches" | "examples"))
        .unwrap_or(components.len().saturating_sub(1));
    components[..=root_index].join("::")
}

fn module_ends_with(module: &str, expected: &[String]) -> bool {
    if expected.is_empty() {
        return true;
    }
    let actual = module.split("::").collect::<Vec<_>>();
    actual.len() >= expected.len()
        && actual[actual.len() - expected.len()..]
            .iter()
            .copied()
            .eq(expected.iter().map(String::as_str))
}

fn find_overlong_path(
    start: &str,
    graph: &BTreeMap<String, BTreeSet<String>>,
) -> Option<Vec<String>> {
    let mut pending = vec![vec![start.to_string()]];
    while let Some(path) = pending.pop() {
        if path.len() > MAX_RESOLVED_CALL_DEPTH {
            return Some(path);
        }
        let Some(current) = path.last() else {
            continue;
        };
        for target in graph.get(current).into_iter().flatten() {
            if !path.contains(target) {
                let mut extended = path.clone();
                extended.push(target.clone());
                pending.push(extended);
            }
        }
    }
    None
}

pub(super) fn expression_ast_depth(block: &syn::Block) -> usize {
    struct Depth {
        current: usize,
        maximum: usize,
    }

    impl<'ast> Visit<'ast> for Depth {
        fn visit_expr(&mut self, expression: &'ast syn::Expr) {
            self.current = self.current.saturating_add(1);
            self.maximum = self.maximum.max(self.current);
            syn::visit::visit_expr(self, expression);
            self.current -= 1;
        }

        fn visit_item_fn(&mut self, _function: &'ast syn::ItemFn) {}
        fn visit_impl_item_fn(&mut self, _function: &'ast syn::ImplItemFn) {}
        fn visit_trait_item_fn(&mut self, _function: &'ast syn::TraitItemFn) {}
    }

    let mut depth = Depth {
        current: 0,
        maximum: 0,
    };
    depth.visit_block(block);
    depth.maximum
}
