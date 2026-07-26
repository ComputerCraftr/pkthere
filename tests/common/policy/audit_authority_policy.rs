use super::{PolicyFinding, PolicyKind, line};
use quote::ToTokens;
use std::collections::BTreeSet;
use syn::spanned::Spanned;
use syn::visit::Visit;

const REGISTERED_INTERIOR_MUTABILITY: &[InteriorMutabilityRegistration] = &[
    InteriorMutabilityRegistration {
        path: "src/allocation_test_support.rs",
        kind: "Cell",
        symbols: &[
            "TRACKING",
            "ALLOCATIONS",
            "TRACKING_PAYLOAD_COPIES",
            "PAYLOAD_COPIES",
            "TRACKING_ENDPOINT_NORMALIZATIONS",
            "ENDPOINT_NORMALIZATIONS",
            "TRACKING_LOCK_CANDIDATES",
            "LOCK_CANDIDATES",
        ],
        ownership: "test-thread-local allocation and copy counters",
        loom_disposition: "single-thread observer; never protocol authority",
    },
    InteriorMutabilityRegistration {
        path: "src/authority/audit_enabled.rs",
        kind: "Cell",
        symbols: &[
            "HELD",
            "OPERATIONS",
            "FAILED",
            "ACQUISITIONS",
            "SHARED_RMWS",
            "PROTOCOL_RMWS",
            "WAITS",
            "OPERATION_COUNTS",
            "ALLOCATION_VIOLATIONS",
            "ALLOCATION_VIOLATIONS_BY_AUTHORITY",
            "WORKER_IDENTITY",
            "PIPELINE_STAGES",
            "WORKER_ALLOCATIONS",
            "WORKER_PAYLOAD_COPIES",
            "WORKER_ENDPOINT_NORMALIZATIONS",
            "FORBIDDEN_AUTHORITY_ACQUISITIONS",
            "FORBIDDEN_REFCOUNT_RMWS",
            "FORBIDDEN_SHARED_RMWS",
            "VIOLATION_CODE",
        ],
        ownership: "thread-local fixed-capacity authority audit stacks and counters",
        loom_disposition: "observes Loom-tested authorities; never cross-thread authority",
    },
    InteriorMutabilityRegistration {
        path: "src/runtime_support.rs",
        kind: "Cell",
        symbols: &["CURRENT_THREAD_SLOT"],
        ownership: "thread-local supervised role identifier",
        loom_disposition: "immutable across one thread execution; no cross-thread publication",
    },
    InteriorMutabilityRegistration {
        path: "src/worker_support/pipeline_audit.rs",
        kind: "Cell",
        symbols: &["TEST_PIPELINE_TOKEN"],
        ownership: "test-thread-local deterministic barrier token",
        loom_disposition: "test observer only; cannot construct or replace production authority",
    },
];

const REGISTERED_TEST_MUTATORS: &[TestMutatorRegistration] = &[
    TestMutatorRegistration {
        path: "src/authority/thread_owned.rs",
        symbol: "fetch_add",
        ownership: "authority-audit shared-RMW counter hook",
        loom_disposition: "observes governed atomics and is not protocol state",
    },
    TestMutatorRegistration {
        path: "src/worker_support/pipeline_audit.rs",
        symbol: "pause_for_test_barrier",
        ownership: "deterministic production-pipeline scheduling observer",
        loom_disposition: "test barrier only; cannot construct a production permit",
    },
];

struct InteriorMutabilityRegistration {
    path: &'static str,
    kind: &'static str,
    symbols: &'static [&'static str],
    ownership: &'static str,
    loom_disposition: &'static str,
}

struct TestMutatorRegistration {
    path: &'static str,
    symbol: &'static str,
    ownership: &'static str,
    loom_disposition: &'static str,
}

fn registered_test_mutator(path: &str, symbol: &str) -> bool {
    REGISTERED_TEST_MUTATORS.iter().any(|registration| {
        registration.path == path
            && registration.symbol == symbol
            && !registration.ownership.is_empty()
            && !registration.loom_disposition.is_empty()
    })
}

fn registered_interior_mutability(path: &str, kind: &str, symbol: &str) -> bool {
    REGISTERED_INTERIOR_MUTABILITY.iter().any(|registration| {
        registration.path == path
            && registration.kind == kind
            && registration.symbols.contains(&symbol)
            && !registration.ownership.is_empty()
            && !registration.loom_disposition.is_empty()
    })
}

fn interior_mutability_name(name: &str) -> bool {
    matches!(name, "Cell" | "RefCell" | "UnsafeCell")
}

fn is_test_support_path(path: &str) -> bool {
    path.split('/').any(|component| {
        component == "tests" || component == "test_support.rs" || component.ends_with("_tests")
    }) || path == "src/allocation_test_support.rs"
        || path.ends_with("/tests.rs")
        || path.ends_with("_tests.rs")
        || path.starts_with("tests/")
}

pub(super) fn analyze_test_only_mutator(
    path: &str,
    cfg_domain: String,
    attrs: &[syn::Attribute],
    signature: &syn::Signature,
    block: &syn::Block,
) -> Option<PolicyFinding> {
    let mut mutation = TestMutationSurface::new(signature);
    mutation.visit_block(block);
    if is_test_support_path(path)
        || registered_test_mutator(path, &signature.ident.to_string())
        || attrs.iter().any(|attr| attr.path().is_ident("test"))
        || !attrs.iter().any(super::policy_syntax::attr_is_test_context)
        || !mutation.found
    {
        return None;
    }
    Some(PolicyFinding {
        kind: PolicyKind::TestStateAuthority,
        path: path.to_string(),
        line: line(signature.span()),
        item: signature.ident.to_string(),
        cfg_domain,
        detail: "test-only state mutation belongs in a test-support module and must enter through production lifecycle APIs"
            .to_string(),
    })
}

struct TestMutationSurface {
    found: bool,
    mutable_inputs: BTreeSet<String>,
    authority_bindings: BTreeSet<String>,
}

impl TestMutationSurface {
    fn new(signature: &syn::Signature) -> Self {
        let mut mutable_inputs = BTreeSet::new();
        for input in &signature.inputs {
            match input {
                syn::FnArg::Receiver(receiver)
                    if receiver.mutability.is_some()
                        || matches!(receiver.kind, syn::ReceiverKind::Reference(_, _, Some(_))) =>
                {
                    mutable_inputs.insert("self".to_string());
                }
                syn::FnArg::Typed(argument) if type_is_mutable_reference(&argument.ty) => {
                    collect_pattern_identifiers(&argument.pat, &mut mutable_inputs);
                }
                _ => {}
            }
        }
        let found = !mutable_inputs.is_empty();
        Self {
            found,
            mutable_inputs,
            authority_bindings: BTreeSet::new(),
        }
    }

    fn externally_mutable_root(&self, expression: &syn::Expr) -> bool {
        expression_root_identifier(expression).is_some_and(|root| {
            self.mutable_inputs.contains(&root) || self.authority_bindings.contains(&root)
        })
    }

    fn protocol_mutation_receiver(&self, expression: &syn::Expr) -> bool {
        self.externally_mutable_root(expression)
            || expression_root_identifier(expression).as_deref() == Some("self")
    }
}

impl<'ast> Visit<'ast> for TestMutationSurface {
    fn visit_local(&mut self, local: &'ast syn::Local) {
        if local_acquires_authority(local) {
            collect_pattern_identifiers(&local.pat, &mut self.authority_bindings);
        }
        syn::visit::visit_local(self, local);
    }

    fn visit_expr_assign(&mut self, assignment: &'ast syn::ExprAssign) {
        self.found |= self.externally_mutable_root(&assignment.left);
        syn::visit::visit_expr_assign(self, assignment);
    }

    fn visit_expr_binary(&mut self, binary: &'ast syn::ExprBinary) {
        if matches!(
            binary.op,
            syn::BinOp::AddAssign(_)
                | syn::BinOp::SubAssign(_)
                | syn::BinOp::MulAssign(_)
                | syn::BinOp::DivAssign(_)
                | syn::BinOp::RemAssign(_)
                | syn::BinOp::BitXorAssign(_)
                | syn::BinOp::BitAndAssign(_)
                | syn::BinOp::BitOrAssign(_)
                | syn::BinOp::ShlAssign(_)
                | syn::BinOp::ShrAssign(_)
        ) {
            self.found |= self.externally_mutable_root(&binary.left);
        }
        syn::visit::visit_expr_binary(self, binary);
    }

    fn visit_expr_reference(&mut self, reference: &'ast syn::ExprReference) {
        self.found |=
            reference.mutability.is_some() && self.externally_mutable_root(&reference.expr);
        syn::visit::visit_expr_reference(self, reference);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        let name = call.method.to_string();
        let root = expression_root_identifier(&call.receiver);
        self.found |= root
            .as_ref()
            .is_some_and(|root| self.mutable_inputs.contains(root))
            || (is_known_interior_mutation(&name)
                && self.protocol_mutation_receiver(&call.receiver));
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        self.found |= call.args.iter().any(|argument| {
            self.externally_mutable_root(argument)
                || matches!(argument, syn::Expr::Reference(reference)
                    if reference.mutability.is_some()
                        && self.externally_mutable_root(&reference.expr))
        });
        syn::visit::visit_expr_call(self, call);
    }
}

fn local_acquires_authority(local: &syn::Local) -> bool {
    let Some(initializer) = &local.init else {
        return false;
    };
    initializer_acquires_authority(&initializer.expr)
}

fn type_is_mutable_reference(ty: &syn::Type) -> bool {
    let mut current = ty;
    loop {
        match current {
            syn::Type::Reference(reference) => return reference.mutability.is_some(),
            syn::Type::Group(group) => current = &group.elem,
            syn::Type::Paren(paren) => current = &paren.elem,
            _ => return false,
        }
    }
}

fn collect_pattern_identifiers(pattern: &syn::Pat, identifiers: &mut BTreeSet<String>) {
    struct Collector<'a>(&'a mut BTreeSet<String>);

    impl<'ast> Visit<'ast> for Collector<'_> {
        fn visit_pat_ident(&mut self, pattern: &'ast syn::PatIdent) {
            self.0.insert(pattern.ident.to_string());
            syn::visit::visit_pat_ident(self, pattern);
        }
    }

    Collector(identifiers).visit_pat(pattern);
}

fn initializer_acquires_authority(expression: &syn::Expr) -> bool {
    struct Acquisition(bool);

    impl<'ast> Visit<'ast> for Acquisition {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if let syn::Expr::Path(path) = call.func.as_ref() {
                self.0 |= path.path.segments.last().is_some_and(|segment| {
                    matches!(
                        segment.ident.to_string().as_str(),
                        "lock_authority" | "lock_authority_or_shutdown"
                    )
                });
            }
            syn::visit::visit_expr_call(self, call);
        }

        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            self.0 |= matches!(call.method.to_string().as_str(), "lock" | "try_lock");
            syn::visit::visit_expr_method_call(self, call);
        }
    }

    let mut acquisition = Acquisition(false);
    acquisition.visit_expr(expression);
    acquisition.0
}

fn expression_root_identifier(expression: &syn::Expr) -> Option<String> {
    let mut current = expression;
    loop {
        match current {
            syn::Expr::Path(path) => {
                return path
                    .path
                    .segments
                    .first()
                    .map(|segment| segment.ident.to_string());
            }
            syn::Expr::Field(field) => current = &field.base,
            syn::Expr::Index(index) => current = &index.expr,
            syn::Expr::Paren(paren) => current = &paren.expr,
            syn::Expr::Group(group) => current = &group.expr,
            syn::Expr::Reference(reference) => current = &reference.expr,
            syn::Expr::Unary(unary) => current = &unary.expr,
            _ => return None,
        }
    }
}

fn is_known_interior_mutation(name: &str) -> bool {
    matches!(
        name,
        "store"
            | "swap"
            | "compare_exchange"
            | "compare_exchange_weak"
            | "set"
            | "replace"
            | "take"
    ) || name.starts_with("fetch_")
}

fn interior_mutability_finding(
    path: &str,
    cfg_domain: String,
    span: proc_macro2::Span,
    item: String,
) -> PolicyFinding {
    PolicyFinding {
        kind: PolicyKind::InteriorMutabilityAuthority,
        path: path.to_string(),
        line: line(span),
        item,
        cfg_domain,
        detail: "Cell/RefCell/UnsafeCell authority must be removed or registered in the reviewed inventory"
            .to_string(),
    }
}

pub(super) fn analyze_interior_mutability_path(
    path: &str,
    cfg_domain: String,
    candidate: &syn::Path,
) -> Option<PolicyFinding> {
    let segment = candidate
        .segments
        .iter()
        .find(|segment| interior_mutability_name(&segment.ident.to_string()))?;
    Some(interior_mutability_finding(
        path,
        cfg_domain,
        segment.ident.span(),
        segment.ident.to_string(),
    ))
}

fn token_stream_interior_mutability(tokens: proc_macro2::TokenStream) -> Vec<syn::Ident> {
    let mut found = Vec::new();
    let mut pending = vec![tokens];
    while let Some(tokens) = pending.pop() {
        for token in tokens {
            match token {
                proc_macro2::TokenTree::Ident(ident)
                    if interior_mutability_name(&ident.to_string()) =>
                {
                    found.push(ident)
                }
                proc_macro2::TokenTree::Group(group) => pending.push(group.stream()),
                proc_macro2::TokenTree::Ident(_)
                | proc_macro2::TokenTree::Punct(_)
                | proc_macro2::TokenTree::Literal(_) => {}
            }
        }
    }
    found
}

pub(super) fn analyze_interior_mutability_macro(
    path: &str,
    cfg_domain: String,
    item: &syn::Macro,
) -> Option<PolicyFinding> {
    let identifiers = token_stream_interior_mutability(item.tokens.clone());
    let first = identifiers.first()?.clone();
    let is_thread_local = item
        .path
        .segments
        .last()
        .is_some_and(|segment| segment.ident == "thread_local");
    if !is_thread_local {
        return Some(interior_mutability_finding(
            path,
            cfg_domain,
            first.span(),
            format!("{}! interior-mutability token", item.path.to_token_stream()),
        ));
    }
    let parsed = match syn::parse2::<syn::File>(item.tokens.clone()) {
        Ok(parsed) => parsed,
        Err(_) => {
            return Some(interior_mutability_finding(
                path,
                cfg_domain,
                first.span(),
                "unparseable thread_local! authority".to_string(),
            ));
        }
    };
    for parsed_item in parsed.items {
        let syn::Item::Static(item_static) = parsed_item else {
            return Some(interior_mutability_finding(
                path,
                cfg_domain,
                first.span(),
                "thread_local! non-static item".to_string(),
            ));
        };
        for ident in token_stream_interior_mutability(item_static.ty.to_token_stream()) {
            if !registered_interior_mutability(
                path,
                &ident.to_string(),
                &item_static.ident.to_string(),
            ) {
                return Some(interior_mutability_finding(
                    path,
                    cfg_domain,
                    ident.span(),
                    format!("thread_local! static {}", item_static.ident),
                ));
            }
        }
    }
    None
}

pub(super) fn analyze_unsafe_thread_impl(
    path: &str,
    cfg_domain: String,
    item: &syn::ItemImpl,
) -> Option<PolicyFinding> {
    item.unsafety?;
    let (trait_path, _) = item.trait_.as_ref()?;
    let trait_name = trait_path.segments.last()?.ident.to_string();
    if !matches!(trait_name.as_str(), "Send" | "Sync") {
        return None;
    }
    Some(PolicyFinding {
        kind: PolicyKind::InteriorMutabilityAuthority,
        path: path.to_string(),
        line: line(item.span()),
        item: format!("unsafe impl {trait_name}"),
        cfg_domain,
        detail: "unsafe thread-safety assertions require an explicit reviewed authority wrapper"
            .to_string(),
    })
}

pub(super) fn analyze_struct(
    path: &str,
    cfg_domain: String,
    item: &syn::ItemStruct,
) -> Vec<PolicyFinding> {
    let mut authority_findings = Vec::new();
    for field in &item.fields {
        let mut surface = MutableAuthoritySurface::default();
        surface.visit_type(&field.ty);
        if item.ident.to_string().contains("Reservation") && surface.ref_cell {
            authority_findings.push(PolicyFinding {
                kind: PolicyKind::InteriorMutabilityAuthority,
                path: path.to_string(),
                line: line(field.span()),
                item: item.ident.to_string(),
                cfg_domain: cfg_domain.clone(),
                detail: "reservation ownership must use consuming typestate, not RefCell"
                    .to_string(),
            });
        }
        if field
            .attrs
            .iter()
            .any(super::policy_syntax::attr_is_test_context)
            && !field
                .attrs
                .iter()
                .any(|attr| super::policy_syntax::cfg_attr_has_string(attr, "authority-audit"))
            && surface.mutable_authority
        {
            authority_findings.push(PolicyFinding {
                kind: PolicyKind::TestStateAuthority,
                path: path.to_string(),
                line: line(field.span()),
                item: item.ident.to_string(),
                cfg_domain: cfg_domain.clone(),
                detail: "cfg(test) mutable fields may not duplicate production authority"
                    .to_string(),
            });
        }
    }
    if path != "src/stats.rs" || item.ident != "Snapshot" {
        return authority_findings;
    }
    authority_findings.extend(
        item.fields
            .iter()
            .filter(|field| {
                crate::common::rust_semantics::type_identifiers(&field.ty)
                    .iter()
                    .any(|identifier| identifier.starts_with("Atomic"))
            })
            .map(|field| PolicyFinding {
                kind: PolicyKind::CoherentStatsAuthority,
                path: path.to_string(),
                line: line(field.span()),
                item: item.ident.to_string(),
                cfg_domain: cfg_domain.clone(),
                detail: "stats snapshots require mutex-protected plain fields".to_string(),
            }),
    );
    authority_findings
}

#[derive(Default)]
struct MutableAuthoritySurface {
    mutable_authority: bool,
    ref_cell: bool,
}

impl<'ast> Visit<'ast> for MutableAuthoritySurface {
    fn visit_path(&mut self, path: &'ast syn::Path) {
        for segment in &path.segments {
            let name = segment.ident.to_string();
            if name == "RefCell" {
                self.ref_cell = true;
            }
            if interior_mutability_name(&name)
                || name.starts_with("Atomic")
                || name.ends_with("Mutex")
            {
                self.mutable_authority = true;
            }
        }
        syn::visit::visit_path(self, path);
    }
}

pub(super) fn analyze_method_call(
    path: &str,
    cfg_domain: String,
    call: &syn::ExprMethodCall,
) -> Option<PolicyFinding> {
    if path == "src/stats.rs"
        && matches!(
            call.method.to_string().as_str(),
            "compare_exchange" | "compare_exchange_weak"
        )
    {
        return Some(PolicyFinding {
            kind: PolicyKind::CoherentStatsAuthority,
            path: path.to_string(),
            line: line(call.span()),
            item: call.method.to_string(),
            cfg_domain,
            detail: "stats must not reintroduce a custom spin/seqlock".to_string(),
        });
    }
    let required_evidence_path = path == "tests/lifecycle_integration.rs"
        || path == "tests/support/src/packet_diagnostics.rs"
        || path == "tests/support/src/bin/topology_verifier.rs"
        || path.starts_with("tests/support/src/socket_reality/");
    if required_evidence_path
        && matches!(
            call.method.to_string().as_str(),
            "unwrap_or" | "unwrap_or_default"
        )
    {
        return Some(PolicyFinding {
            kind: PolicyKind::RequiredEvidenceDefault,
            path: path.to_string(),
            line: line(call.span()),
            item: call.method.to_string(),
            cfg_domain,
            detail: "required verifier evidence must be asserted, not fabricated".to_string(),
        });
    }
    None
}

pub(super) fn analyze_function_signature(
    path: &str,
    cfg_domain: String,
    signature: &syn::Signature,
) -> Option<PolicyFinding> {
    if path == "src/flow_state/topology.rs" {
        return None;
    }
    let syn::ReturnType::Type(_, return_type) = &signature.output else {
        return None;
    };
    let mut visitor = DetachedTopologyReturn::default();
    visitor.visit_type(return_type);
    let returns_detached_topology = visitor.detached;
    returns_detached_topology.then(|| PolicyFinding {
        kind: PolicyKind::InteriorMutabilityAuthority,
        path: path.to_string(),
        line: line(signature.output.span()),
        item: signature.ident.to_string(),
        cfg_domain,
        detail: "client-flow topology ownership must remain borrowed through ClientFlowTopologyReservation"
            .to_string(),
    })
}

#[derive(Default)]
struct DetachedTopologyReturn {
    reference_depth: usize,
    detached: bool,
}

impl<'ast> Visit<'ast> for DetachedTopologyReturn {
    fn visit_type_reference(&mut self, reference: &'ast syn::TypeReference) {
        self.reference_depth += 1;
        syn::visit::visit_type_reference(self, reference);
        self.reference_depth -= 1;
    }

    fn visit_path(&mut self, path: &'ast syn::Path) {
        if self.reference_depth == 0
            && path
                .segments
                .last()
                .is_some_and(|segment| segment.ident == "FlowTopologyWriteReservation")
        {
            self.detached = true;
        }
        syn::visit::visit_path(self, path);
    }
}
