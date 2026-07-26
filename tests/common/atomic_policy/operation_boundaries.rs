use super::{attrs_are_test_context, production_rust_sources};
use pkthere_test_support::test_paths as path_policy;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use syn::visit::Visit;

const REVIEWED_BOUNDARY_MODULES: &[&str] = &["src/authority.rs"];
const OPERATION_NAMES: &[&str] = &[
    "SocketCreate",
    "SocketBind",
    "SocketConnect",
    "SocketDisconnect",
    "SocketPeerInspection",
    "SocketLocalInspection",
    "SocketConfigure",
    "SocketCaptureEnable",
    "Poll",
    "SocketSend",
    "SocketReceive",
    "WakeSocketSend",
    "WakeSocketReceive",
    "TopologyDrain",
    "ThreadSleep",
    "CondvarWait",
    "SupervisorHintSend",
    "ChannelSend",
    "ChannelReceive",
    "Allocator",
    "Formatting",
    "Logging",
    "JsonSerialization",
    "FatalPublication",
    "RefcountFinalize",
    "SocketDescriptorClose",
    "ThreadJoin",
    "StatsFlush",
    "FixedQueue",
    "ProcessImmediateExit",
    "PipelineBarrier",
    "RefcountClone",
    "RefcountUpgrade",
];

struct BoundaryAudit<'a> {
    source: &'a str,
    violations: Vec<String>,
}

impl BoundaryAudit<'_> {
    fn inspect(
        &mut self,
        signature: &syn::Signature,
        block: &syn::Block,
        attrs: &[syn::Attribute],
    ) {
        if attrs_are_test_context(attrs) {
            return;
        }
        let mut operations = RawOperationCollector {
            function_name: signature.ident.to_string(),
            ..RawOperationCollector::default()
        };
        operations.visit_block(block);
        for operation in operations.operations {
            let supervisor_hint_declared = operation == "ChannelSend"
                && block_references_operation(block, "SupervisorHintSend");
            if !block_references_operation(block, operation) && !supervisor_hint_declared {
                self.violations.push(format!(
                    "{}::{} performs {operation} without its audited operation scope",
                    self.source, signature.ident
                ));
            }
        }
    }
}

impl<'ast> Visit<'ast> for BoundaryAudit<'_> {
    visit_non_test_containers!();

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        self.inspect(&item.sig, &item.block, &item.attrs);
        if !attrs_are_test_context(&item.attrs) {
            syn::visit::visit_item_fn(self, item);
        }
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        self.inspect(&item.sig, &item.block, &item.attrs);
        if !attrs_are_test_context(&item.attrs) {
            syn::visit::visit_impl_item_fn(self, item);
        }
    }

    fn visit_trait_item_fn(&mut self, item: &'ast syn::TraitItemFn) {
        if let Some(block) = &item.default {
            self.inspect(&item.sig, block, &item.attrs);
        }
        if !attrs_are_test_context(&item.attrs) {
            syn::visit::visit_trait_item_fn(self, item);
        }
    }
}

#[derive(Clone)]
struct ScopeBinding {
    name: String,
    operation: String,
    active: bool,
}

struct ScopedBoundaryAudit<'a> {
    source: &'a str,
    function: String,
    active: BTreeMap<String, usize>,
    bindings: Vec<ScopeBinding>,
    violations: Vec<String>,
}

impl ScopedBoundaryAudit<'_> {
    fn enter_binding(&mut self, name: String, operation: String) {
        *self.active.entry(operation.clone()).or_default() += 1;
        self.bindings.push(ScopeBinding {
            name,
            operation,
            active: true,
        });
    }

    fn leave_binding(&mut self, index: usize) {
        let Some(binding) = self.bindings.get_mut(index) else {
            return;
        };
        if !binding.active {
            return;
        }
        binding.active = false;
        let operation = binding.operation.clone();
        if let Some(count) = self.active.get_mut(&operation) {
            *count -= 1;
            if *count == 0 {
                self.active.remove(&operation);
            }
        }
    }

    fn leave_named_binding(&mut self, name: &str) {
        if let Some(index) = self
            .bindings
            .iter()
            .rposition(|binding| binding.active && binding.name == name)
        {
            self.leave_binding(index);
        }
    }

    fn require(&mut self, operation: &'static str) {
        let supervisor_hint_declared =
            operation == "ChannelSend" && self.active.contains_key("SupervisorHintSend");
        if !self.active.contains_key(operation) && !supervisor_hint_declared {
            self.violations.push(format!(
                "{}::{} performs {operation} outside its lexical audited operation scope",
                self.source, self.function
            ));
        }
    }

    fn inspect_call(&mut self, call: &syn::ExprCall) {
        let Some(operation) = raw_call_operation(&self.function, call) else {
            return;
        };
        self.require(operation);
    }

    fn inspect_method_call(&mut self, call: &syn::ExprMethodCall) {
        let Some(operation) = raw_method_operation(&self.function, call) else {
            return;
        };
        self.require(operation);
    }

    fn inspect_macro(&mut self, expression: &syn::ExprMacro) {
        let path = expression
            .mac
            .path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect::<Vec<_>>();
        if path.len() > 1 && path.last().is_some_and(|name| name == "format") {
            self.require("Formatting");
        }
        if path.last().is_some_and(|name| name == "json") {
            self.require("JsonSerialization");
        }
    }

    fn visit_function(&mut self, name: String, block: &'_ syn::Block) {
        let previous_function = std::mem::replace(&mut self.function, name);
        self.visit_block(block);
        self.function = previous_function;
    }

    fn visit_function_if_production(
        &mut self,
        attrs: &[syn::Attribute],
        name: String,
        block: &'_ syn::Block,
    ) {
        if !attrs_are_test_context(attrs) {
            self.visit_function(name, block);
        }
    }
}

impl<'ast> Visit<'ast> for ScopedBoundaryAudit<'_> {
    visit_non_test_containers!();

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        self.visit_function_if_production(&item.attrs, item.sig.ident.to_string(), &item.block);
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        if attrs_are_test_context(&item.attrs) {
            return;
        }
        self.visit_function(item.sig.ident.to_string(), &item.block);
    }

    fn visit_trait_item_fn(&mut self, item: &'ast syn::TraitItemFn) {
        if attrs_are_test_context(&item.attrs) {
            return;
        }
        let Some(block) = &item.default else {
            return;
        };
        self.visit_function(item.sig.ident.to_string(), block);
    }

    fn visit_block(&mut self, block: &'ast syn::Block) {
        let binding_start = self.bindings.len();
        for statement in &block.stmts {
            if let syn::Stmt::Local(local) = statement {
                if let Some(initializer) = &local.init {
                    self.visit_expr(&initializer.expr);
                    if let Some((name, operation)) = audited_scope_binding(local) {
                        self.enter_binding(name, operation);
                    }
                }
                continue;
            }
            syn::visit::visit_stmt(self, statement);
            if let Some(name) = explicitly_dropped_binding(statement) {
                self.leave_named_binding(&name);
            }
        }
        for index in (binding_start..self.bindings.len()).rev() {
            self.leave_binding(index);
        }
        self.bindings.truncate(binding_start);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        self.inspect_call(call);
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.inspect_method_call(call);
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_macro(&mut self, expression: &'ast syn::ExprMacro) {
        self.inspect_macro(expression);
        syn::visit::visit_expr_macro(self, expression);
    }
}

fn audited_scope_binding(local: &syn::Local) -> Option<(String, String)> {
    let syn::Pat::Ident(binding) = &local.pat else {
        return None;
    };
    let initializer = local.init.as_ref()?;
    let call = audited_scope_constructor(&initializer.expr)?;
    let operation = call.args.iter().find_map(operation_from_expression)?;
    Some((binding.ident.to_string(), (*operation).to_string()))
}

fn audited_scope_constructor(mut expression: &syn::Expr) -> Option<&syn::ExprCall> {
    loop {
        match expression {
            syn::Expr::Call(call) => {
                let syn::Expr::Path(function) = call.func.as_ref() else {
                    return None;
                };
                let segments = function
                    .path
                    .segments
                    .iter()
                    .map(|segment| segment.ident.to_string())
                    .collect::<Vec<_>>();
                return (segments
                    .ends_with(&["AuditedOperationScope".to_string(), "enter".to_string()])
                    || matches!(
                        segments.last().map(String::as_str),
                        Some("audited_operation" | "socket_operation_scope")
                    ))
                .then_some(call);
            }
            syn::Expr::Try(wrapped) => expression = &wrapped.expr,
            syn::Expr::MethodCall(method) => expression = &method.receiver,
            syn::Expr::Paren(wrapped) => expression = &wrapped.expr,
            syn::Expr::Group(wrapped) => expression = &wrapped.expr,
            syn::Expr::Reference(wrapped) => expression = &wrapped.expr,
            _ => return None,
        }
    }
}

fn block_references_operation(block: &syn::Block, expected: &str) -> bool {
    struct Visitor<'a> {
        expected: &'a str,
        found: bool,
    }
    impl Visit<'_> for Visitor<'_> {
        fn visit_path(&mut self, path: &syn::Path) {
            let segments = path.segments.iter().collect::<Vec<_>>();
            self.found |= segments.len() >= 2
                && segments[segments.len() - 2].ident == "OperationId"
                && segments[segments.len() - 1].ident == self.expected;
            if !self.found {
                syn::visit::visit_path(self, path);
            }
        }
    }
    let mut visitor = Visitor {
        expected,
        found: false,
    };
    visitor.visit_block(block);
    visitor.found
}

fn operation_from_expression(expression: &syn::Expr) -> Option<&&'static str> {
    let syn::Expr::Path(path) = expression else {
        return None;
    };
    let segments = path.path.segments.iter().collect::<Vec<_>>();
    if segments.len() < 2 || segments[segments.len() - 2].ident != "OperationId" {
        return None;
    }
    OPERATION_NAMES.iter().find(|operation| {
        segments
            .last()
            .is_some_and(|segment| segment.ident == **operation)
    })
}

fn explicitly_dropped_binding(statement: &syn::Stmt) -> Option<String> {
    let syn::Stmt::Expr(syn::Expr::Call(call), _) = statement else {
        return None;
    };
    let syn::Expr::Path(function) = call.func.as_ref() else {
        return None;
    };
    if !function.path.is_ident("drop") || call.args.len() != 1 {
        return None;
    }
    let syn::Expr::Path(argument) = call.args.first()? else {
        return None;
    };
    argument.path.get_ident().map(ToString::to_string)
}

fn raw_call_operation(function_name: &str, call: &syn::ExprCall) -> Option<&'static str> {
    let syn::Expr::Path(path) = call.func.as_ref() else {
        return None;
    };
    let segments = path
        .path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>();
    match segments.as_slice() {
        [prefix @ .., function]
            if matches!(function.as_str(), "poll" | "WSAPoll")
                && (function == "WSAPoll" || prefix.iter().any(|segment| segment == "libc")) =>
        {
            Some("Poll")
        }
        [prefix @ .., function]
            if function == "connect" && prefix.iter().any(|segment| segment == "libc") =>
        {
            Some(if function_name == "disconnect" {
                "SocketDisconnect"
            } else {
                "SocketConnect"
            })
        }
        [prefix @ .., function]
            if function == "sleep" && prefix.iter().any(|segment| segment == "thread") =>
        {
            Some("ThreadSleep")
        }
        [_, function] if function == "WSAIoctl" => Some("SocketCaptureEnable"),
        [prefix @ .., function]
            if function == "_exit" && prefix.iter().any(|segment| segment == "libc") =>
        {
            Some("ProcessImmediateExit")
        }
        [prefix @ .., function]
            if function == "ExitProcess" && prefix.iter().any(|segment| segment == "Threading") =>
        {
            Some("ProcessImmediateExit")
        }
        [prefix @ .., function]
            if function == "new" && prefix.last().is_some_and(|segment| segment == "Socket") =>
        {
            Some("SocketCreate")
        }
        [prefix @ .., function]
            if function == "bind"
                && prefix.last().is_some_and(|segment| segment == "UdpSocket") =>
        {
            Some("SocketBind")
        }
        _ => None,
    }
}

fn raw_method_operation(function_name: &str, call: &syn::ExprMethodCall) -> Option<&'static str> {
    let receiver_expression = call.receiver.as_ref();
    let receiver = crate::common::rust_semantics::expression_identifiers(receiver_expression);
    let backend_dispatch = receiver.contains("backend");
    let socket_receiver = receiver.iter().any(|fragment| {
        matches!(
            fragment.as_str(),
            "socket" | "sock" | "descriptor" | "udp_socket" | "packet_socket" | "wake_socket"
        )
    }) && !backend_dispatch;
    let wake_sender = function_name == "notify" && receiver.contains("sender");
    let wake_receiver = function_name == "receive_wake" && receiver.contains("receiver");
    let socket_configuration_receiver = socket_receiver
        || receiver
            .iter()
            .any(|fragment| matches!(fragment.as_str(), "sender" | "receiver"));
    match call.method.to_string().as_str() {
        "bind" if socket_receiver => Some("SocketBind"),
        "connect" if socket_receiver && function_name == "disconnect" => Some("SocketDisconnect"),
        "connect" if socket_receiver => Some("SocketConnect"),
        "local_addr" if socket_receiver => Some("SocketLocalInspection"),
        "peer_addr" if socket_receiver => Some("SocketPeerInspection"),
        method if method.starts_with("set_") && socket_configuration_receiver => {
            Some("SocketConfigure")
        }
        "send" if wake_sender => Some("WakeSocketSend"),
        "recv" if wake_receiver => Some("WakeSocketReceive"),
        "send" | "send_to" | "send_vectored" if socket_receiver => Some("SocketSend"),
        "recv" | "recv_from" | "recv_vectored" if socket_receiver => Some("SocketReceive"),
        "flush" => Some("StatsFlush"),
        "join" => Some("ThreadJoin"),
        "upgrade" => Some("RefcountUpgrade"),
        _ => None,
    }
}

#[derive(Default)]
struct RawOperationCollector {
    function_name: String,
    operations: BTreeSet<&'static str>,
}

impl Visit<'_> for RawOperationCollector {
    fn visit_expr_call(&mut self, call: &syn::ExprCall) {
        if let Some(operation) = raw_call_operation(&self.function_name, call) {
            self.operations.insert(operation);
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &syn::ExprMethodCall) {
        if let Some(operation) = raw_method_operation(&self.function_name, call) {
            self.operations.insert(operation);
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_macro(&mut self, expression: &syn::ExprMacro) {
        let path = expression
            .mac
            .path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect::<Vec<_>>();
        if path.len() > 1 && path.last().is_some_and(|name| name == "format") {
            self.operations.insert("Formatting");
        }
        if path.last().is_some_and(|name| name == "json") {
            self.operations.insert("JsonSerialization");
        }
        syn::visit::visit_expr_macro(self, expression);
    }
}

pub(super) fn assert_no_unaudited_operation_boundaries(root: &Path) {
    let violations = audit_production_boundaries(root);
    assert_dropped_scope_is_rejected();
    assert_error_wrapped_scope_is_recognized();
    assert!(
        violations.is_empty(),
        "production operations bypass audited boundaries:\n{}",
        violations.join("\n")
    );
}

fn assert_error_wrapped_scope_is_recognized() {
    let fixture = syn::parse_file(
        r#"
        fn wrapped_scope(descriptor: &Weak<Socket>) -> Result<(), Error> {
            let operation = AuditedOperationScope::enter(OperationId::RefcountUpgrade)
                .map_err(Error::from)?;
            let descriptor = descriptor.upgrade();
            drop(operation);
            drop(descriptor);
            Ok(())
        }
        "#,
    )
    .expect("parse error-wrapped operation-scope fixture");
    let mut audit = ScopedBoundaryAudit {
        source: "wrapped_scope_fixture.rs",
        function: String::new(),
        active: BTreeMap::new(),
        bindings: Vec::new(),
        violations: Vec::new(),
    };
    audit.visit_file(&fixture);
    assert!(
        audit.violations.is_empty(),
        "recursive operation-scope analysis rejected map_err/try wrapping: {:?}",
        audit.violations
    );
}

fn audit_production_boundaries(root: &Path) -> Vec<String> {
    let mut violations = Vec::new();
    for source in production_rust_sources(root) {
        let relative = path_policy::render_repo_relative_path(root, &source);
        if REVIEWED_BOUNDARY_MODULES.contains(&relative.as_str()) {
            continue;
        }
        let syntax = crate::common::rust_semantics::parse_file(&source);
        let mut audit = BoundaryAudit {
            source: &relative,
            violations: Vec::new(),
        };
        audit.visit_file(&syntax);
        violations.extend(audit.violations);
        let mut scoped = ScopedBoundaryAudit {
            source: &relative,
            function: String::new(),
            active: BTreeMap::new(),
            bindings: Vec::new(),
            violations: Vec::new(),
        };
        scoped.visit_file(&syntax);
        violations.extend(scoped.violations);
    }
    violations
}

fn assert_dropped_scope_is_rejected() {
    let dropped_scope_fixture = syn::parse_file(
        r#"
        fn dropped_scope(socket: &Socket) {
            let operation = audited_operation(OperationId::SocketSend);
            drop(operation);
            socket.send(&[1]);
        }
        "#,
    )
    .expect("parse dropped operation-scope fixture");
    let mut dropped_scope_audit = ScopedBoundaryAudit {
        source: "dropped_scope_fixture.rs",
        function: String::new(),
        active: BTreeMap::new(),
        bindings: Vec::new(),
        violations: Vec::new(),
    };
    dropped_scope_audit.visit_file(&dropped_scope_fixture);
    assert!(
        dropped_scope_audit
            .violations
            .iter()
            .any(|violation| violation.contains("SocketSend outside its lexical")),
        "operation-scope policy accepted a syscall after its RAII scope was dropped"
    );
}
