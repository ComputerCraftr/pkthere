use super::{PolicyFinding, PolicyKind, line};
use syn::visit::Visit;

pub(super) fn analyze_function(
    path: &str,
    function: &str,
    is_test: bool,
    cfg_domain: String,
    block: &syn::Block,
) -> Vec<PolicyFinding> {
    let mut findings = Vec::new();
    if path.starts_with("src/")
        && !is_test
        && function == "disconnect_socket"
        && path != "src/net/managed_socket.rs"
    {
        findings.push(PolicyFinding {
            kind: PolicyKind::SocketLifecycleAuthority,
            path: path.to_string(),
            line: line(block.brace_token.span.open()),
            item: format!("{function}()"),
            cfg_domain: cfg_domain.clone(),
            detail: "platform socket disconnect helpers belong to ManagedSocket".to_string(),
        });
    }
    let mut visitor = SocketAuthorityVisitor {
        path,
        function,
        is_test,
        cfg_domain,
        findings,
    };
    visitor.visit_block(block);
    visitor.findings
}

struct SocketAuthorityVisitor<'a> {
    path: &'a str,
    function: &'a str,
    is_test: bool,
    cfg_domain: String,
    findings: Vec<PolicyFinding>,
}

impl SocketAuthorityVisitor<'_> {
    fn record(&mut self, span: proc_macro2::Span, detail: &str) {
        self.findings.push(PolicyFinding {
            kind: PolicyKind::SocketLifecycleAuthority,
            path: self.path.to_string(),
            line: line(span),
            item: format!("{}()", self.function),
            cfg_domain: self.cfg_domain.clone(),
            detail: detail.to_string(),
        });
    }
}

impl<'ast> Visit<'ast> for SocketAuthorityVisitor<'_> {
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        let production_source = self.path.starts_with("src/");
        if production_source && !self.is_test && call.method == "try_clone" {
            self.record(
                call.method.span(),
                "runtime socket descriptors must be shared through ManagedSocket",
            );
        }
        if production_source && !self.is_test && call.method == "connect" {
            let managed_backend = self.path == "src/net/managed_socket.rs";
            let route_probe =
                self.path == "src/net/socket.rs" && self.function == "resolve_route_local_ip";
            if !managed_backend && !route_probe {
                self.record(
                    call.method.span(),
                    "production socket connect transitions belong to ManagedSocket",
                );
            }
        }
        if production_source && !self.is_test && call.method == "set_port" {
            let route_probe =
                self.path == "src/net/socket.rs" && self.function == "resolve_route_local_ip";
            if !route_probe {
                self.record(
                    call.method.span(),
                    "logical endpoint IDs must not be synchronized through port mutation",
                );
            }
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_item_fn(&mut self, _item: &'ast syn::ItemFn) {}
    fn visit_impl_item_fn(&mut self, _item: &'ast syn::ImplItemFn) {}
    fn visit_trait_item_fn(&mut self, _item: &'ast syn::TraitItemFn) {}
}
