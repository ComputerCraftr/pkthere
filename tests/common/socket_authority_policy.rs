use super::{PolicyFinding, PolicyKind, line};
use quote::ToTokens;
use std::collections::BTreeSet;
use syn::spanned::Spanned;
use syn::visit::Visit;

pub(super) fn socket_type_aliases(file: &syn::File) -> BTreeSet<String> {
    let mut aliases = BTreeSet::from(["Socket".to_string()]);
    for item in &file.items {
        if let syn::Item::Use(item_use) = item {
            collect_socket_aliases(&item_use.tree, &[], &mut aliases);
        }
    }
    aliases
}

fn collect_socket_aliases(
    tree: &syn::UseTree,
    initial_prefix: &[String],
    aliases: &mut BTreeSet<String>,
) {
    let mut pending = vec![(tree, initial_prefix.to_owned())];
    while let Some((tree, mut prefix)) = pending.pop() {
        match tree {
            syn::UseTree::Path(path) => {
                prefix.push(path.ident.to_string());
                pending.push((&path.tree, prefix));
            }
            syn::UseTree::Name(name)
                if prefix.as_slice() == ["socket2"] && name.ident == "Socket" =>
            {
                aliases.insert(name.ident.to_string());
            }
            syn::UseTree::Rename(rename)
                if prefix.as_slice() == ["socket2"] && rename.ident == "Socket" =>
            {
                aliases.insert(rename.rename.to_string());
            }
            syn::UseTree::Group(group) => {
                pending.extend(group.items.iter().map(|item| (item, prefix.clone())));
            }
            syn::UseTree::Glob(_) | syn::UseTree::Name(_) | syn::UseTree::Rename(_) => {}
        }
    }
}

pub(super) fn analyze_enum(
    path: &str,
    cfg_domain: String,
    item: &syn::ItemEnum,
) -> Option<PolicyFinding> {
    let governed = path.starts_with("crates/wire/src/packet_headers/")
        || path.starts_with("tests/support/src/socket_reality/");
    let variants = item
        .variants
        .iter()
        .map(|variant| variant.ident.to_string())
        .collect::<BTreeSet<_>>();
    let duplicate_family =
        item.ident != "IpVersion" && variants.contains("V4") && variants.contains("V6");
    let duplicate_layout = item.ident != "ReceiveHeaderMode"
        && variants.contains("IpHeader")
        && (variants.contains("Headerless") || variants.contains("TransportHeaderOnly"));
    (governed && (duplicate_family || duplicate_layout)).then(|| PolicyFinding {
        kind: PolicyKind::SocketLifecycleAuthority,
        path: path.to_string(),
        line: line(item.ident.span()),
        item: item.ident.to_string(),
        cfg_domain,
        detail: "use Domain, IpVersion, and ReceiveHeaderMode".into(),
    })
}

pub(super) fn analyze_function(
    path: &str,
    function: &str,
    is_test: bool,
    cfg_domain: String,
    inputs: &syn::punctuated::Punctuated<syn::FnArg, syn::Token![,]>,
    socket_aliases: &BTreeSet<String>,
    block: &syn::Block,
) -> Vec<PolicyFinding> {
    let mut findings = Vec::new();
    if path == "src/net/sock_mgr/manager.rs"
        && function == "publish_prechecked"
        && !inputs
            .to_token_stream()
            .to_string()
            .contains("ManagerTransactionGuard")
    {
        findings.push(PolicyFinding {
            kind: PolicyKind::ManagerVersionAuthority,
            path: path.to_string(),
            line: line(block.brace_token.span.open()),
            item: format!("{function}()"),
            cfg_domain: cfg_domain.clone(),
            detail: "manager publication requires a typed transaction guard".to_string(),
        });
    }
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
        socket_aliases: socket_aliases.clone(),
        connection_state_names: connection_bool_parameters(inputs),
        socket_send_seen: false,
    };
    visitor.visit_block(block);
    if visitor.socket_send_seen && !visitor.connection_state_names.is_empty() {
        visitor.record(
            block.brace_token.span.open(),
            "Boolean connection-state inputs must not select socket send paths",
        );
    }
    visitor.findings
}

pub(super) fn analyze_struct(
    path: &str,
    cfg_domain: String,
    item: &syn::ItemStruct,
) -> Vec<PolicyFinding> {
    if !path.starts_with("src/net/sock_mgr/") || path == "src/net/sock_mgr/version.rs" {
        return Vec::new();
    }
    item.fields
        .iter()
        .filter(|field| {
            field
                .ident
                .as_ref()
                .is_some_and(|ident| ident.to_string().contains("version"))
                && field.ty.to_token_stream().to_string().contains("AtomicU64")
        })
        .map(|field| PolicyFinding {
            kind: PolicyKind::ManagerVersionAuthority,
            path: path.to_string(),
            line: line(field.span()),
            item: item.ident.to_string(),
            cfg_domain: cfg_domain.clone(),
            detail: "manager version atomics belong to the version clock".to_string(),
        })
        .collect()
}

fn connection_bool_parameters(
    inputs: &syn::punctuated::Punctuated<syn::FnArg, syn::Token![,]>,
) -> BTreeSet<String> {
    inputs
        .iter()
        .filter_map(|argument| {
            let syn::FnArg::Typed(argument) = argument else {
                return None;
            };
            let syn::Pat::Ident(pattern) = argument.pat.as_ref() else {
                return None;
            };
            let syn::Type::Path(ty) = argument.ty.as_ref() else {
                return None;
            };
            let name = pattern.ident.to_string();
            (name.contains("connected")
                && ty
                    .path
                    .segments
                    .last()
                    .is_some_and(|segment| segment.ident == "bool"))
            .then_some(name)
        })
        .collect()
}

struct SocketAuthorityVisitor<'a> {
    path: &'a str,
    function: &'a str,
    is_test: bool,
    cfg_domain: String,
    findings: Vec<PolicyFinding>,
    socket_aliases: BTreeSet<String>,
    connection_state_names: BTreeSet<String>,
    socket_send_seen: bool,
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
    fn visit_ident(&mut self, ident: &'ast syn::Ident) {
        if self.path.starts_with("src/net/sock_mgr/") && ident == "prev_ver" {
            self.findings.push(PolicyFinding {
                kind: PolicyKind::ManagerVersionAuthority,
                path: self.path.to_string(),
                line: line(ident.span()),
                item: ident.to_string(),
                cfg_domain: self.cfg_domain.clone(),
                detail: "manager versions are allocated by VersionClock, never by callers"
                    .to_string(),
            });
        }
        syn::visit::visit_ident(self, ident);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        let production_source = self.path.starts_with("src/");
        if self.path.starts_with("src/net/sock_mgr/")
            && self.path != "src/net/sock_mgr/version.rs"
            && call.method == "fetch_update"
            && call
                .receiver
                .to_token_stream()
                .to_string()
                .contains("version")
        {
            self.findings.push(PolicyFinding {
                kind: PolicyKind::ManagerVersionAuthority,
                path: self.path.to_string(),
                line: line(call.method.span()),
                item: format!("{}()", self.function),
                cfg_domain: self.cfg_domain.clone(),
                detail: "direct manager version allocation belongs to VersionClock".to_string(),
            });
        }
        if self.path.starts_with("src/net/sock_mgr/")
            && self.path != "src/net/sock_mgr/version.rs"
            && self.function != "publish_prechecked"
            && call.method == "publish_prechecked"
            && call
                .receiver
                .to_token_stream()
                .to_string()
                .contains("version")
        {
            self.findings.push(PolicyFinding {
                kind: PolicyKind::ManagerVersionAuthority,
                path: self.path.to_string(),
                line: line(call.method.span()),
                item: format!("{}()", self.function),
                cfg_domain: self.cfg_domain.clone(),
                detail: "manager publication must pass through its transaction-guarded wrapper"
                    .to_string(),
            });
        }
        if production_source && !self.is_test && call.method == "try_clone" {
            self.record(
                call.method.span(),
                "runtime socket descriptors must be shared through ManagedSocket",
            );
        }
        if production_source && !self.is_test && call.method == "connect" {
            let managed_backend = self.path == "src/net/managed_socket.rs"
                || self.path.starts_with("src/net/managed_socket/");
            let route_probe =
                self.path == "src/net/socket.rs" && self.function == "resolve_route_local_ip";
            if !managed_backend && !route_probe {
                self.record(
                    call.method.span(),
                    "production socket connect transitions belong to ManagedSocket",
                );
            }
        }
        if production_source
            && !self.is_test
            && (call.method == "recv" || call.method == "recv_from")
            && self.path != "src/net/managed_socket.rs"
            && !self.path.starts_with("src/net/managed_socket/")
        {
            self.record(
                call.method.span(),
                "production receive syscalls belong to ManagedSocket::receive",
            );
        }
        if production_source
            && !self.is_test
            && matches!(
                call.method.to_string().as_str(),
                "send" | "send_to" | "send_vectored" | "send_to_vectored"
            )
        {
            self.socket_send_seen = true;
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
        if production_source
            && !self.is_test
            && call.method == "reconcile_destination_required"
            && !self.path.starts_with("src/net/managed_socket")
        {
            self.record(
                call.method.span(),
                "socket association reconciliation must complete inside ManagedSocket",
            );
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        let production_source = self.path.starts_with("src/") && !self.is_test;
        if let syn::Expr::Path(path) = call.func.as_ref() {
            let segments = &path.path.segments;
            let called = segments.last().map(|segment| segment.ident.to_string());
            if called.as_deref() == Some("from_raw_parts")
                && self.path != "src/net/managed_socket/receive.rs"
                && self.path != "tests/support/src/socket_reality/collect/receive_buffer.rs"
            {
                self.record(
                    path.path.span(),
                    "initialized receive-prefix conversion belongs to an audited receive buffer",
                );
            }
            if !production_source {
                syn::visit::visit_expr_call(self, call);
                return;
            }
            let raw_receive = called
                .as_deref()
                .is_some_and(|name| name == "recv" || name == "recv_from")
                && (segments.iter().any(|segment| segment.ident == "socket2")
                    || segments.iter().rev().nth(1).is_some_and(|owner| {
                        self.socket_aliases.contains(&owner.ident.to_string())
                    }));
            if raw_receive && self.path != "src/net/managed_socket/receive.rs" {
                self.record(
                    path.path.span(),
                    "raw socket receive APIs belong to the audited managed receive boundary",
                );
            }
            if called
                .as_deref()
                .is_some_and(|name| name.contains("send"))
                && call.args.iter().any(|argument| {
                    matches!(
                        argument,
                        syn::Expr::Path(argument_path)
                            if argument_path
                                .path
                                .get_ident()
                                .is_some_and(|ident| self.connection_state_names.contains(&ident.to_string()))
                    )
                })
            {
                self.record(
                    path.path.span(),
                    "Boolean connection-state values must not be passed into send helpers",
                );
            }
            if segments.len() == 2
                && segments[0].ident == "ManagedSocket"
                && (segments[1].ident == "new" || segments[1].ident == "from")
            {
                self.record(
                    segments[1].ident.span(),
                    "ManagedSocket adoption must use a checked explicit-state constructor",
                );
            }
            if called.as_deref() == Some("reconcile_destination_required")
                && !self.path.starts_with("src/net/managed_socket")
            {
                self.record(
                    path.path.span(),
                    "socket association reconciliation must complete inside ManagedSocket",
                );
            }
            if segments
                .last()
                .is_some_and(|segment| segment.ident == "send_payload")
                && call.args.iter().any(|argument| {
                    matches!(
                        argument,
                        syn::Expr::MethodCall(method)
                            if method.method == "listener_connected"
                                || method.method == "upstream_connected"
                    )
                })
            {
                self.record(
                    path.path.span(),
                    "send path selection must come atomically from ManagedSocket association",
                );
            }
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_local(&mut self, local: &'ast syn::Local) {
        if let Some(initializer) = &local.init
            && let syn::Expr::MethodCall(call) = initializer.expr.as_ref()
            && matches!(
                call.method.to_string().as_str(),
                "is_connected" | "listener_connected" | "upstream_connected"
            )
            && let syn::Pat::Ident(pattern) = &local.pat
        {
            self.connection_state_names
                .insert(pattern.ident.to_string());
        }
        syn::visit::visit_local(self, local);
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        collect_socket_aliases(&item.tree, &[], &mut self.socket_aliases);
        syn::visit::visit_item_use(self, item);
    }

    fn visit_item_fn(&mut self, _item: &'ast syn::ItemFn) {}
    fn visit_impl_item_fn(&mut self, _item: &'ast syn::ImplItemFn) {}
    fn visit_trait_item_fn(&mut self, _item: &'ast syn::TraitItemFn) {}
}
