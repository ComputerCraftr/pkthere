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

pub(super) fn analyze_use(
    path: &str,
    cfg_domain: String,
    item: &syn::ItemUse,
) -> Option<PolicyFinding> {
    if !path.starts_with("tests/support/src/socket_reality/collect/") {
        return None;
    }
    let mut imports = Vec::new();
    collect_import_paths(&item.tree, Vec::new(), &mut imports);
    for segments in imports {
        let imports_policy_decision = segments
            .first()
            .is_some_and(|segment| segment == "pkthere_socket_policy")
            && segments.iter().any(|segment| {
                segment.starts_with("resolve_")
                    || segment.contains("capability")
                    || segment.contains("lifecycle_supported")
                    || segment.contains("creation_policy")
            });
        if imports_policy_decision {
            return Some(PolicyFinding {
                kind: PolicyKind::SocketLifecycleAuthority,
                path: path.to_string(),
                line: line(item.span()),
                item: "use declaration".to_string(),
                cfg_domain,
                detail: "independent socket-reality collectors cannot import production policy decisions"
                    .to_string(),
            });
        }
    }
    None
}

fn collect_import_paths(
    tree: &syn::UseTree,
    initial_prefix: Vec<String>,
    imports: &mut Vec<Vec<String>>,
) {
    let mut pending = vec![(tree, initial_prefix)];
    while let Some((tree, mut prefix)) = pending.pop() {
        match tree {
            syn::UseTree::Path(path) => {
                prefix.push(path.ident.to_string());
                pending.push((&path.tree, prefix));
            }
            syn::UseTree::Name(name) => {
                prefix.push(name.ident.to_string());
                imports.push(prefix);
            }
            syn::UseTree::Rename(rename) => {
                prefix.push(rename.ident.to_string());
                imports.push(prefix);
            }
            syn::UseTree::Glob(_) => imports.push(prefix),
            syn::UseTree::Group(group) => {
                pending.extend(group.items.iter().map(|item| (item, prefix.clone())));
            }
        }
    }
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
    if path == "src/net/sock_mgr/manager.rs" && is_test {
        findings.push(PolicyFinding {
            kind: PolicyKind::SocketLifecycleAuthority,
            path: path.to_string(),
            line: line(block.brace_token.span.open()),
            item: format!("{function}()"),
            cfg_domain: cfg_domain.clone(),
            detail: "test-only socket-manager helpers belong in the test module; production lifecycle tests must call the production transaction".to_string(),
        });
    }
    if path.starts_with("src/net/sock_mgr/manager")
        && !is_test
        && (inputs_reference_ident(inputs, "before_transition")
            || inputs_reference_ident(inputs, "after_transition"))
    {
        findings.push(PolicyFinding {
            kind: PolicyKind::SocketLifecycleAuthority,
            path: path.to_string(),
            line: line(block.brace_token.span.open()),
            item: format!("{function}()"),
            cfg_domain: cfg_domain.clone(),
            detail:
                "production socket transactions cannot expose test-only transition observer hooks"
                    .to_string(),
        });
    }
    if matches!(
        path,
        "src/net/sock_mgr/receiver_slot.rs" | "src/worker_support/receive.rs"
    ) && function == "for_test"
    {
        findings.push(PolicyFinding {
            kind: PolicyKind::SocketLifecycleAuthority,
            path: path.to_string(),
            line: line(block.brace_token.span.open()),
            item: format!("{function}()"),
            cfg_domain: cfg_domain.clone(),
            detail: "receive tests must claim production receiver slots and capture production authority"
                .to_string(),
        });
    }
    if path == "src/net/sock_mgr/manager.rs"
        && function == "publish_prechecked"
        && !inputs_reference_ident(inputs, "ManagerTransactionGuard")
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
    if path.starts_with("tests/support/src/socket_reality/verify/")
        && function.starts_with("is_")
        && ["windows", "linux", "macos", "freebsd", "unix"]
            .iter()
            .any(|platform| function.contains(platform))
    {
        findings.push(PolicyFinding {
            kind: PolicyKind::SocketLifecycleAuthority,
            path: path.to_string(),
            line: line(block.brace_token.span.open()),
            item: format!("{function}()"),
            cfg_domain: cfg_domain.clone(),
            detail: "platform-specific verifier exceptions are forbidden; exact RealityCase evidence must use the canonical verifier"
                .to_string(),
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
    is_test_context: bool,
    cfg_domain: String,
    item: &syn::ItemStruct,
) -> Vec<PolicyFinding> {
    if path.starts_with("src/")
        && !is_test_context
        && item.fields.iter().any(|field| {
            crate::common::rust_semantics::type_identifiers(&field.ty)
                .iter()
                .any(|name| {
                    matches!(
                        name.as_str(),
                        "RawFd" | "OwnedFd" | "BorrowedFd" | "RawSocket" | "OwnedSocket"
                    )
                })
        })
        && path != "src/net/managed_socket/platform.rs"
    {
        return vec![PolicyFinding {
            kind: PolicyKind::SocketLifecycleAuthority,
            path: path.to_string(),
            line: line(item.ident.span()),
            item: item.ident.to_string(),
            cfg_domain,
            detail: "persistent raw descriptors belong only to the audited managed socket platform owner"
                .to_string(),
        }];
    }
    if path == "src/net/sock_mgr/manager/types.rs" && item.ident == "SocketManager" {
        let test_only_fields = item
            .fields
            .iter()
            .filter(|field| {
                field.attrs.iter().any(|attribute| {
                    attribute.path().is_ident("cfg")
                        && attribute
                            .meta
                            .to_token_stream()
                            .to_string()
                            .split(|character: char| !character.is_ascii_alphanumeric())
                            .any(|token| token == "test")
                })
            })
            .map(|field| {
                field
                    .ident
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_else(|| "<unnamed>".to_string())
            })
            .collect::<Vec<_>>();
        if !test_only_fields.is_empty() {
            return vec![PolicyFinding {
                kind: PolicyKind::SocketLifecycleAuthority,
                path: path.to_string(),
                line: line(item.ident.span()),
                item: item.ident.to_string(),
                cfg_domain,
                detail: format!(
                    "SocketManager cannot carry test-only lifecycle authority fields: {}",
                    test_only_fields.join(", ")
                ),
            }];
        }
    }
    if matches!(
        item.ident.to_string().as_str(),
        "ClientFlowReservation" | "TopologyReservation"
    ) && item
        .fields
        .iter()
        .any(|field| crate::common::rust_semantics::type_references_ident(&field.ty, "MutexGuard"))
    {
        return vec![PolicyFinding {
            kind: PolicyKind::SocketLifecycleAuthority,
            path: path.to_string(),
            line: line(item.ident.span()),
            item: item.ident.to_string(),
            cfg_domain,
            detail: "topology and client-flow reservations must be logical tokens, never retained mutex guards"
                .to_string(),
        }];
    }
    if is_test_context
        || !path.starts_with("src/net/sock_mgr/")
        || path == "src/net/sock_mgr/version.rs"
    {
        return Vec::new();
    }
    item.fields
        .iter()
        .filter(|field| {
            field
                .ident
                .as_ref()
                .is_some_and(|ident| ident.to_string().contains("version"))
                && crate::common::rust_semantics::type_references_ident(&field.ty, "AtomicU64")
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

fn inputs_reference_ident(
    inputs: &syn::punctuated::Punctuated<syn::FnArg, syn::Token![,]>,
    expected: &str,
) -> bool {
    inputs.iter().any(|argument| match argument {
        syn::FnArg::Receiver(_) => false,
        syn::FnArg::Typed(argument) => {
            let pattern_has =
                crate::common::rust_semantics::pattern_references_ident(&argument.pat, expected);
            pattern_has
                || crate::common::rust_semantics::type_references_ident(&argument.ty, expected)
        }
    })
}

fn expression_references_ident_fragment(expression: &syn::Expr, fragment: &str) -> bool {
    crate::common::rust_semantics::expression_identifiers(expression)
        .iter()
        .any(|identifier| identifier.contains(fragment))
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
    fn visit_path(&mut self, path: &'ast syn::Path) {
        if self
            .path
            .starts_with("tests/support/src/socket_reality/collect/")
            && path
                .segments
                .first()
                .is_some_and(|segment| segment.ident == "pkthere_socket_policy")
            && path.segments.iter().any(|segment| {
                let name = segment.ident.to_string();
                name.starts_with("resolve_")
                    || name.contains("capability")
                    || name.contains("lifecycle_supported")
                    || name.contains("creation_policy")
            })
        {
            self.record(
                path.span(),
                "independent socket-reality collectors cannot import production policy decisions",
            );
        }
        syn::visit::visit_path(self, path);
    }

    fn visit_ident(&mut self, ident: &'ast syn::Ident) {
        if self
            .path
            .starts_with("tests/support/src/socket_reality/verify/")
            && matches!(
                ident.to_string().as_str(),
                "current_icmp_platform_capabilities" | "icmp_platform_capabilities"
            )
        {
            self.record(
                ident.span(),
                "reality verification must consume the exact resolved policy/fingerprint, not an aggregate platform capability",
            );
        }
        if self.path.starts_with("src/net/managed_socket")
            && matches!(
                ident.to_string().as_str(),
                "reopen_after_io_drain_timeout" | "IoDrainTimedOut"
            )
        {
            self.record(
                ident.span(),
                "I/O quiescence loss must poison topology and remain a typed fatal invariant",
            );
        }
        if self.path.starts_with("tests/") && ident == "ALL_CONNECT_MODES" {
            self.record(
                ident.span(),
                "connection matrices must separate production policy from explicitly named debug scenarios",
            );
        }
        if self.path.starts_with("tests/")
            && self.is_test
            && !self.function.contains("debug")
            && !self.function.contains("forced_unconnected")
            && !self.function.contains("synthetic")
            && matches!(
                ident.to_string().as_str(),
                "FORCED_UNCONNECTED_DEBUG_SCENARIOS" | "ForcedUnconnectedDebug"
            )
        {
            self.record(
                ident.span(),
                "a production-named test cannot select a forced-unconnected debug scenario",
            );
        }
        if ident == "connected_listener_slot" {
            self.record(
                ident.span(),
                "callers cannot nominate a connected listener; the manager selects the stable owner from resolved lifecycle policy",
            );
        }
        if self.path.starts_with("crates/socket_policy/src/")
            && matches!(
                ident.to_string().as_str(),
                "force_unconnected" | "replaces_connected_owner_on_clear"
            )
        {
            self.record(
                ident.span(),
                "listener connection and clear behavior belongs to ListenerLockLifecycle",
            );
        }
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

    fn visit_expr_struct(&mut self, expression: &'ast syn::ExprStruct) {
        if self.is_test
            && self.path.starts_with("src/")
            && expression
                .path
                .segments
                .last()
                .is_some_and(|segment| segment.ident == "AdmittedWirePacket")
        {
            self.record(
                expression.path.span(),
                "test-only code cannot construct admitted packets; tests must invoke production parsing and admission",
            );
        }
        if self.path.starts_with("tests/")
            && !self.function.contains("debug")
            && !self.function.contains("forced_unconnected")
            && !self.function.contains("synthetic")
        {
            for field in &expression.fields {
                let forces_unconnected = matches!(
                    &field.member,
                    syn::Member::Named(name)
                        if name == "debug_client_unconnected"
                            || name == "debug_upstream_unconnected"
                );
                let true_literal = matches!(
                    field.expr,
                    syn::Expr::Lit(syn::ExprLit {
                        lit: syn::Lit::Bool(ref value),
                        ..
                    }) if value.value
                );
                if forces_unconnected && true_literal {
                    self.record(
                        field.span(),
                        "a production-named test cannot force an unconnected debug policy",
                    );
                }
            }
        }
        syn::visit::visit_expr_struct(self, expression);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        let production_source = self.path.starts_with("src/");
        if production_source
            && !self.is_test
            && call.method == "parse"
            && crate::common::rust_semantics::expression_identifiers(&call.receiver)
                .contains("parser")
        {
            self.record(
                call.method.span(),
                "production packet parsing must call parse_network then parse_transport",
            );
        }
        if production_source
            && !self.is_test
            && matches!(
                call.method.to_string().as_str(),
                "set_read_timeout" | "set_write_timeout"
            )
        {
            self.record(
                call.method.span(),
                "production data-plane blocking is governed by bounded readiness polling",
            );
        }
        if production_source
            && call.method == "connects_after_lock"
            && self.path != "src/main.rs"
            && self.path != "src/net/sock_mgr/manager.rs"
        {
            self.record(
                call.method.span(),
                "production listener connection decisions belong to the socket manager; other callers may only report the resolved lifecycle",
            );
        }
        if self.path.starts_with("src/net/sock_mgr/")
            && self.path != "src/net/sock_mgr/version.rs"
            && matches!(
                call.method.to_string().as_str(),
                "fetch_update" | "try_update"
            )
            && expression_references_ident_fragment(&call.receiver, "version")
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
            && expression_references_ident_fragment(&call.receiver, "version")
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
        if production_source
            && !self.is_test
            && matches!(
                call.method.to_string().as_str(),
                "try_clone" | "into_raw_fd" | "into_raw_socket"
            )
        {
            self.record(
                call.method.span(),
                "runtime socket descriptors must not be cloned or escape ManagedSocket ownership",
            );
        }
        if production_source && !self.is_test && call.method == "connect" {
            let managed_backend = self.path == "src/net/managed_socket.rs"
                || self.path.starts_with("src/net/managed_socket/");
            let route_probe =
                self.path == "src/net/socket.rs" && self.function == "resolve_route_local_ip";
            let unpublished_realization = self.path == "src/net/socket/realization.rs"
                && self.function == "configure_connected";
            if !managed_backend && !route_probe && !unpublished_realization {
                self.record(
                    call.method.span(),
                    "production socket connect transitions belong to ManagedSocket",
                );
            }
        }
        if production_source
            && !self.is_test
            && call.method == "disconnect"
            && crate::common::rust_semantics::expression_identifiers(&call.receiver)
                .contains("backend")
            && !(self.path == "src/net/managed_socket/association_reservation.rs"
                && self.function == "observe_disconnect")
        {
            self.record(
                call.method.span(),
                "every production backend disconnect must pass through the typed postcondition observer",
            );
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
            && !(self.path == "src/net/sock_mgr/manager_client_flow.rs"
                && self.function == "reconcile_stale_send_association")
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
            if called
                .as_deref()
                .is_some_and(|name| matches!(name, "dup" | "dup2" | "dup3" | "DuplicateHandle"))
                && self.path != "src/net/managed_socket/platform.rs"
            {
                self.record(
                    path.path.span(),
                    "production descriptor duplication is forbidden outside the audited managed socket platform owner",
                );
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
            if segments.len() == 2
                && segments[0].ident == "ManagedReceiver"
                && segments[1].ident == "new"
                && self.path != "src/net/sock_mgr/receiver_slot.rs"
            {
                self.record(
                    segments[1].ident.span(),
                    "receive capabilities are published and claimed only through ReceiverSlot",
                );
            }
            if called.as_deref() == Some("reconcile_destination_required")
                && !self.path.starts_with("src/net/managed_socket")
                && !(self.path == "src/net/sock_mgr/manager_client_flow.rs"
                    && self.function == "reconcile_stale_send_association")
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
