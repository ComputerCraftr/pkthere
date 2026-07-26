use super::{PolicyFinding, PolicyKind, line};
use syn::spanned::Spanned;
use syn::visit::Visit;

const MIXED_FAILURE_CALLS: &[&str] = &[
    "try_reserve_client_flow",
    "try_reserve_client_flow_until",
    "reserve_until",
    "try_topology_read",
    "try_admission_snapshot",
    "reserve_topology_until",
    "publish_prechecked",
    "assert_current",
    "publish_locked",
    "reset_under",
    "invalidate_flow_authority_under",
    "clear_pending_icmp_client_lock_under",
    "promote_pending_icmp_client_session_with_replay_under",
    "promote_ready_icmp_client_session_with_replay_under",
];

pub(super) fn analyze_function(
    path: &str,
    name: &str,
    is_test: bool,
    cfg_domain: String,
    block: &syn::Block,
) -> Vec<PolicyFinding> {
    if is_test {
        return Vec::new();
    }
    let mut visitor = FailureContainmentVisitor {
        path,
        name,
        cfg_domain,
        findings: Vec::new(),
        saw_join: None,
        saw_is_finished: false,
    };
    visitor.visit_block(block);
    visitor.inspect_statement_order(block);
    if let Some(span) = visitor.saw_join
        && !visitor.saw_is_finished
        && (path == "src/runtime_support.rs" || path.ends_with("/fixture.rs"))
    {
        visitor.record(
            span,
            "join()",
            "a supervised blocking join requires an adjacent is_finished authority".to_string(),
        );
    }
    visitor.findings
}

struct FailureContainmentVisitor<'a> {
    path: &'a str,
    name: &'a str,
    cfg_domain: String,
    findings: Vec<PolicyFinding>,
    saw_join: Option<proc_macro2::Span>,
    saw_is_finished: bool,
}

impl FailureContainmentVisitor<'_> {
    fn record(&mut self, span: proc_macro2::Span, item: &str, detail: String) {
        self.findings.push(PolicyFinding {
            kind: PolicyKind::FailureContainmentAuthority,
            path: self.path.to_string(),
            line: line(span),
            item: item.to_string(),
            cfg_domain: self.cfg_domain.clone(),
            detail,
        });
    }

    fn inspect_statement_order(&mut self, block: &syn::Block) {
        for (index, statement) in block.stmts.iter().enumerate() {
            let syn::Stmt::Expr(expression, semicolon) = statement else {
                continue;
            };
            if semicolon.is_some() && is_ignored_validation(expression) {
                self.record(
                    expression.span(),
                    "validate()",
                    "reservation validation must be propagated before mutation".to_string(),
                );
            }
            if expression_calls_fatal_publisher(expression)
                && block.stmts[index.saturating_add(1)..]
                    .iter()
                    .any(statement_returns_normal_authority)
            {
                self.record(
                    expression.span(),
                    "fatal publication",
                    "fatal publication cannot be followed by a usable authority value".to_string(),
                );
            }
        }
    }
}

impl<'ast> Visit<'ast> for FailureContainmentVisitor<'_> {
    fn visit_expr_if(&mut self, expression: &'ast syn::ExprIf) {
        if let syn::Expr::Let(let_expression) = expression.cond.as_ref()
            && mentions_mixed_failure_call(&let_expression.expr)
            && is_catch_all_error_pattern(&let_expression.pat)
        {
            self.record(
                expression.span(),
                "catch-all conditional error",
                "mixed-class authority errors require variant-aware conditional handling"
                    .to_string(),
            );
        }
        syn::visit::visit_expr_if(self, expression);
    }

    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        if path
            .path
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "is_finished")
        {
            self.saw_is_finished = true;
        }
        syn::visit::visit_expr_path(self, path);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if matches!(
            call.func.as_ref(),
            syn::Expr::Path(path)
                if path.path.segments.last().is_some_and(|segment| segment.ident == "is_finished")
        ) {
            self.saw_is_finished = true;
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        let method = call.method.to_string();
        if method == "ok" && mentions_mixed_failure_call(&call.receiver) {
            self.record(
                call.span(),
                ".ok()",
                "mixed-class authority errors must be matched exhaustively".to_string(),
            );
        }
        if method == "is_err" && mentions_mixed_failure_call(&call.receiver) {
            self.record(
                call.span(),
                ".is_err()",
                "authority validation and mutation errors must be propagated or classified, not reduced to a Boolean".to_string(),
            );
        }
        let is_stats_sealing_owner =
            self.path == "src/stats/recorder.rs" && self.name == "drive_sealing_once";
        if method == "queue_flush_marker" && self.name != "seal_until" && !is_stats_sealing_owner {
            self.record(
                call.span(),
                "queue_flush_marker()",
                "only consuming producer cleanup may request a final marker".to_string(),
            );
        }
        if method == "join" {
            self.saw_join = Some(call.span());
        } else if method == "is_finished" {
            self.saw_is_finished = true;
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_match(&mut self, expression: &'ast syn::ExprMatch) {
        if mentions_mixed_failure_call(&expression.expr) {
            for arm in &expression.arms {
                if is_catch_all_error_pattern(&arm.pat) {
                    self.record(
                        arm.pat.span(),
                        "catch-all error arm",
                        "mixed-class authority errors require variant-aware handling".to_string(),
                    );
                }
            }
        }
        syn::visit::visit_expr_match(self, expression);
    }
}

fn mentions_mixed_failure_call(expression: &syn::Expr) -> bool {
    MIXED_FAILURE_CALLS
        .iter()
        .any(|function| expression_calls_named(expression, function))
}

fn is_catch_all_error_pattern(pattern: &syn::Pat) -> bool {
    match pattern {
        syn::Pat::Wild(_) => true,
        syn::Pat::TupleStruct(tuple) => {
            tuple
                .path
                .segments
                .last()
                .is_some_and(|segment| segment.ident == "Err")
                && tuple
                    .elems
                    .iter()
                    .any(|element| matches!(element, syn::Pat::Wild(_)))
        }
        syn::Pat::Or(patterns) => patterns.cases.iter().any(is_catch_all_error_pattern),
        _ => false,
    }
}

fn is_ignored_validation(expression: &syn::Expr) -> bool {
    matches!(
        expression,
        syn::Expr::MethodCall(call) if call.method == "validate"
    )
}

fn expression_calls_fatal_publisher(expression: &syn::Expr) -> bool {
    if !matches!(
        expression,
        syn::Expr::Call(_) | syn::Expr::MethodCall(_) | syn::Expr::Macro(_)
    ) {
        return false;
    }
    expression_calls_named(expression, "publish_process_fatal")
        || expression_calls_named(expression, "request_current_fatal")
}

fn statement_returns_normal_authority(statement: &syn::Stmt) -> bool {
    let syn::Stmt::Expr(expression, _) = statement else {
        return false;
    };
    let expression = match expression {
        syn::Expr::Return(returned) => returned.expr.as_deref(),
        expression => Some(expression),
    };
    expression.is_some_and(|expression| {
        matches!(
            expression,
            syn::Expr::Call(call)
                if matches!(
                    call.func.as_ref(),
                    syn::Expr::Path(path)
                        if path.path.is_ident("Ok") || path.path.is_ident("Some")
                )
        )
    })
}

fn expression_calls_named(expression: &syn::Expr, expected: &str) -> bool {
    struct Visitor<'a> {
        expected: &'a str,
        found: bool,
    }
    impl Visit<'_> for Visitor<'_> {
        fn visit_expr_call(&mut self, call: &syn::ExprCall) {
            self.found |= matches!(
                call.func.as_ref(),
                syn::Expr::Path(path)
                    if path.path.segments.last().is_some_and(|segment| segment.ident == self.expected)
            );
            if !self.found {
                syn::visit::visit_expr_call(self, call);
            }
        }

        fn visit_expr_method_call(&mut self, call: &syn::ExprMethodCall) {
            self.found |= call.method == self.expected;
            if !self.found {
                syn::visit::visit_expr_method_call(self, call);
            }
        }
    }
    let mut visitor = Visitor {
        expected,
        found: false,
    };
    visitor.visit_expr(expression);
    visitor.found
}
