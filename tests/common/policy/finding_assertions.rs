use super::{PolicyKind, WorkspaceAnalysis, line, relative};
use std::collections::BTreeSet;
use syn::spanned::Spanned;

pub(super) fn collect_displaced_constants(
    items: &[syn::Item],
    scope: &str,
    violations: &mut Vec<(usize, String)>,
) {
    let mut pending = vec![(scope.to_string(), items)];
    while let Some((current_scope, current_items)) = pending.pop() {
        let mut runtime_item_seen = false;
        for item in current_items {
            match item {
                syn::Item::Const(constant) if runtime_item_seen => {
                    violations.push((line(constant.span()), current_scope.clone()));
                }
                syn::Item::Static(item_static) if runtime_item_seen => {
                    violations.push((line(item_static.span()), current_scope.clone()));
                }
                syn::Item::Const(_)
                | syn::Item::Static(_)
                | syn::Item::Use(_)
                | syn::Item::ExternCrate(_) => {}
                syn::Item::Macro(item_macro) if item_macro.ident.is_some() => {}
                syn::Item::Mod(module) => {
                    if let Some((_, nested)) = &module.content {
                        pending.push((format!("{current_scope}::{}", module.ident), nested));
                    }
                }
                _ => runtime_item_seen = true,
            }
        }
    }
}

pub(super) fn assert_none(
    analysis: &WorkspaceAnalysis,
    kinds: &[PolicyKind],
    governed_paths: &[&str],
) {
    let expected = kinds.iter().copied().collect::<BTreeSet<_>>();
    let findings = analysis
        .parsed
        .iter()
        .filter(|(path, _)| {
            governed_paths.is_empty()
                || governed_paths.contains(&relative(&analysis.inventory.repo_root, path).as_str())
        })
        .flat_map(|(_, parsed)| {
            parsed
                .findings
                .iter()
                .filter(|finding| expected.contains(&finding.kind))
        })
        .collect::<Vec<_>>();
    assert!(
        findings.is_empty(),
        "Rust syntax policy violations:\n{}",
        findings
            .iter()
            .map(|finding| finding.render())
            .collect::<Vec<_>>()
            .join("\n")
    );
}
