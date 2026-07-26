use super::{PolicyFinding, PolicyKind, line};
use quote::ToTokens;
use syn::spanned::Spanned;

pub(super) fn analyze_macro(
    path: &str,
    cfg_domain: String,
    item: &syn::Macro,
) -> Option<PolicyFinding> {
    let macro_name = item.path.segments.last()?.ident.to_string();
    ((path.starts_with("src/") || path.starts_with("crates/"))
        && matches!(
            macro_name.as_str(),
            "debug_assert" | "debug_assert_eq" | "debug_assert_ne"
        ))
    .then(|| PolicyFinding {
        kind: PolicyKind::ProductionDebugAssertion,
        path: path.to_string(),
        line: line(item.span()),
        item: macro_name,
        cfg_domain,
        detail: "a production invariant must return a typed error or use a release assertion"
            .to_string(),
    })
}

pub(super) fn analyze_attribute(
    path: &str,
    cfg_domain: String,
    attr: &syn::Attribute,
) -> Option<PolicyFinding> {
    let tokens = attr.meta.to_token_stream().to_string();
    ((path.starts_with("src/") || path.starts_with("crates/"))
        && tokens
            .split(|character: char| !character.is_alphanumeric() && character != '_')
            .any(|token| token == "debug_assertions"))
    .then(|| PolicyFinding {
        kind: PolicyKind::ProductionDebugAssertion,
        path: path.to_string(),
        line: line(attr.span()),
        item: "cfg(debug_assertions)".to_string(),
        cfg_domain,
        detail: "production behavior and invariant checking must not disappear from release builds"
            .to_string(),
    })
}
