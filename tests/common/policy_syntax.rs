use quote::ToTokens;

pub(super) fn cfg_fragments(attrs: &[syn::Attribute]) -> Vec<String> {
    attrs
        .iter()
        .filter(|attr| attr.path().is_ident("cfg") || attr.path().is_ident("cfg_attr"))
        .map(|attr| attr.meta.to_token_stream().to_string())
        .collect()
}

pub(super) fn attr_is_test_context(attr: &syn::Attribute) -> bool {
    if attr
        .path()
        .segments
        .last()
        .is_some_and(|segment| segment.ident == "test")
    {
        return true;
    }
    (attr.path().is_ident("cfg") || attr.path().is_ident("cfg_attr"))
        && token_stream_has_ident(attr.meta.to_token_stream(), "test")
}

fn token_stream_has_ident(stream: proc_macro2::TokenStream, expected: &str) -> bool {
    let mut pending = stream.into_iter().collect::<Vec<_>>();
    while let Some(token) = pending.pop() {
        match token {
            proc_macro2::TokenTree::Ident(ident) if ident == expected => return true,
            proc_macro2::TokenTree::Group(group) => pending.extend(group.stream()),
            _ => {}
        }
    }
    false
}

pub(super) fn use_tree_has_glob(tree: &syn::UseTree) -> bool {
    let mut pending = vec![tree];
    while let Some(tree) = pending.pop() {
        match tree {
            syn::UseTree::Glob(_) => return true,
            syn::UseTree::Group(group) => pending.extend(group.items.iter()),
            syn::UseTree::Path(path) => pending.push(&path.tree),
            syn::UseTree::Name(_) | syn::UseTree::Rename(_) => {}
        }
    }
    false
}

pub(super) fn path_string(path: &syn::Path) -> String {
    path.segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>()
        .join("::")
}
