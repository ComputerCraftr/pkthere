use quote::ToTokens;
use syn::parse::Parser;

const TARGET_LINUX: u8 = 1 << 0;
const TARGET_MACOS: u8 = 1 << 1;
const TARGET_WINDOWS: u8 = 1 << 2;
const TARGET_FREEBSD: u8 = 1 << 3;
const TARGET_ALL: u8 = TARGET_LINUX | TARGET_MACOS | TARGET_WINDOWS | TARGET_FREEBSD;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct TargetMask(u8);

impl TargetMask {
    pub(super) const fn all() -> Self {
        Self(TARGET_ALL)
    }

    pub(super) const fn intersect(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    pub(super) const fn overlaps(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }
}

pub(super) fn cfg_target_mask(attrs: &[syn::Attribute]) -> TargetMask {
    attrs
        .iter()
        .filter(|attr| attr.path().is_ident("cfg"))
        .filter_map(|attr| attr.parse_args::<syn::Meta>().ok())
        .fold(TargetMask::all(), |mask, meta| {
            mask.intersect(meta_target_mask(&meta))
        })
}

fn meta_target_mask(meta: &syn::Meta) -> TargetMask {
    enum Task {
        Evaluate(Box<syn::Meta>),
        Intersect(usize),
        Union(usize),
        Complement,
    }
    let mut tasks = vec![Task::Evaluate(Box::new(meta.clone()))];
    let mut values = Vec::new();
    while let Some(task) = tasks.pop() {
        match task {
            Task::Evaluate(meta) if matches!(meta.as_ref(), syn::Meta::Path(path) if path.is_ident("unix")) =>
            {
                values.push(TargetMask(TARGET_LINUX | TARGET_MACOS | TARGET_FREEBSD));
            }
            Task::Evaluate(meta) if matches!(meta.as_ref(), syn::Meta::Path(path) if path.is_ident("windows")) =>
            {
                values.push(TargetMask(TARGET_WINDOWS));
            }
            Task::Evaluate(meta) if matches!(meta.as_ref(), syn::Meta::Path(_)) => {
                values.push(TargetMask::all());
            }
            Task::Evaluate(meta) if matches!(meta.as_ref(), syn::Meta::NameValue(_)) => {
                let syn::Meta::NameValue(value) = meta.as_ref() else {
                    continue;
                };
                values.push(name_value_target_mask(value));
            }
            Task::Evaluate(meta) => {
                let syn::Meta::List(list) = *meta else {
                    values.push(TargetMask::all());
                    continue;
                };
                let Some(items) = parse_meta_list(&list) else {
                    values.push(TargetMask::all());
                    continue;
                };
                if list.path.is_ident("all") {
                    tasks.push(Task::Intersect(items.len()));
                } else if list.path.is_ident("any") {
                    tasks.push(Task::Union(items.len()));
                } else if list.path.is_ident("not") && items.len() == 1 {
                    tasks.push(Task::Complement);
                } else {
                    values.push(TargetMask::all());
                    continue;
                }
                tasks.extend(items.into_iter().rev().map(Box::new).map(Task::Evaluate));
            }
            Task::Intersect(count) => {
                let start = values.len().saturating_sub(count);
                let combined = values[start..]
                    .iter()
                    .copied()
                    .fold(TargetMask::all(), TargetMask::intersect);
                values.truncate(start);
                values.push(combined);
            }
            Task::Union(count) => {
                let start = values.len().saturating_sub(count);
                let combined =
                    TargetMask(values[start..].iter().fold(0, |mask, item| mask | item.0));
                values.truncate(start);
                values.push(combined);
            }
            Task::Complement => {
                let value = values.pop().unwrap_or_else(TargetMask::all);
                values.push(TargetMask(TARGET_ALL & !value.0));
            }
        }
    }
    values.pop().unwrap_or_else(TargetMask::all)
}

fn parse_meta_list(list: &syn::MetaList) -> Option<Vec<syn::Meta>> {
    syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated
        .parse2(list.tokens.clone())
        .ok()
        .map(|items| items.into_iter().collect())
}

fn name_value_target_mask(value: &syn::MetaNameValue) -> TargetMask {
    let syn::Expr::Lit(syn::ExprLit {
        lit: syn::Lit::Str(literal),
        ..
    }) = &value.value
    else {
        return TargetMask::all();
    };
    if value.path.is_ident("target_os") {
        return match literal.value().as_str() {
            "linux" => TargetMask(TARGET_LINUX),
            "macos" => TargetMask(TARGET_MACOS),
            "windows" => TargetMask(TARGET_WINDOWS),
            "freebsd" => TargetMask(TARGET_FREEBSD),
            _ => TargetMask::all(),
        };
    }
    if value.path.is_ident("target_family") {
        return match literal.value().as_str() {
            "unix" => TargetMask(TARGET_LINUX | TARGET_MACOS | TARGET_FREEBSD),
            "windows" => TargetMask(TARGET_WINDOWS),
            _ => TargetMask::all(),
        };
    }
    if value.path.is_ident("target_env") && literal.value() == "musl" {
        return TargetMask(TARGET_LINUX);
    }
    TargetMask::all()
}

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

pub(super) fn cfg_attr_has_ident(attr: &syn::Attribute, expected: &str) -> bool {
    (attr.path().is_ident("cfg") || attr.path().is_ident("cfg_attr"))
        && token_stream_has_ident(attr.meta.to_token_stream(), expected)
}

pub(super) fn cfg_attr_has_string(attr: &syn::Attribute, expected: &str) -> bool {
    (attr.path().is_ident("cfg") || attr.path().is_ident("cfg_attr"))
        && token_stream_has_string(attr.meta.to_token_stream(), expected)
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

fn token_stream_has_string(stream: proc_macro2::TokenStream, expected: &str) -> bool {
    let mut pending = stream.into_iter().collect::<Vec<_>>();
    while let Some(token) = pending.pop() {
        match token {
            proc_macro2::TokenTree::Literal(literal) => {
                if syn::parse_str::<syn::LitStr>(&literal.to_string())
                    .is_ok_and(|value| value.value() == expected)
                {
                    return true;
                }
            }
            proc_macro2::TokenTree::Group(group) => pending.extend(group.stream()),
            proc_macro2::TokenTree::Ident(_) | proc_macro2::TokenTree::Punct(_) => {}
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
