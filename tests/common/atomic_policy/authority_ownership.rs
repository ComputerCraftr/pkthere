use std::path::Path;
use syn::visit::Visit;

pub(super) fn assert_consuming_flow_reservation_shape(root: &Path) {
    let definition = parse(root, "src/flow_state.rs");
    let reservation = named_struct(&definition, "ClientFlowReservation");
    let topology = named_field(reservation, "topology");
    assert!(
        option_contains_type(&topology.ty, "FlowTopologyWriteReservation"),
        "client-flow topology ownership must remain an ordinary consuming Option"
    );
    assert!(
        !type_contains_mutability(&topology.ty),
        "client-flow topology ownership cannot be hidden by interior mutability"
    );

    let implementation = parse(root, "src/flow_state/reservation.rs");
    for method in ["commit", "rollback"] {
        let signature = inherent_method(&implementation, "ClientFlowReservation", method);
        let receiver = signature
            .receiver()
            .unwrap_or_else(|| panic!("{method} must consume ClientFlowReservation"));
        assert!(
            matches!(receiver.kind, syn::ReceiverKind::Value),
            "{method} must consume ClientFlowReservation rather than mutate hidden ownership"
        );
    }
}

pub(super) fn assert_thread_owned_recorder_shape(root: &Path) {
    let definition = parse(root, "src/stats.rs");
    let recorder = named_struct(&definition, "StatsRecorder");
    let enabled = named_struct(&definition, "EnabledRecorder");
    let local = named_field(enabled, "local");
    assert!(
        type_ends_with(&local.ty, "RecorderState") && !type_contains_mutability(&local.ty),
        "packet accounting must mutate one ordinary worker-local RecorderState"
    );
    assert!(!derives_trait(&recorder.attrs, "Clone"));

    let accounting = parse(root, "src/stats/recorder.rs");
    let sink = trait_impl(&accounting, "StatsSink", "StatsRecorder");
    for item in &sink.items {
        let syn::ImplItem::Fn(method) = item else {
            continue;
        };
        let receiver = method
            .sig
            .receiver()
            .unwrap_or_else(|| panic!("StatsSink::{} must have a receiver", method.sig.ident));
        assert!(
            matches!(receiver.kind, syn::ReceiverKind::Reference(_, _, Some(_))),
            "StatsSink::{} must require unique &mut recorder ownership",
            method.sig.ident
        );
    }
    assert!(
        !has_trait_impl(&definition, "Clone", "StatsRecorder")
            && !has_trait_impl(&accounting, "Clone", "StatsRecorder"),
        "a worker-owned stats recorder must not be cloneable"
    );
}

fn parse(root: &Path, path: &str) -> syn::File {
    crate::common::rust_semantics::parse_file(&root.join(path))
}

pub(super) fn named_struct<'a>(syntax: &'a syn::File, name: &str) -> &'a syn::ItemStruct {
    syntax
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Struct(item) if item.ident == name => Some(item),
            _ => None,
        })
        .unwrap_or_else(|| panic!("{name} definition"))
}

fn named_field<'a>(item: &'a syn::ItemStruct, name: &str) -> &'a syn::Field {
    item.fields
        .iter()
        .find(|field| field.ident.as_ref().is_some_and(|ident| ident == name))
        .unwrap_or_else(|| panic!("{}::{name} field", item.ident))
}

fn inherent_method<'a>(syntax: &'a syn::File, target: &str, method: &str) -> &'a syn::Signature {
    syntax
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Impl(item)
                if item.trait_.is_none() && type_ends_with(&item.self_ty, target) =>
            {
                Some(item)
            }
            _ => None,
        })
        .flat_map(|item| &item.items)
        .find_map(|item| match item {
            syn::ImplItem::Fn(item) if item.sig.ident == method => Some(&item.sig),
            _ => None,
        })
        .unwrap_or_else(|| panic!("{target}::{method} definition"))
}

fn trait_impl<'a>(syntax: &'a syn::File, trait_name: &str, target: &str) -> &'a syn::ItemImpl {
    syntax
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Impl(item)
                if item.trait_.as_ref().is_some_and(|(path, _)| {
                    path.segments
                        .last()
                        .is_some_and(|segment| segment.ident == trait_name)
                }) && type_ends_with(&item.self_ty, target) =>
            {
                Some(item)
            }
            _ => None,
        })
        .unwrap_or_else(|| panic!("{trait_name} for {target} implementation"))
}

fn has_trait_impl(syntax: &syn::File, trait_name: &str, target: &str) -> bool {
    syntax.items.iter().any(|item| match item {
        syn::Item::Impl(item) => item.trait_.as_ref().is_some_and(|(path, _)| {
            path.segments
                .last()
                .is_some_and(|segment| segment.ident == trait_name)
                && type_ends_with(&item.self_ty, target)
        }),
        _ => false,
    })
}

fn derives_trait(attrs: &[syn::Attribute], trait_name: &str) -> bool {
    attrs.iter().any(|attribute| {
        if !attribute.path().is_ident("derive") {
            return false;
        }
        let mut found = false;
        let _ = attribute.parse_nested_meta(|meta| {
            found |= meta
                .path
                .segments
                .last()
                .is_some_and(|segment| segment.ident == trait_name);
            Ok(())
        });
        found
    })
}

fn option_contains_type(ty: &syn::Type, expected: &str) -> bool {
    let syn::Type::Path(path) = ty else {
        return false;
    };
    let Some(option) = path
        .path
        .segments
        .last()
        .filter(|segment| segment.ident == "Option")
    else {
        return false;
    };
    let syn::PathArguments::AngleBracketed(arguments) = &option.arguments else {
        return false;
    };
    arguments.args.len() == 1
        && matches!(
            arguments.args.first(),
            Some(syn::GenericArgument::Type(inner)) if type_ends_with(inner, expected)
        )
}

fn type_ends_with(ty: &syn::Type, expected: &str) -> bool {
    matches!(ty, syn::Type::Path(path) if path.path.segments.last().is_some_and(|segment| segment.ident == expected))
}

fn type_contains_mutability(ty: &syn::Type) -> bool {
    #[derive(Default)]
    struct Mutability {
        found: bool,
    }
    impl<'ast> Visit<'ast> for Mutability {
        fn visit_path(&mut self, path: &'ast syn::Path) {
            self.found |= path.segments.iter().any(|segment| {
                matches!(
                    segment.ident.to_string().as_str(),
                    "Cell" | "RefCell" | "UnsafeCell"
                ) || segment.ident.to_string().ends_with("Mutex")
            });
            syn::visit::visit_path(self, path);
        }
    }
    let mut mutability = Mutability::default();
    mutability.visit_type(ty);
    mutability.found
}
